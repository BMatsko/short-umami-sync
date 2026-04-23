package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Event struct {
	ReceivedAt   time.Time       `json:"received_at"`
	Source       string          `json:"source"`
	Domain       string          `json:"domain,omitempty"`
	PropertyID   string          `json:"property_id,omitempty"`
	Payload      json.RawMessage `json:"payload"`
	Forwarded    bool            `json:"forwarded"`
	ForwardError string          `json:"forward_error,omitempty"`
}

type Mapping struct {
	Domain     string
	PropertyID string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type app struct {
	db               *sql.DB
	password         string
	sessionSecret    string
	settingsMu       sync.RWMutex
	umamiEndpoint    string
	umamiAPIKey      string
	umamiDefaultProp string
	mu               sync.Mutex
	events           []Event
	tmplLogin        *template.Template
	tmplDash         *template.Template
}

func main() {
	cfg := mustNewApp()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/login", cfg.loginHandler)
	mux.HandleFunc("/logout", cfg.logoutHandler)
	mux.HandleFunc("/dashboard", cfg.requireAuth(cfg.dashboardHandler))
	mux.HandleFunc("/dashboard/settings", cfg.requireAuth(cfg.settingsUpdateHandler))
	mux.HandleFunc("/dashboard/mappings", cfg.requireAuth(cfg.mappingUpsertHandler))
	mux.HandleFunc("/dashboard/mappings/delete", cfg.requireAuth(cfg.mappingDeleteHandler))
	mux.HandleFunc("/webhooks/shortio", cfg.shortioWebhookHandler)
	mux.HandleFunc("/", cfg.rootHandler)

	addr := ":" + envOr("PORT", "8080")
	log.Printf("starting short-umami-sync on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func mustNewApp() *app {
	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dbURL == "" {
		dbURL = strings.TrimSpace(os.Getenv("POSTGRES_URL"))
	}
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required for persistent domain-to-property mappings")
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatal(err)
	}
	if err := initSchema(ctx, db); err != nil {
		log.Fatal(err)
	}

	storedSettings, err := loadSettings(ctx, db)
	if err != nil {
		log.Fatal(err)
	}

	return &app{
		db:               db,
		password:         envOr("APP_PASSWORD", "changeme"),
		sessionSecret:    mustEnv("SESSION_SECRET"),
		umamiEndpoint:    settingOrEnv(storedSettings, "umami_endpoint", "UMAMI_ENDPOINT"),
		umamiAPIKey:      settingOrEnv(storedSettings, "umami_api_key", "UMAMI_API_KEY"),
		umamiDefaultProp: settingOrEnv(storedSettings, "umami_website_id", "UMAMI_WEBSITE_ID"),
		tmplLogin:        template.Must(template.New("login").Parse(loginTemplate)),
		tmplDash:         template.Must(template.New("dashboard").Parse(dashboardTemplate)),
	}
}

func initSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS domain_mappings (
			domain TEXT PRIMARY KEY,
			property_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		CREATE TABLE IF NOT EXISTS app_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`)
	return err
}

func loadSettings(ctx context.Context, db *sql.DB) (map[string]string, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rows, err := db.QueryContext(queryCtx, `
		SELECT key, value
		FROM app_settings
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		settings[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return settings, nil
}

func settingOrEnv(settings map[string]string, key, envKey string) string {
	if value, ok := settings[key]; ok {
		return value
	}
	return os.Getenv(envKey)
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if strings.TrimSpace(v) == "" {
		return "dev-session-secret"
	}
	return v
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func (a *app) rootHandler(w http.ResponseWriter, r *http.Request) {
	if a.isAuthed(r) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *app) loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_ = a.tmplLogin.Execute(w, map[string]any{"Error": ""})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if r.FormValue("password") != a.password {
			w.WriteHeader(http.StatusUnauthorized)
			_ = a.tmplLogin.Execute(w, map[string]any{"Error": "Incorrect password."})
			return
		}
		http.SetCookie(w, a.sessionCookie())
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *app) logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if r.TLS != nil {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *app) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	mappings, err := a.listMappings(r.Context())
	if err != nil {
		http.Error(w, "failed to load mappings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	a.mu.Lock()
	items := make([]Event, len(a.events))
	copy(items, a.events)
	a.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ReceivedAt.After(items[j].ReceivedAt) })

	settings := a.settingsSnapshot()
	_ = a.tmplDash.Execute(w, map[string]any{
		"Events":           items,
		"Mappings":         mappings,
		"UmamiEndpoint":    settings.Endpoint,
		"UmamiAPIKey":      settings.APIKey,
		"DefaultPropertyID": settings.DefaultPropertyID,
		"Message":          r.URL.Query().Get("message"),
		"Error":            r.URL.Query().Get("error"),
	})
}

func (a *app) mappingUpsertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithError(w, r, "invalid form")
		return
	}
	domain := normalizeDomain(r.FormValue("domain"))
	propertyID := strings.TrimSpace(r.FormValue("property_id"))
	if domain == "" || propertyID == "" {
		redirectWithError(w, r, "domain and property ID are required")
		return
	}
	if err := a.upsertMapping(r.Context(), domain, propertyID); err != nil {
		redirectWithError(w, r, "save failed: "+err.Error())
		return
	}
	redirectWithMessage(w, r, fmt.Sprintf("Saved mapping for %s", domain))
}

func (a *app) mappingDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithError(w, r, "invalid form")
		return
	}
	domain := normalizeDomain(r.FormValue("domain"))
	if domain == "" {
		redirectWithError(w, r, "domain is required")
		return
	}
	if err := a.deleteMapping(r.Context(), domain); err != nil {
		redirectWithError(w, r, "delete failed: "+err.Error())
		return
	}
	redirectWithMessage(w, r, fmt.Sprintf("Deleted mapping for %s", domain))
}

func (a *app) settingsUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectWithError(w, r, "invalid form")
		return
	}

	endpoint := strings.TrimSpace(r.FormValue("umami_endpoint"))
	apiKey := strings.TrimSpace(r.FormValue("umami_api_key"))
	defaultPropertyID := strings.TrimSpace(r.FormValue("umami_website_id"))

	if err := a.saveSettings(r.Context(), endpoint, apiKey, defaultPropertyID); err != nil {
		redirectWithError(w, r, "save failed: "+err.Error())
		return
	}

	a.setSettings(endpoint, apiKey, defaultPropertyID)
	redirectWithMessage(w, r, "Saved settings")
}

func redirectWithMessage(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/dashboard?message="+url.QueryEscape(msg), http.StatusFound)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/dashboard?error="+url.QueryEscape(msg), http.StatusFound)
}

type runtimeSettings struct {
	Endpoint          string
	APIKey            string
	DefaultPropertyID string
}

func (a *app) settingsSnapshot() runtimeSettings {
	a.settingsMu.RLock()
	defer a.settingsMu.RUnlock()
	return runtimeSettings{
		Endpoint:          a.umamiEndpoint,
		APIKey:            a.umamiAPIKey,
		DefaultPropertyID: a.umamiDefaultProp,
	}
}

func (a *app) setSettings(endpoint, apiKey, defaultPropertyID string) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	a.umamiEndpoint = endpoint
	a.umamiAPIKey = apiKey
	a.umamiDefaultProp = defaultPropertyID
}

func (a *app) saveSettings(ctx context.Context, endpoint, apiKey, defaultPropertyID string) error {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := a.db.ExecContext(queryCtx, `
		INSERT INTO app_settings (key, value, updated_at)
		VALUES
			('umami_endpoint', $1, now()),
			('umami_api_key', $2, now()),
			('umami_website_id', $3, now())
		ON CONFLICT (key)
		DO UPDATE SET value = EXCLUDED.value, updated_at = now()
	`, endpoint, apiKey, defaultPropertyID)
	return err
}

func (a *app) shortioWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	settings := a.settingsSnapshot()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		http.Error(w, "empty payload", http.StatusBadRequest)
		return
	}
	payload := json.RawMessage(body)
	domain := extractDomain(payload)
	propertyID, resolvedFrom, resolveErr := a.resolvePropertyID(r.Context(), domain, settings.DefaultPropertyID)
	event := Event{ReceivedAt: time.Now().UTC(), Source: "shortio", Domain: domain, PropertyID: propertyID, Payload: payload}
	if resolveErr != nil {
		event.Forwarded = false
		event.ForwardError = resolveErr.Error()
	} else {
		event.Forwarded, event.ForwardError = a.forwardToUmami(r, payload, domain, propertyID, resolvedFrom, settings.Endpoint, settings.APIKey)
	}
	a.mu.Lock()
	a.events = append(a.events, event)
	if len(a.events) > 100 {
		a.events = a.events[len(a.events)-100:]
	}
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "forwarded": event.Forwarded, "error": event.ForwardError, "domain": domain, "property_id": propertyID})
}

func (a *app) resolvePropertyID(ctx context.Context, domain, defaultPropertyID string) (propertyID string, resolvedFrom string, err error) {
	if domain != "" {
		mapped, err := a.getMapping(ctx, domain)
		if err != nil {
			return "", "", err
		}
		if mapped != "" {
			return mapped, "database", nil
		}
	}
	if strings.TrimSpace(defaultPropertyID) != "" {
		return strings.TrimSpace(defaultPropertyID), "environment", nil
	}
	return "", "", fmt.Errorf("no domain mapping found for %q", domain)
}

func (a *app) forwardToUmami(r *http.Request, payload json.RawMessage, domain, propertyID, resolvedFrom, endpoint, apiKey string) (bool, string) {
	if endpoint == "" {
		return false, "UMAMI_ENDPOINT is not configured"
	}
	forward := map[string]any{
		"source":       "shortio",
		"received_at":  time.Now().UTC().Format(time.RFC3339Nano),
		"request": map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"remote":  r.RemoteAddr,
			"agent":   r.UserAgent(),
		},
		"payload": json.RawMessage(payload),
	}
	if domain != "" {
		forward["domain"] = domain
	}
	if propertyID != "" {
		forward["website_id"] = propertyID
		forward["property_source"] = resolvedFrom
	}
	b, err := json.Marshal(forward)
	if err != nil {
		return false, err.Error()
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(b)))
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, fmt.Sprintf("umami returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return true, ""
}

func (a *app) listMappings(ctx context.Context) ([]Mapping, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := a.db.QueryContext(queryCtx, `
		SELECT domain, property_id, created_at, updated_at
		FROM domain_mappings
		ORDER BY domain ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mappings []Mapping
	for rows.Next() {
		var m Mapping
		if err := rows.Scan(&m.Domain, &m.PropertyID, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return mappings, nil
}

func (a *app) getMapping(ctx context.Context, domain string) (string, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var propertyID string
	err := a.db.QueryRowContext(queryCtx, `
		SELECT property_id
		FROM domain_mappings
		WHERE domain = $1
	`, domain).Scan(&propertyID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return propertyID, nil
}

func (a *app) upsertMapping(ctx context.Context, domain, propertyID string) error {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := a.db.ExecContext(queryCtx, `
		INSERT INTO domain_mappings (domain, property_id, created_at, updated_at)
		VALUES ($1, $2, now(), now())
		ON CONFLICT (domain)
		DO UPDATE SET property_id = EXCLUDED.property_id, updated_at = now()
	`, domain, propertyID)
	return err
}

func (a *app) deleteMapping(ctx context.Context, domain string) error {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := a.db.ExecContext(queryCtx, `DELETE FROM domain_mappings WHERE domain = $1`, domain)
	return err
}

const sessionCookieName = "short_umami_session"

func (a *app) sessionCookie() *http.Cookie {
	expiry := time.Now().Add(7 * 24 * time.Hour).Unix()
	value := fmt.Sprintf("%d", expiry)
	sig := a.sign(value)
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    value + "." + sig,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(expiry, 0),
	}
	return cookie
}

func (a *app) isAuthed(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}
	exp, sig := parts[0], parts[1]
	if !hmac.Equal([]byte(sig), []byte(a.sign(exp))) {
		return false
	}
	unix, err := parseInt64(exp)
	if err != nil {
		return false
	}
	return time.Now().Unix() < unix
}

func (a *app) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.isAuthed(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (a *app) sign(v string) string {
	mac := hmac.New(sha256.New, []byte(a.sessionSecret))
	_, _ = mac.Write([]byte(v))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

func normalizeDomain(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
			value = parsed.Host
		}
	}
	if idx := strings.Index(value, "/"); idx >= 0 {
		value = value[:idx]
	}
	if idx := strings.Index(value, ":"); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSuffix(value, ".")
}

func extractDomain(payload json.RawMessage) string {
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return ""
	}
	return extractDomainValue(decoded)
}

func extractDomainValue(value any) string {
	switch v := value.(type) {
	case map[string]any:
		for _, key := range []string{"domain", "shortDomain", "short_domain", "shortUrlDomain", "short_url_domain", "shortUrl", "short_url", "hostname", "host"} {
			if raw, ok := v[key]; ok {
				if domain := domainFromValue(raw); domain != "" {
					return domain
				}
			}
		}
		for _, raw := range v {
			if domain := extractDomainValue(raw); domain != "" {
				return domain
			}
		}
	case []any:
		for _, item := range v {
			if domain := extractDomainValue(item); domain != "" {
				return domain
			}
		}
	case string:
		return domainFromString(v)
	}
	return ""
}

func domainFromValue(value any) string {
	switch v := value.(type) {
	case string:
		return domainFromString(v)
	case map[string]any, []any:
		return extractDomainValue(v)
	default:
		return ""
	}
}

func domainFromString(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
			return strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		}
	}
	if idx := strings.Index(value, "/"); idx >= 0 {
		value = value[:idx]
	}
	if idx := strings.Index(value, ":"); idx >= 0 {
		value = value[:idx]
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" || !strings.Contains(value, ".") {
		return ""
	}
	return value
}

const loginTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Short Umami Sync</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f8fb;
      --surface: rgba(255, 255, 255, 0.92);
      --surface-strong: #ffffff;
      --border: rgba(148, 163, 184, 0.22);
      --border-strong: rgba(148, 163, 184, 0.35);
      --text: #0f172a;
      --muted: #64748b;
      --primary: #0f766e;
      --primary-strong: #115e59;
      --danger: #b91c1c;
      --shadow: 0 24px 70px rgba(15, 23, 42, 0.08);
      --radius: 20px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(45, 212, 191, 0.18), transparent 30%),
        radial-gradient(circle at top right, rgba(96, 165, 250, 0.16), transparent 28%),
        linear-gradient(180deg, #f8fafc 0%, #eef2f7 100%);
      display: grid;
      place-items: center;
      padding: 32px 16px;
    }
    .shell {
      width: min(100%, 480px);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 24px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
      padding: 34px;
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(15, 118, 110, 0.08);
      color: var(--primary-strong);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin-bottom: 18px;
    }
    h1 { margin: 0 0 8px; font-size: 32px; letter-spacing: -0.03em; }
    p { margin: 0; color: var(--muted); line-height: 1.6; }
    .stack { display: grid; gap: 18px; margin-top: 28px; }
    label { display: grid; gap: 8px; font-size: 14px; font-weight: 600; color: #334155; }
    input {
      width: 100%;
      border: 1px solid var(--border-strong);
      border-radius: 14px;
      background: var(--surface-strong);
      padding: 14px 16px;
      font: inherit;
      color: var(--text);
      outline: none;
      transition: border-color .15s ease, box-shadow .15s ease, transform .15s ease;
    }
    input:focus {
      border-color: rgba(15, 118, 110, 0.5);
      box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12);
    }
    button {
      border: 0;
      border-radius: 14px;
      background: linear-gradient(180deg, #14b8a6, #0f766e);
      color: white;
      font: inherit;
      font-weight: 700;
      padding: 13px 18px;
      cursor: pointer;
      box-shadow: 0 10px 20px rgba(15, 118, 110, 0.18);
    }
    button:hover { background: linear-gradient(180deg, #10b5a2, #115e59); }
    .error {
      padding: 12px 14px;
      background: rgba(185, 28, 28, 0.08);
      border: 1px solid rgba(185, 28, 28, 0.16);
      color: var(--danger);
      border-radius: 14px;
      font-size: 14px;
      margin-top: 18px;
    }
  </style>
</head>
<body>
  <main class="shell">
    <div class="eyebrow">Short Umami Sync</div>
    <h1>Welcome back</h1>
    <p>Sign in to manage mappings, update Umami settings, and review recent webhook activity.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form class="stack" method="post" action="/login">
      <label>Password
        <input type="password" name="password" autofocus>
      </label>
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>`

const dashboardTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dashboard - Short Umami Sync</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f3f6fa;
      --surface: rgba(255, 255, 255, 0.9);
      --surface-strong: #ffffff;
      --border: rgba(148, 163, 184, 0.22);
      --border-strong: rgba(148, 163, 184, 0.36);
      --text: #0f172a;
      --muted: #64748b;
      --muted-soft: #94a3b8;
      --primary: #0f766e;
      --primary-strong: #115e59;
      --danger: #b91c1c;
      --success: #15803d;
      --shadow: 0 24px 70px rgba(15, 23, 42, 0.08);
      --radius: 20px;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(45, 212, 191, 0.18), transparent 28%),
        radial-gradient(circle at top right, rgba(96, 165, 250, 0.12), transparent 24%),
        linear-gradient(180deg, #f8fafc 0%, #eef2f7 100%);
    }
    a { color: inherit; }
    code {
      padding: 0.2rem 0.45rem;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.05);
      color: #0f172a;
      font-size: 0.92em;
      word-break: break-word;
    }
    .page {
      width: min(1180px, calc(100% - 32px));
      margin: 24px auto 40px;
    }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      margin-bottom: 22px;
    }
    .hero {
      flex: 1;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 28px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
      padding: 26px 28px;
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(15, 118, 110, 0.08);
      color: var(--primary-strong);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin-bottom: 14px;
    }
    h1, h2, h3 { margin: 0; letter-spacing: -0.03em; }
    h1 { font-size: 34px; line-height: 1.05; }
    .subtitle { margin: 10px 0 0; color: var(--muted); font-size: 15px; line-height: 1.6; max-width: 72ch; }
    .actions { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; justify-content: flex-end; }
    .button-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 42px;
      padding: 0 16px;
      border-radius: 12px;
      border: 1px solid var(--border-strong);
      background: var(--surface-strong);
      text-decoration: none;
      font-weight: 700;
      color: #0f172a;
      box-shadow: 0 8px 18px rgba(15, 23, 42, 0.04);
    }
    .button-link.primary {
      border-color: transparent;
      color: white;
      background: linear-gradient(180deg, #14b8a6, #0f766e);
      box-shadow: 0 10px 20px rgba(15, 118, 110, 0.18);
    }
    .notice {
      margin: 16px 0 0;
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid transparent;
      font-size: 14px;
      line-height: 1.5;
    }
    .notice.success { background: rgba(21, 128, 61, 0.08); border-color: rgba(21, 128, 61, 0.15); color: var(--success); }
    .notice.error { background: rgba(185, 28, 28, 0.08); border-color: rgba(185, 28, 28, 0.15); color: var(--danger); }
    .grid {
      display: grid;
      gap: 18px;
      margin-top: 18px;
      grid-template-columns: repeat(12, minmax(0, 1fr));
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
      padding: 22px;
    }
    .card h2 {
      font-size: 18px;
      margin-bottom: 10px;
    }
    .card-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 18px;
    }
    .muted { color: var(--muted); }
    .muted-soft { color: var(--muted-soft); }
    .config { grid-column: span 12; }
    .settings { grid-column: span 12; }
    .mappings { grid-column: span 12; }
    .events { grid-column: span 12; }
    @media (min-width: 1060px) {
      .settings { grid-column: span 5; }
      .mappings { grid-column: span 7; }
      .events { grid-column: span 12; }
    }
    .chips { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 8px; }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 12px;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.04);
      border: 1px solid rgba(148, 163, 184, 0.16);
      color: #334155;
      font-size: 13px;
      font-weight: 600;
    }
    .chip strong { color: #0f172a; }
    .form-grid {
      display: grid;
      gap: 14px;
      grid-template-columns: 1fr;
    }
    @media (min-width: 760px) {
      .form-grid.cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    label { display: grid; gap: 8px; font-size: 13px; font-weight: 700; color: #334155; }
    .hint { font-size: 12px; color: var(--muted); font-weight: 500; line-height: 1.4; }
    input {
      width: 100%;
      border: 1px solid var(--border-strong);
      border-radius: 14px;
      background: var(--surface-strong);
      padding: 13px 14px;
      font: inherit;
      color: var(--text);
      outline: none;
      transition: border-color .15s ease, box-shadow .15s ease, transform .15s ease;
    }
    input:focus {
      border-color: rgba(15, 118, 110, 0.5);
      box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12);
    }
    .button-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-top: 16px;
      flex-wrap: wrap;
    }
    button {
      border: 0;
      border-radius: 14px;
      background: linear-gradient(180deg, #14b8a6, #0f766e);
      color: white;
      font: inherit;
      font-weight: 700;
      padding: 12px 16px;
      cursor: pointer;
      box-shadow: 0 10px 20px rgba(15, 118, 110, 0.16);
    }
    button.secondary {
      background: var(--surface-strong);
      color: #0f172a;
      border: 1px solid var(--border-strong);
      box-shadow: none;
    }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      text-align: left;
      vertical-align: top;
      padding: 14px 12px;
      border-bottom: 1px solid rgba(148, 163, 184, 0.18);
      font-size: 14px;
    }
    th { color: var(--muted); font-weight: 700; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
    tr:last-child td { border-bottom: 0; }
    .inline { display: inline; }
    .event {
      border: 1px solid rgba(148, 163, 184, 0.18);
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.7);
      padding: 18px;
      margin-top: 14px;
    }
    .event-head {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 12px;
    }
    .event-meta {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 8px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 10px;
      border-radius: 999px;
      background: rgba(15, 118, 110, 0.08);
      color: var(--primary-strong);
      font-size: 12px;
      font-weight: 700;
    }
    pre {
      overflow: auto;
      margin: 14px 0 0;
      padding: 14px;
      border-radius: 16px;
      background: #0b1120;
      color: #d9e2f2;
      font-size: 12px;
      line-height: 1.6;
      white-space: pre-wrap;
      word-break: break-word;
    }
  </style>
</head>
<body>
  <main class="page">
    <div class="topbar">
      <section class="hero">
        <div class="eyebrow">Short Umami Sync</div>
        <h1>Dashboard</h1>
        <p class="subtitle">Manage Umami forwarding settings, map Short.io domains to Umami properties, and review webhook traffic in one clean workspace.</p>
        <div class="chips">
          <span class="chip"><strong>Endpoint</strong> {{if .UmamiEndpoint}}{{.UmamiEndpoint}}{{else}}not set{{end}}</span>
          <span class="chip"><strong>API token</strong> {{if .UmamiAPIKey}}configured{{else}}not set{{end}}</span>
          <span class="chip"><strong>Fallback property</strong> {{if .DefaultPropertyID}}{{.DefaultPropertyID}}{{else}}not set{{end}}</span>
        </div>
        {{if .Message}}<div class="notice success">{{.Message}}</div>{{end}}
        {{if .Error}}<div class="notice error">{{.Error}}</div>{{end}}
      </section>
      <div class="actions">
        <a class="button-link primary" href="#settings">Settings</a>
        <a class="button-link" href="#mappings">Mappings</a>
        <a class="button-link" href="#events">Events</a>
        <a class="button-link" href="/logout">Log out</a>
      </div>
    </div>

    <section class="grid">
      <article class="card config">
        <div class="card-head">
          <div>
            <h2>Configuration</h2>
            <p class="muted">The app uses the saved settings below when forwarding Short.io webhooks to Umami.</p>
          </div>
        </div>
        <div class="form-grid cols-2">
          <div>
            <div class="hint">Short.io webhook endpoint</div>
            <code>/webhooks/shortio</code>
          </div>
          <div>
            <div class="hint">Domain mappings override the fallback property ID on a per-domain basis.</div>
            <code>domain_mappings</code>
          </div>
        </div>
      </article>

      <article class="card settings" id="settings">
        <div class="card-head">
          <div>
            <h2>Umami settings</h2>
            <p class="muted">Update the destination endpoint, API token, and fallback property here.</p>
          </div>
        </div>
        <form method="post" action="/dashboard/settings">
          <div class="form-grid">
            <label>Umami Endpoint
              <input type="url" name="umami_endpoint" value="{{.UmamiEndpoint}}" placeholder="https://analytics.example.com/api/send">
              <span class="hint">The POST target for forwarded events.</span>
            </label>
            <label>API Token
              <input type="text" name="umami_api_key" value="{{.UmamiAPIKey}}" placeholder="optional bearer token">
              <span class="hint">Stored securely in the service database and sent as a Bearer token when set.</span>
            </label>
            <label>Fallback property ID
              <input type="text" name="umami_website_id" value="{{.DefaultPropertyID}}" placeholder="umami-property-id">
              <span class="hint">Used when a webhook domain does not have a dedicated mapping.</span>
            </label>
          </div>
          <div class="button-row">
            <span class="muted">Changes apply immediately to new webhook requests.</span>
            <button type="submit">Save settings</button>
          </div>
        </form>
      </article>

      <article class="card mappings" id="mappings">
        <div class="card-head">
          <div>
            <h2>Domain-to-property mappings</h2>
            <p class="muted">Override the fallback property for specific Short.io domains.</p>
          </div>
        </div>
        <form method="post" action="/dashboard/mappings">
          <div class="form-grid cols-2">
            <label>Short.io domain
              <input type="text" name="domain" placeholder="example.short.gy">
            </label>
            <label>Umami property ID
              <input type="text" name="property_id" placeholder="umami-property-id">
            </label>
          </div>
          <div class="button-row">
            <span class="muted">Domains are normalized before saving.</span>
            <button type="submit">Save mapping</button>
          </div>
        </form>
        <div style="margin-top: 18px; overflow-x: auto;">
          <table>
            <thead>
              <tr><th>Domain</th><th>Property ID</th><th>Updated</th><th></th></tr>
            </thead>
            <tbody>
              {{if .Mappings}}
                {{range .Mappings}}
                  <tr>
                    <td><code>{{.Domain}}</code></td>
                    <td><code>{{.PropertyID}}</code></td>
                    <td class="muted">{{.UpdatedAt.Format "2006-01-02 15:04:05 MST"}}</td>
                    <td>
                      <form class="inline" method="post" action="/dashboard/mappings/delete">
                        <input type="hidden" name="domain" value="{{.Domain}}">
                        <button class="secondary" type="submit">Delete</button>
                      </form>
                    </td>
                  </tr>
                {{end}}
              {{else}}
                <tr><td colspan="4" class="muted">No mappings configured yet.</td></tr>
              {{end}}
            </tbody>
          </table>
        </div>
      </article>

      <article class="card events" id="events">
        <div class="card-head">
          <div>
            <h2>Recent webhook events</h2>
            <p class="muted">The latest payloads received by the service, including forwarding status.</p>
          </div>
        </div>
        {{if .Events}}
          {{range .Events}}
            <div class="event">
              <div class="event-head">
                <div>
                  <div class="badge">{{.Source}}</div>
                  <div style="margin-top: 10px; font-weight: 700; font-size: 15px;">{{.ReceivedAt.Format "2006-01-02 15:04:05 MST"}}</div>
                  <div class="event-meta">
                    <span class="chip"><strong>Domain</strong> {{if .Domain}}{{.Domain}}{{else}}—{{end}}</span>
                    <span class="chip"><strong>Property ID</strong> {{if .PropertyID}}{{.PropertyID}}{{else}}—{{end}}</span>
                    <span class="chip"><strong>Forwarded</strong> {{.Forwarded}}</span>
                  </div>
                </div>
              </div>
              {{if .ForwardError}}<div class="notice error" style="margin-top: 0;">{{.ForwardError}}</div>{{end}}
              <pre>{{printf "%s" .Payload}}</pre>
            </div>
          {{end}}
        {{else}}
          <p class="muted">No events received yet.</p>
        {{end}}
      </article>
    </section>
  </main>
</body>
</html>`

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
	WebhookKey   string          `json:"webhook_key,omitempty"`
	Domain       string          `json:"domain,omitempty"`
	PropertyID   string          `json:"property_id,omitempty"`
	ResolvedFrom string          `json:"resolved_from,omitempty"`
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
	db                *sql.DB
	password          string
	sessionSecret     string
	umamiEndpoint     string
	umamiAPIKey       string
	umamiDefaultProp  string
	mu                sync.Mutex
	events            []Event
	tmplLogin         *template.Template
	tmplDash          *template.Template
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
	mux.HandleFunc("/dashboard/mappings", cfg.requireAuth(cfg.mappingUpsertHandler))
	mux.HandleFunc("/dashboard/mappings/delete", cfg.requireAuth(cfg.mappingDeleteHandler))
	mux.HandleFunc("/dashboard/settings", cfg.requireAuth(cfg.settingsHandler))
	mux.HandleFunc("/webhooks/shortio", cfg.shortioWebhookHandler)
	mux.HandleFunc("/webhooks/shortio/", cfg.shortioWebhookHandler)
	mux.HandleFunc("/", cfg.rootHandler)

	addr := ":" + envOr("PORT", "8080")
		log.Printf("event=startup service=short-umami-sync address=%s", addr)
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

	a := &app{
		db:               db,
		password:         envOr("APP_PASSWORD", "changeme"),
		sessionSecret:    mustEnv("SESSION_SECRET"),
		umamiEndpoint:    os.Getenv("UMAMI_ENDPOINT"),
		umamiAPIKey:      os.Getenv("UMAMI_API_KEY"),
		umamiDefaultProp: os.Getenv("UMAMI_WEBSITE_ID"),
		tmplLogin:        template.Must(template.New("login").Parse(loginTemplate)),
		tmplDash:         template.Must(template.New("dashboard").Parse(dashboardTemplate)),
	}
	a.loadSettings(ctx)
	return a
}

func initSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS domain_mappings (
			domain TEXT PRIMARY KEY,
			property_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE TABLE IF NOT EXISTS settings (
			key        TEXT PRIMARY KEY,
			value      TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`)
	return err
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
			log.Printf("event=login_failed remote=%s", r.RemoteAddr)
			w.WriteHeader(http.StatusUnauthorized)
			_ = a.tmplLogin.Execute(w, map[string]any{"Error": "Incorrect password."})
			return
		}
		log.Printf("event=login_success remote=%s", r.RemoteAddr)
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
	log.Printf("event=logout remote=%s", r.RemoteAddr)
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

	_ = a.tmplDash.Execute(w, map[string]any{
		"Events":              items,
		"Mappings":            mappings,
		"UmamiEndpoint":       a.umamiEndpoint,
		"UmamiAPIKey":         a.umamiAPIKey,
		"DefaultPropertyID":   a.umamiDefaultProp,
		"WebhookRoutePattern": "/webhooks/shortio/:domain_or_id",
		"Message":             r.URL.Query().Get("message"),
		"Error":               r.URL.Query().Get("error"),
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
	originalKey := normalizeMappingKey(r.FormValue("original_domain"))
	key := normalizeMappingKey(r.FormValue("domain"))
	propertyID := strings.TrimSpace(r.FormValue("property_id"))
	if key == "" || propertyID == "" {
		redirectWithError(w, r, "domain and property ID are required")
		return
	}
	if originalKey == "" {
		originalKey = key
	}
	if err := a.saveMapping(r.Context(), originalKey, key, propertyID); err != nil {
		redirectWithError(w, r, "save failed: "+err.Error())
		return
	}
	log.Printf("event=mapping_saved original_key=%q key=%q property_id=%q", originalKey, key, propertyID)
	redirectWithMessage(w, r, fmt.Sprintf("Saved mapping for %s", key))
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
	key := normalizeMappingKey(r.FormValue("domain"))
	if key == "" {
		redirectWithError(w, r, "domain is required")
		return
	}
	if err := a.deleteMapping(r.Context(), key); err != nil {
		redirectWithError(w, r, "delete failed: "+err.Error())
		return
	}
	log.Printf("event=mapping_deleted key=%q", key)
	redirectWithMessage(w, r, fmt.Sprintf("Deleted mapping for %s", key))
}

func redirectWithMessage(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/dashboard?message="+url.QueryEscape(msg), http.StatusFound)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/dashboard?error="+url.QueryEscape(msg), http.StatusFound)
}

func (a *app) shortioWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		http.Error(w, "empty payload", http.StatusBadRequest)
		return
	}
	routeKey := ""
	if strings.HasPrefix(r.URL.Path, "/webhooks/shortio/") {
		routeKey = normalizeMappingKey(strings.TrimPrefix(r.URL.Path, "/webhooks/shortio/"))
	}
	payload := json.RawMessage(body)
	payloadDomain := extractDomain(payload)
	propertyID, resolvedFrom, resolveErr := a.resolvePropertyID(r.Context(), routeKey, payloadDomain)
	event := Event{ReceivedAt: time.Now().UTC(), Source: "shortio", WebhookKey: routeKey, Domain: payloadDomain, PropertyID: propertyID, ResolvedFrom: resolvedFrom, Payload: payload}
	log.Printf("event=webhook_received source=shortio path=%q route_key=%q payload_domain=%q property_id=%q", r.URL.Path, routeKey, payloadDomain, propertyID)
	if resolveErr != nil {
		event.Forwarded = false
		event.ForwardError = resolveErr.Error()
		log.Printf("event=webhook_resolution_failed source=shortio path=%q route_key=%q payload_domain=%q error=%q", r.URL.Path, routeKey, payloadDomain, resolveErr.Error())
	} else {
		event.Forwarded, event.ForwardError = a.forwardToUmami(r, payload, routeKey, payloadDomain, propertyID, resolvedFrom)
		if event.Forwarded {
			log.Printf("event=webhook_forwarded source=shortio path=%q route_key=%q payload_domain=%q property_id=%q resolved_from=%s", r.URL.Path, routeKey, payloadDomain, propertyID, resolvedFrom)
		} else {
			log.Printf("event=webhook_forward_failed source=shortio path=%q route_key=%q payload_domain=%q property_id=%q resolved_from=%s error=%q", r.URL.Path, routeKey, payloadDomain, propertyID, resolvedFrom, event.ForwardError)
		}
	}
	a.mu.Lock()
	a.events = append(a.events, event)
	if len(a.events) > 100 {
		a.events = a.events[len(a.events)-100:]
	}
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "forwarded": event.Forwarded, "error": event.ForwardError, "domain": payloadDomain, "route_key": routeKey, "property_id": propertyID, "resolved_from": resolvedFrom})
}

func (a *app) resolvePropertyID(ctx context.Context, routeKey, payloadDomain string) (propertyID string, resolvedFrom string, err error) {
	for _, candidate := range []struct {
		value  string
		source string
	}{
		{value: routeKey, source: "route"},
		{value: payloadDomain, source: "payload"},
	} {
		if candidate.value == "" {
			continue
		}
		mapped, err := a.getMapping(ctx, candidate.value)
		if err != nil {
			return "", "", err
		}
		if mapped != "" {
			return mapped, candidate.source, nil
		}
	}
	if strings.TrimSpace(a.umamiDefaultProp) != "" {
		return strings.TrimSpace(a.umamiDefaultProp), "environment", nil
	}
	return "", "", fmt.Errorf("no domain mapping found for route key %q or payload domain %q", routeKey, payloadDomain)
}

func (a *app) forwardToUmami(r *http.Request, payload json.RawMessage, routeKey, payloadDomain, propertyID, resolvedFrom string) (bool, string) {
	if a.umamiEndpoint == "" {
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
	if routeKey != "" {
		forward["domain"] = routeKey
	} else if payloadDomain != "" {
		forward["domain"] = payloadDomain
	}
	if propertyID != "" {
		forward["website_id"] = propertyID
		forward["property_source"] = resolvedFrom
	}
	b, err := json.Marshal(forward)
	if err != nil {
		return false, err.Error()
	}
	req, err := http.NewRequest(http.MethodPost, a.umamiEndpoint, strings.NewReader(string(b)))
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	if a.umamiAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.umamiAPIKey)
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

func (a *app) saveMapping(ctx context.Context, originalDomain, domain, propertyID string) error {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := a.db.BeginTx(queryCtx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if originalDomain != "" && originalDomain != domain {
		if _, err := tx.ExecContext(queryCtx, `DELETE FROM domain_mappings WHERE domain = $1`, originalDomain); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(queryCtx, `
		INSERT INTO domain_mappings (domain, property_id, created_at, updated_at)
		VALUES ($1, $2, now(), now())
		ON CONFLICT (domain)
		DO UPDATE SET property_id = EXCLUDED.property_id, updated_at = now()
	`, domain, propertyID); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *app) deleteMapping(ctx context.Context, domain string) error {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := a.db.ExecContext(queryCtx, `DELETE FROM domain_mappings WHERE domain = $1`, domain)
	return err
}

func (a *app) getSetting(ctx context.Context, key string) (string, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var value string
	err := a.db.QueryRowContext(queryCtx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (a *app) saveSetting(ctx context.Context, key, value string) error {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := a.db.ExecContext(queryCtx, `
		INSERT INTO settings (key, value, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (key)
		DO UPDATE SET value = EXCLUDED.value, updated_at = now()
	`, key, value)
	return err
}

func (a *app) loadSettings(ctx context.Context) {
	if endpoint, err := a.getSetting(ctx, "umami_endpoint"); err != nil {
		log.Printf("event=settings_load_error key=umami_endpoint error=%q", err)
	} else if endpoint != "" {
		a.umamiEndpoint = endpoint
		log.Printf("event=settings_loaded key=umami_endpoint source=database")
	}

	if apiKey, err := a.getSetting(ctx, "umami_api_key"); err != nil {
		log.Printf("event=settings_load_error key=umami_api_key error=%q", err)
	} else if apiKey != "" {
		a.umamiAPIKey = apiKey
		log.Printf("event=settings_loaded key=umami_api_key source=database")
	}
}

func (a *app) settingsHandler(w http.ResponseWriter, r *http.Request) {
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

	if endpoint != "" {
		if _, err := url.ParseRequestURI(endpoint); err != nil {
			redirectWithError(w, r, "invalid Umami endpoint URL: "+err.Error())
			return
		}
	}

	if err := a.saveSetting(r.Context(), "umami_endpoint", endpoint); err != nil {
		redirectWithError(w, r, "failed to save endpoint: "+err.Error())
		return
	}
	if err := a.saveSetting(r.Context(), "umami_api_key", apiKey); err != nil {
		redirectWithError(w, r, "failed to save API key: "+err.Error())
		return
	}

	a.umamiEndpoint = endpoint
	a.umamiAPIKey = apiKey
	log.Printf("event=settings_saved umami_endpoint=%q api_key_set=%v", endpoint, apiKey != "")
	redirectWithMessage(w, r, "Settings saved successfully")
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

func normalizeMappingKey(raw string) string {
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

func logEvent(message string, fields map[string]any) {
	parts := []string{message}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, fields[k]))
	}
	log.Println(strings.Join(parts, " "))
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
<html>
<head>
  <meta charset="utf-8">
  <title>Short Umami Sync</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 760px; margin: 48px auto; padding: 0 16px; }
    input, button { font: inherit; padding: 10px 12px; }
    .error { color: #b00020; }
  </style>
</head>
<body>
  <h1>Short Umami Sync</h1>
  <p>Sign in to manage domain-to-property mappings and view recent webhook activity.</p>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form method="post" action="/login">
    <label>Password<br><input type="password" name="password" autofocus></label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>`

const dashboardTemplate = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Dashboard - Short Umami Sync</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 16px; }
    code, pre { background: #f4f4f4; padding: 2px 6px; border-radius: 4px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin: 16px 0; }
    .muted { color: #666; }
    pre { overflow:auto; padding: 12px; white-space: pre-wrap; }
    a { color: #0b57d0; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #e5e5e5; vertical-align: top; }
    .success { color: #0a7a2f; }
    .error { color: #b00020; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    input { width: 100%; box-sizing: border-box; font: inherit; padding: 10px 12px; }
    button { font: inherit; padding: 8px 12px; }
    .row-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .row-card { border: 1px solid #eee; border-radius: 10px; padding: 14px; margin-top: 12px; }
    .inline-actions { display: flex; gap: 8px; align-items: center; }
    .settings-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .settings-grid label { display: flex; flex-direction: column; gap: 6px; font-weight: 500; }
    .settings-grid input { margin-top: 2px; }
    .btn-primary { background: #0b57d0; color: #fff; border: none; border-radius: 6px; padding: 10px 18px; cursor: pointer; font-weight: 500; }
    .btn-primary:hover { background: #0842a0; }
    @media (max-width: 600px) { .settings-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <h1>Short Umami Sync</h1>
  <p><a href="/logout">Log out</a></p>
  {{if .Message}}<p class="success">{{.Message}}</p>{{end}}
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <div class="card">
    <h2>Configuration</h2>
    <p class="muted">Umami endpoint: <code>{{if .UmamiEndpoint}}{{.UmamiEndpoint}}{{else}}not set{{end}}</code></p>
    <p class="muted">API token: <code>{{if .UmamiAPIKey}}••••••••{{else}}not set{{end}}</code></p>
    <p class="muted">Fallback Umami property ID: <code>{{if .DefaultPropertyID}}{{.DefaultPropertyID}}{{else}}not set{{end}}</code></p>
    <p class="muted">Short.io webhook route: <code>{{.WebhookRoutePattern}}</code></p>
    <p class="muted">Use a unique route like <code>/webhooks/shortio/example.short.gy</code> or <code>/webhooks/shortio/short-domain-id</code> to target a specific mapping.</p>
  </div>
  <div class="card">
    <h2>Settings</h2>
    <p class="muted">Override Umami connection settings. Changes take effect immediately and persist across restarts. Environment variables are used as fallback when no database value is set.</p>
    <form method="post" action="/dashboard/settings">
      <div class="settings-grid">
        <label>
          Umami Endpoint
          <input type="text" name="umami_endpoint" value="{{.UmamiEndpoint}}" placeholder="https://umami.example.com/api/send">
        </label>
        <label>
          Umami API Token <span class="muted">(optional)</span>
          <input type="password" name="umami_api_key" value="{{.UmamiAPIKey}}" placeholder="Leave blank to clear" autocomplete="new-password">
        </label>
      </div>
      <p><button type="submit" class="btn-primary">Save Settings</button></p>
    </form>
  </div>
  <div class="card">
    <h2>Sync mappings</h2>
    <form method="post" action="/dashboard/mappings">
      <div class="grid">
        <label>Short.io domain or ID<br><input type="text" name="domain" placeholder="example.short.gy or short-domain-id"></label>
        <label>Umami property ID<br><input type="text" name="property_id" placeholder="umami-property-id"></label>
      </div>
      <p><button type="submit">Add mapping</button></p>
    </form>
    {{if .Mappings}}
      {{range .Mappings}}
        <div class="row-card">
          <form method="post" action="/dashboard/mappings">
            <input type="hidden" name="original_domain" value="{{.Domain}}">
            <div class="grid">
              <label>Short.io domain or ID<br><input type="text" name="domain" value="{{.Domain}}"></label>
              <label>Umami property ID<br><input type="text" name="property_id" value="{{.PropertyID}}"></label>
            </div>
            <div class="row-actions">
              <button type="submit">Save</button>
              <span class="muted">Created {{.CreatedAt.Format "2006-01-02 15:04:05 MST"}} · Updated {{.UpdatedAt.Format "2006-01-02 15:04:05 MST"}}</span>
            </div>
          </form>
          <form class="inline-actions" method="post" action="/dashboard/mappings/delete">
            <input type="hidden" name="domain" value="{{.Domain}}">
            <button type="submit">Delete</button>
          </form>
        </div>
      {{end}}
    {{else}}
      <p class="muted">No mappings configured yet.</p>
    {{end}}
  </div>
  <div class="card">
    <h2>Recent webhook events</h2>
    {{if .Events}}
      {{range .Events}}
        <div class="card">
          <div><strong>{{.Source}}</strong> — {{.ReceivedAt.Format "2006-01-02 15:04:05 MST"}}</div>
          <div>Webhook key: <code>{{.WebhookKey}}</code></div>
          <div>Payload domain: <code>{{.Domain}}</code></div>
          <div>Property ID: <code>{{.PropertyID}}</code></div>
          <div>Resolved from: {{.ResolvedFrom}}</div>
          <div>Forwarded to Umami: {{.Forwarded}}</div>
          {{if .ForwardError}}<div class="muted">{{.ForwardError}}</div>{{end}}
          <pre>{{printf "%s" .Payload}}</pre>
        </div>
      {{end}}
    {{else}}
      <p class="muted">No events received yet.</p>
    {{end}}
  </div>
</body>
</html>`
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
	settingsFromDB    bool
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
	mux.HandleFunc("/dashboard/settings", cfg.requireAuth(cfg.settingsUpdateHandler))
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

	// Load settings from database, overriding environment variables when present.
	if err := a.loadSettings(ctx); err != nil {
		log.Printf("event=settings_load_warning error=%q (using environment variables)", err)
	}

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
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`)
	return err
}

// loadSettings reads umami_endpoint and umami_api_key from the settings table
// and overrides the values that were seeded from environment variables.
// If a key is absent from the database the environment-variable value is kept.
func (a *app) loadSettings(ctx context.Context) error {
	rows, err := a.db.QueryContext(ctx, `SELECT key, value FROM settings WHERE key IN ('umami_endpoint','umami_api_key')`)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := 0
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		switch k {
		case "umami_endpoint":
			a.umamiEndpoint = v
			found++
		case "umami_api_key":
			a.umamiAPIKey = v
			found++
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if found > 0 {
		a.settingsFromDB = true
	}
	return nil
}

// saveSetting upserts a single key/value pair into the settings table.
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
		"SettingsFromDB":      a.settingsFromDB,
		"Message":             r.URL.Query().Get("message"),
		"Error":               r.URL.Query().Get("error"),
	})
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

	if endpoint != "" {
		if _, err := url.ParseRequestURI(endpoint); err != nil {
			redirectWithError(w, r, "Umami Endpoint must be a valid URL")
			return
		}
	}

	if endpoint != "" {
		if err := a.saveSetting(r.Context(), "umami_endpoint", endpoint); err != nil {
			redirectWithError(w, r, "failed to save endpoint: "+err.Error())
			return
		}
		a.umamiEndpoint = endpoint
	}
	if apiKey != "" {
		if err := a.saveSetting(r.Context(), "umami_api_key", apiKey); err != nil {
			redirectWithError(w, r, "failed to save API key: "+err.Error())
			return
		}
		a.umamiAPIKey = apiKey
	}
	a.settingsFromDB = true
	log.Printf("event=settings_updated endpoint=%q api_key_set=%v", endpoint, apiKey != "")
	redirectWithMessage(w, r, "Settings saved successfully")
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
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Short Umami Sync — Sign In</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: #f0f2f5;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      color: #1a1a2e;
    }
    .login-card {
      background: #fff;
      border-radius: 16px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.10), 0 1px 4px rgba(0,0,0,0.06);
      padding: 48px 40px 40px;
      width: 100%;
      max-width: 420px;
    }
    .logo {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 28px;
    }
    .logo-icon {
      width: 40px; height: 40px;
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      color: #fff;
      font-size: 20px;
      font-weight: 700;
      flex-shrink: 0;
    }
    .logo-text { font-size: 18px; font-weight: 700; color: #1a1a2e; line-height: 1.2; }
    .logo-sub  { font-size: 12px; color: #6b7280; font-weight: 400; }
    h1 { font-size: 22px; font-weight: 700; margin-bottom: 6px; }
    .subtitle { color: #6b7280; font-size: 14px; margin-bottom: 28px; }
    label { display: block; font-size: 13px; font-weight: 600; color: #374151; margin-bottom: 6px; }
    input[type="password"] {
      width: 100%;
      padding: 11px 14px;
      border: 1.5px solid #d1d5db;
      border-radius: 8px;
      font: inherit;
      font-size: 15px;
      color: #1a1a2e;
      background: #f9fafb;
      transition: border-color 0.15s, box-shadow 0.15s;
      outline: none;
    }
    input[type="password"]:focus {
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59,130,246,0.15);
      background: #fff;
    }
    .field { margin-bottom: 20px; }
    .btn {
      width: 100%;
      padding: 12px;
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      color: #fff;
      border: none;
      border-radius: 8px;
      font: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.15s, transform 0.1s;
      margin-top: 4px;
    }
    .btn:hover { opacity: 0.92; }
    .btn:active { transform: scale(0.99); }
    .alert-error {
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #b91c1c;
      border-radius: 8px;
      padding: 10px 14px;
      font-size: 14px;
      margin-bottom: 20px;
    }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="logo">
      <div class="logo-icon">S</div>
      <div>
        <div class="logo-text">Short Umami Sync</div>
        <div class="logo-sub">Analytics bridge</div>
      </div>
    </div>
    <h1>Welcome back</h1>
    <p class="subtitle">Sign in to manage your webhook mappings and settings.</p>
    {{if .Error}}<div class="alert-error">{{.Error}}</div>{{end}}
    <form method="post" action="/login">
      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" autofocus placeholder="Enter your password">
      </div>
      <button class="btn" type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>`

const dashboardTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dashboard — Short Umami Sync</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: #f0f2f5;
      color: #1a1a2e;
      min-height: 100vh;
    }
    /* ── Top nav ── */
    .topnav {
      background: #fff;
      border-bottom: 1px solid #e5e7eb;
      padding: 0 32px;
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 10;
      box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }
    .nav-brand {
      display: flex;
      align-items: center;
      gap: 10px;
      text-decoration: none;
      color: inherit;
    }
    .nav-icon {
      width: 34px; height: 34px;
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      color: #fff;
      font-size: 16px;
      font-weight: 700;
      flex-shrink: 0;
    }
    .nav-title { font-size: 16px; font-weight: 700; }
    .nav-sub   { font-size: 11px; color: #6b7280; }
    .nav-actions { display: flex; align-items: center; gap: 16px; }
    .nav-link {
      font-size: 13px;
      color: #6b7280;
      text-decoration: none;
      padding: 6px 12px;
      border-radius: 6px;
      transition: background 0.15s, color 0.15s;
    }
    .nav-link:hover { background: #f3f4f6; color: #1a1a2e; }
    /* ── Page wrapper ── */
    .page { max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }
    /* ── Alerts ── */
    .alert {
      border-radius: 10px;
      padding: 12px 16px;
      font-size: 14px;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .alert-success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #15803d; }
    .alert-error   { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; }
    .alert-icon { font-size: 16px; flex-shrink: 0; }
    /* ── Section cards ── */
    .section {
      background: #fff;
      border: 1px solid #e5e7eb;
      border-radius: 14px;
      box-shadow: 0 1px 4px rgba(0,0,0,0.05);
      margin-bottom: 24px;
      overflow: hidden;
    }
    .section-header {
      padding: 20px 24px 16px;
      border-bottom: 1px solid #f3f4f6;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .section-title {
      font-size: 16px;
      font-weight: 700;
      color: #111827;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .section-title .icon {
      width: 28px; height: 28px;
      border-radius: 7px;
      display: flex; align-items: center; justify-content: center;
      font-size: 14px;
      flex-shrink: 0;
    }
    .icon-blue   { background: #eff6ff; color: #3b82f6; }
    .icon-purple { background: #f5f3ff; color: #7c3aed; }
    .icon-green  { background: #f0fdf4; color: #16a34a; }
    .icon-orange { background: #fff7ed; color: #ea580c; }
    .section-desc { font-size: 13px; color: #6b7280; margin-top: 2px; }
    .section-body { padding: 20px 24px; }
    /* ── Form elements ── */
    .field { margin-bottom: 16px; }
    .field:last-child { margin-bottom: 0; }
    .field label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #374151;
      margin-bottom: 6px;
    }
    .field input[type="text"],
    .field input[type="url"] {
      width: 100%;
      padding: 10px 13px;
      border: 1.5px solid #d1d5db;
      border-radius: 8px;
      font: inherit;
      font-size: 14px;
      color: #1a1a2e;
      background: #f9fafb;
      transition: border-color 0.15s, box-shadow 0.15s;
      outline: none;
    }
    .field input[type="text"]:focus,
    .field input[type="url"]:focus {
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59,130,246,0.12);
      background: #fff;
    }
    .field-hint { font-size: 12px; color: #9ca3af; margin-top: 4px; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    @media (max-width: 640px) { .grid-2 { grid-template-columns: 1fr; } }
    /* ── Buttons ── */
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 9px 18px;
      border-radius: 8px;
      font: inherit;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      border: none;
      transition: opacity 0.15s, transform 0.1s, box-shadow 0.15s;
      text-decoration: none;
    }
    .btn:active { transform: scale(0.98); }
    .btn-primary {
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      color: #fff;
      box-shadow: 0 1px 3px rgba(99,102,241,0.3);
    }
    .btn-primary:hover { opacity: 0.9; box-shadow: 0 2px 8px rgba(99,102,241,0.35); }
    .btn-secondary {
      background: #fff;
      color: #374151;
      border: 1.5px solid #d1d5db;
    }
    .btn-secondary:hover { background: #f9fafb; border-color: #9ca3af; }
    .btn-danger {
      background: #fff;
      color: #b91c1c;
      border: 1.5px solid #fca5a5;
    }
    .btn-danger:hover { background: #fef2f2; border-color: #f87171; }
    .btn-sm { padding: 6px 12px; font-size: 12px; }
    /* ── Settings source badge ── */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 9px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
    }
    .badge-db  { background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }
    .badge-env { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
    /* ── Info row ── */
    .info-row {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 0;
      border-bottom: 1px solid #f3f4f6;
      font-size: 13px;
    }
    .info-row:last-child { border-bottom: none; padding-bottom: 0; }
    .info-label { color: #6b7280; min-width: 180px; flex-shrink: 0; }
    .info-value { color: #111827; font-weight: 500; }
    code {
      background: #f3f4f6;
      border: 1px solid #e5e7eb;
      padding: 2px 7px;
      border-radius: 5px;
      font-size: 12px;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      color: #374151;
      word-break: break-all;
    }
    /* ── Mapping rows ── */
    .mapping-row {
      border: 1px solid #e5e7eb;
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 12px;
      background: #fafafa;
      transition: border-color 0.15s;
    }
    .mapping-row:hover { border-color: #c7d2fe; background: #fff; }
    .mapping-row:last-child { margin-bottom: 0; }
    .mapping-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 12px;
      flex-wrap: wrap;
    }
    .mapping-meta { font-size: 11px; color: #9ca3af; margin-left: auto; }
    /* ── Events ── */
    .event-card {
      border: 1px solid #e5e7eb;
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 12px;
      background: #fafafa;
    }
    .event-card:last-child { margin-bottom: 0; }
    .event-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 10px;
      flex-wrap: wrap;
    }
    .event-source {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #6366f1;
      background: #f5f3ff;
      padding: 2px 8px;
      border-radius: 4px;
    }
    .event-time { font-size: 12px; color: #9ca3af; }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 8px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
    }
    .status-ok  { background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }
    .status-err { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
    .status-pending { background: #fffbeb; color: #b45309; border: 1px solid #fde68a; }
    .event-fields { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; margin-bottom: 10px; }
    .event-field { font-size: 12px; }
    .event-field-label { color: #9ca3af; margin-bottom: 2px; }
    .event-field-value { color: #374151; font-weight: 500; }
    .event-error { font-size: 12px; color: #b91c1c; background: #fef2f2; border-radius: 6px; padding: 6px 10px; margin-top: 8px; }
    details { margin-top: 10px; }
    summary {
      font-size: 12px;
      color: #6b7280;
      cursor: pointer;
      user-select: none;
      padding: 4px 0;
    }
    summary:hover { color: #374151; }
    pre {
      background: #1e1e2e;
      color: #cdd6f4;
      border-radius: 8px;
      padding: 14px;
      font-size: 12px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-all;
      margin-top: 8px;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      line-height: 1.6;
    }
    .empty-state {
      text-align: center;
      padding: 40px 20px;
      color: #9ca3af;
    }
    .empty-state .empty-icon { font-size: 36px; margin-bottom: 10px; }
    .empty-state p { font-size: 14px; }
    a { color: #3b82f6; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .divider { height: 1px; background: #f3f4f6; margin: 16px 0; }
  </style>
</head>
<body>
  <!-- Top navigation -->
  <nav class="topnav">
    <a class="nav-brand" href="/dashboard">
      <div class="nav-icon">S</div>
      <div>
        <div class="nav-title">Short Umami Sync</div>
        <div class="nav-sub">Analytics bridge</div>
      </div>
    </a>
    <div class="nav-actions">
      <a class="nav-link" href="/logout">Sign out</a>
    </div>
  </nav>

  <div class="page">
    <!-- Alerts -->
    {{if .Message}}
    <div class="alert alert-success">
      <span class="alert-icon">✓</span>
      <span>{{.Message}}</span>
    </div>
    {{end}}
    {{if .Error}}
    <div class="alert alert-error">
      <span class="alert-icon">✕</span>
      <span>{{.Error}}</span>
    </div>
    {{end}}

    <!-- ── Umami Settings ── -->
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">
            <span class="icon icon-blue">⚙</span>
            Umami Settings
          </div>
          <div class="section-desc">Configure the Umami endpoint and API token. Changes are persisted in the database.</div>
        </div>
        {{if .SettingsFromDB}}
          <span class="badge badge-db">● Database</span>
        {{else}}
          <span class="badge badge-env">● Environment</span>
        {{end}}
      </div>
      <div class="section-body">
        <form method="post" action="/dashboard/settings">
          <div class="grid-2">
            <div class="field">
              <label for="umami_endpoint">Umami Endpoint URL</label>
              <input type="url" id="umami_endpoint" name="umami_endpoint" value="{{.UmamiEndpoint}}" placeholder="https://umami.example.com/api/send">
              <div class="field-hint">The full URL of your Umami ingest endpoint.</div>
            </div>
            <div class="field">
              <label for="umami_api_key">API Token</label>
              <input type="text" id="umami_api_key" name="umami_api_key" value="{{.UmamiAPIKey}}" placeholder="Bearer token (optional)">
              <div class="field-hint">Leave blank to keep the current token unchanged.</div>
            </div>
          </div>
          <div style="margin-top:16px;">
            <button class="btn btn-primary" type="submit">Save settings</button>
          </div>
        </form>
        <div class="divider"></div>
        <div class="info-row">
          <span class="info-label">Fallback property ID</span>
          <span class="info-value"><code>{{if .DefaultPropertyID}}{{.DefaultPropertyID}}{{else}}not set{{end}}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">Webhook route pattern</span>
          <span class="info-value"><code>{{.WebhookRoutePattern}}</code></span>
        </div>
        <div class="info-row" style="border-bottom:none; padding-bottom:0;">
          <span class="info-label">Example webhook URL</span>
          <span class="info-value"><code>/webhooks/shortio/example.short.gy</code></span>
        </div>
      </div>
    </div>

    <!-- ── Domain Mappings ── -->
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">
            <span class="icon icon-purple">⇄</span>
            Domain Mappings
          </div>
          <div class="section-desc">Map Short.io domains or IDs to Umami property IDs.</div>
        </div>
      </div>
      <div class="section-body">
        <!-- Add new mapping -->
        <form method="post" action="/dashboard/mappings" style="margin-bottom:20px;">
          <div class="grid-2">
            <div class="field">
              <label>Short.io domain or ID</label>
              <input type="text" name="domain" placeholder="example.short.gy">
            </div>
            <div class="field">
              <label>Umami property ID</label>
              <input type="text" name="property_id" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
            </div>
          </div>
          <button class="btn btn-primary" type="submit">Add mapping</button>
        </form>

        {{if .Mappings}}
          {{range .Mappings}}
          <div class="mapping-row">
            <form method="post" action="/dashboard/mappings">
              <input type="hidden" name="original_domain" value="{{.Domain}}">
              <div class="grid-2">
                <div class="field">
                  <label>Short.io domain or ID</label>
                  <input type="text" name="domain" value="{{.Domain}}">
                </div>
                <div class="field">
                  <label>Umami property ID</label>
                  <input type="text" name="property_id" value="{{.PropertyID}}">
                </div>
              </div>
              <div class="mapping-actions">
                <button class="btn btn-secondary btn-sm" type="submit">Save changes</button>
                <span class="mapping-meta">Created {{.CreatedAt.Format "Jan 2, 2006"}} · Updated {{.UpdatedAt.Format "Jan 2, 2006 15:04 MST"}}</span>
              </div>
            </form>
            <form method="post" action="/dashboard/mappings/delete" style="margin-top:8px;">
              <input type="hidden" name="domain" value="{{.Domain}}">
              <button class="btn btn-danger btn-sm" type="submit">Delete</button>
            </form>
          </div>
          {{end}}
        {{else}}
          <div class="empty-state">
            <div class="empty-icon">⇄</div>
            <p>No mappings configured yet. Add one above to get started.</p>
          </div>
        {{end}}
      </div>
    </div>

    <!-- ── Recent Events ── -->
    <div class="section">
      <div class="section-header">
        <div>
          <div class="section-title">
            <span class="icon icon-green">↻</span>
            Recent Webhook Events
          </div>
          <div class="section-desc">Last 100 events received from Short.io webhooks.</div>
        </div>
        {{if .Events}}
          <span class="badge badge-db" style="background:#f0fdf4;color:#15803d;border-color:#bbf7d0;">{{len .Events}} events</span>
        {{end}}
      </div>
      <div class="section-body">
        {{if .Events}}
          {{range .Events}}
          <div class="event-card">
            <div class="event-header">
              <span class="event-source">{{.Source}}</span>
              <span class="event-time">{{.ReceivedAt.Format "Jan 2, 2006 15:04:05 MST"}}</span>
              {{if .Forwarded}}
                <span class="status-badge status-ok">✓ Forwarded</span>
              {{else if .ForwardError}}
                <span class="status-badge status-err">✕ Failed</span>
              {{else}}
                <span class="status-badge status-pending">⏸ Pending</span>
              {{end}}
            </div>
            <div class="event-fields">
              <div class="event-field">
                <div class="event-field-label">Webhook key</div>
                <div class="event-field-value"><code>{{if .WebhookKey}}{{.WebhookKey}}{{else}}—{{end}}</code></div>
              </div>
              <div class="event-field">
                <div class="event-field-label">Payload domain</div>
                <div class="event-field-value"><code>{{if .Domain}}{{.Domain}}{{else}}—{{end}}</code></div>
              </div>
              <div class="event-field">
                <div class="event-field-label">Property ID</div>
                <div class="event-field-value"><code>{{if .PropertyID}}{{.PropertyID}}{{else}}—{{end}}</code></div>
              </div>
              <div class="event-field">
                <div class="event-field-label">Resolved from</div>
                <div class="event-field-value">{{if .ResolvedFrom}}{{.ResolvedFrom}}{{else}}—{{end}}</div>
              </div>
            </div>
            {{if .ForwardError}}
              <div class="event-error">Error: {{.ForwardError}}</div>
            {{end}}
            <details>
              <summary>View raw payload</summary>
              <pre>{{printf "%s" .Payload}}</pre>
            </details>
          </div>
          {{end}}
        {{else}}
          <div class="empty-state">
            <div class="empty-icon">↻</div>
            <p>No events received yet. Configure a Short.io webhook to get started.</p>
          </div>
        {{end}}
      </div>
    </div>
  </div>
</body>
</html>`
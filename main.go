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
	mappingsMu       sync.RWMutex
	umamiEndpoint    string
	umamiAPIKey      string
	umamiDefaultProp string
	mu               sync.Mutex
	events           []Event
	tmplLogin        *template.Template
	tmplDash         *template.Template
}


func main() {
	setupPersistentLogging()
	cfg := mustNewApp()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/login", cfg.loginHandler)
	mux.HandleFunc("/logout", cfg.logoutHandler)
	mux.HandleFunc("/dashboard", cfg.requireAuth(cfg.dashboardHandler))
	mux.HandleFunc("/api/events", cfg.requireAuth(cfg.apiEventsHandler))
	mux.HandleFunc("/dashboard/settings", cfg.requireAuth(cfg.settingsUpdateHandler))
	mux.HandleFunc("/dashboard/mappings", cfg.requireAuth(cfg.mappingUpsertHandler))
	mux.HandleFunc("/dashboard/mappings/delete", cfg.requireAuth(cfg.mappingDeleteHandler))
	mux.HandleFunc("/webhooks/shortio", cfg.shortioWebhookHandler)
	mux.HandleFunc("/webhooks/shortio/", cfg.shortioWebhookHandler)
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
	if err := initEventHistory(ctx, db); err != nil {
		log.Printf("failed to initialize event history: %v", err)
	}

	return &app{
		db:               db,
		password:         envOr("APP_PASSWORD", "changeme"),
		sessionSecret:    mustEnv("SESSION_SECRET"),
		umamiEndpoint:    normalizeUmamiEndpoint(settingOrEnv(storedSettings, "umami_endpoint", "UMAMI_ENDPOINT")),
		umamiAPIKey:      settingOrEnvAny(storedSettings, "umami_api_key", "UMAMI_API_TOKEN", "UMAMI_API_KEY"),
		umamiDefaultProp: settingOrEnvAny(storedSettings, "umami_website_id", "FALLBACK_SITE_ID", "UMAMI_WEBSITE_ID"),
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

func settingOrEnvAny(settings map[string]string, key string, envKeys ...string) string {
	if value, ok := settings[key]; ok {
		return value
	}
	for _, envKey := range envKeys {
		if value := strings.TrimSpace(os.Getenv(envKey)); value != "" {
			return value
		}
	}
	return ""
}

func normalizeUmamiEndpoint(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	return strings.TrimRight(value, " ")
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
	events, err := a.listEvents(r.Context(), 100)
	if err != nil {
		http.Error(w, "failed to load events: "+err.Error(), http.StatusInternalServerError)
		return
	}

	settings := a.settingsSnapshot()
	_ = a.tmplDash.Execute(w, map[string]any{
		"Events":            events,
		"Mappings":          mappings,
		"UmamiEndpoint":     settings.Endpoint,
		"UmamiAPIKey":       settings.APIKey,
		"DefaultPropertyID": settings.DefaultPropertyID,
		"Message":           r.URL.Query().Get("message"),
		"Error":             r.URL.Query().Get("error"),
	})
}

func (a *app) apiEventsHandler(w http.ResponseWriter, r *http.Request) {
	events, err := a.listEvents(r.Context(), 100)
	if err != nil {
		http.Error(w, "failed to load events: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
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

	endpoint := normalizeUmamiEndpoint(strings.TrimSpace(r.FormValue("umami_endpoint")))
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
	a.umamiEndpoint = normalizeUmamiEndpoint(endpoint)
	a.umamiAPIKey = apiKey
	a.umamiDefaultProp = defaultPropertyID
}

func (a *app) saveSettings(ctx context.Context, endpoint, apiKey, defaultPropertyID string) error {
	endpoint = normalizeUmamiEndpoint(endpoint)
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

func (a *app) listEvents(ctx context.Context, limit int) ([]Event, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := a.db.QueryContext(queryCtx, `
		SELECT received_at, source, domain, property_id, payload, forwarded, forward_error
		FROM event_history
		ORDER BY received_at DESC, id DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var event Event
		var domain, propertyID, forwardError string
		var payload []byte
		if err := rows.Scan(&event.ReceivedAt, &event.Source, &domain, &propertyID, &payload, &event.Forwarded, &forwardError); err != nil {
			return nil, err
		}
		if domain != "" {
			event.Domain = domain
		}
		if propertyID != "" {
			event.PropertyID = propertyID
		}
		if forwardError != "" {
			event.ForwardError = forwardError
		}
		event.Payload = json.RawMessage(payload)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}


func initEventHistory(ctx context.Context, db *sql.DB) error {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := db.ExecContext(queryCtx, `
		CREATE TABLE IF NOT EXISTS event_history (
			id BIGSERIAL PRIMARY KEY,
			received_at TIMESTAMPTZ NOT NULL,
			source TEXT NOT NULL,
			domain TEXT NOT NULL DEFAULT '',
			property_id TEXT NOT NULL DEFAULT '',
			payload JSONB NOT NULL,
			forwarded BOOLEAN NOT NULL DEFAULT false,
			forward_error TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS event_history_received_at_idx ON event_history (received_at DESC, id DESC);
	`)
	return err
}

func persistEvent(ctx context.Context, db *sql.DB, event Event) error {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := db.ExecContext(queryCtx, `
		INSERT INTO event_history (received_at, source, domain, property_id, payload, forwarded, forward_error)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5::jsonb, $6, $7)
	`, event.ReceivedAt, event.Source, event.Domain, event.PropertyID, []byte(event.Payload), event.Forwarded, event.ForwardError)
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
	routeKey := ""
	if strings.HasPrefix(r.URL.Path, "/webhooks/shortio/") {
		routeKey = normalizeDomain(strings.TrimPrefix(r.URL.Path, "/webhooks/shortio/"))
	}
	payload := json.RawMessage(body)
	payloadDomain := extractDomain(payload)
	propertyID, resolvedFrom, resolveErr := a.resolvePropertyID(r.Context(), routeKey, payloadDomain, settings.DefaultPropertyID)
	domainForEvent := routeKey
	if domainForEvent == "" {
		domainForEvent = payloadDomain
	}
	event := Event{ReceivedAt: time.Now().UTC(), Source: "shortio", Domain: domainForEvent, PropertyID: propertyID, Payload: payload}
	if resolveErr != nil {
		event.Forwarded = false
		event.ForwardError = resolveErr.Error()
	} else {
		event.Forwarded, event.ForwardError = a.forwardToUmami(r, payload, domainForEvent, propertyID, resolvedFrom, settings.Endpoint, settings.APIKey)
	}
	if err := persistEvent(r.Context(), a.db, event); err != nil {
		log.Printf("failed to persist event: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "forwarded": event.Forwarded, "error": event.ForwardError, "domain": domainForEvent, "property_id": propertyID})
}

func (a *app) resolvePropertyID(ctx context.Context, routeKey, payloadDomain, defaultPropertyID string) (propertyID string, resolvedFrom string, err error) {
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
	if strings.TrimSpace(defaultPropertyID) != "" {
		return strings.TrimSpace(defaultPropertyID), "environment", nil
	}
	return "", "", fmt.Errorf("no domain mapping found for route key %q or payload domain %q", routeKey, payloadDomain)
}

func (a *app) forwardToUmami(r *http.Request, payload json.RawMessage, domain, propertyID, resolvedFrom, endpoint, apiKey string) (bool, string) {
	endpoint = normalizeUmamiEndpoint(endpoint)
	if endpoint == "" {
		return false, "UMAMI_ENDPOINT is not configured"
	}
	forward := map[string]any{
		"source":      "shortio",
		"received_at": time.Now().UTC().Format(time.RFC3339Nano),
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

func setupPersistentLogging() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
	if err := os.MkdirAll("/data", 0o755); err != nil {
		log.Printf("failed to create /data for logs: %v", err)
		return
	}
	file, err := os.OpenFile("/data/short-umami-sync.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("failed to open persistent log file: %v", err)
		return
	}
	log.SetOutput(io.MultiWriter(os.Stdout, file))
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
      --bg: #f5f7fa;
      --surface: rgba(255, 255, 255, 0.92);
      --border: rgba(15, 23, 42, 0.08);
      --text: #0f172a;
      --muted: #64748b;
      --accent-2: #115e59;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(45, 212, 191, 0.12), transparent 24%),
        linear-gradient(180deg, #f8fafc 0%, #edf2f7 100%);
    }
    .panel {
      width: min(100%, 420px);
      padding: 28px;
      border-radius: 24px;
      background: var(--surface);
      border: 1px solid var(--border);
      backdrop-filter: blur(10px);
      box-shadow: 0 24px 70px rgba(15, 23, 42, 0.08);
    }
    .eyebrow {
      display: inline-flex;
      padding: 7px 10px;
      border-radius: 999px;
      font-size: 11px;
      letter-spacing: .08em;
      text-transform: uppercase;
      font-weight: 700;
      color: var(--accent-2);
      background: rgba(15, 118, 110, 0.08);
      margin-bottom: 14px;
    }
    h1 { margin: 0 0 8px; font-size: 30px; letter-spacing: -0.03em; }
    p { margin: 0; color: var(--muted); line-height: 1.55; }
    form { margin-top: 24px; display: grid; gap: 12px; }
    label { display: grid; gap: 8px; font-size: 13px; font-weight: 600; color: #334155; }
    input {
      width: 100%;
      padding: 13px 14px;
      border-radius: 14px;
      border: 1px solid rgba(148, 163, 184, 0.35);
      background: white;
      font: inherit;
      color: var(--text);
      outline: none;
    }
    input:focus { border-color: rgba(15, 118, 110, 0.5); box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12); }
    button {
      border: 0;
      border-radius: 14px;
      padding: 12px 16px;
      background: linear-gradient(180deg, #14b8a6, #0f766e);
      color: white;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }
    .error {
      margin-top: 14px;
      padding: 12px 14px;
      border-radius: 14px;
      background: rgba(185, 28, 28, 0.08);
      color: #b91c1c;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <main class="panel">
    <div class="eyebrow">Short Umami Sync</div>
    <h1>Sign in</h1>
    <p>Manage the settings, mappings, and activity feed.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="post" action="/login">
      <label>Password
        <input type="password" name="password" autofocus>
      </label>
      <button type="submit">Continue</button>
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
      --bg: #f5f7fa;
      --surface: rgba(255, 255, 255, 0.9);
      --surface-2: #ffffff;
      --border: rgba(15, 23, 42, 0.08);
      --text: #0f172a;
      --muted: #64748b;
      --accent-2: #115e59;
      --danger: #b91c1c;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(45, 212, 191, 0.12), transparent 24%),
        linear-gradient(180deg, #f8fafc 0%, #edf2f7 100%);
    }
    a { color: inherit; text-decoration: none; }
    code {
      padding: 0.18rem 0.45rem;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.05);
      word-break: break-word;
      font-size: .92em;
    }
    .page { width: min(1120px, calc(100% - 12px)); margin: 6px auto 16px; }
    .topbar {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 12px;
      align-items: start;
      margin-bottom: 12px;
    }
    .hero, .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 24px;
      backdrop-filter: blur(10px);
      box-shadow: 0 22px 60px rgba(15, 23, 42, 0.06);
    }
    .hero { padding: 14px; }
    .eyebrow {
      display: inline-flex;
      padding: 7px 10px;
      border-radius: 999px;
      font-size: 11px;
      letter-spacing: .08em;
      text-transform: uppercase;
      font-weight: 700;
      color: var(--accent-2);
      background: rgba(15, 118, 110, 0.08);
      margin-bottom: 14px;
    }
    h1, h2 { margin: 0; letter-spacing: -0.03em; }
    h1 { font-size: 34px; line-height: 1.05; }
    h2 { font-size: 17px; }
    p { margin: 0; }
    .subtitle { margin-top: 10px; max-width: 72ch; color: var(--muted); line-height: 1.55; }
    .actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .actions > * { min-width: 0; }
    .btn, button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      padding: 0 14px;
      width: 100%;
      border-radius: 12px;
      white-space: normal;
      word-break: break-word;
      text-align: center;
      border: 1px solid rgba(148, 163, 184, 0.28);
      background: var(--surface-2);
      color: var(--text);
      font: inherit;
      font-weight: 650;
      cursor: pointer;
    }
    .btn.primary, button.primary {
      background: linear-gradient(180deg, #14b8a6, #0f766e);
      color: white;
      border-color: transparent;
    }
    .notice {
      margin-top: 14px;
      padding: 12px 14px;
      border-radius: 14px;
      font-size: 14px;
      line-height: 1.45;
    }
    .notice.success { background: rgba(21, 128, 61, 0.08); color: #15803d; }
    .notice.error { background: rgba(185, 28, 28, 0.08); color: var(--danger); }
    .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
    .chip {
      display: inline-flex;
      gap: 8px;
      align-items: center;
      padding: 8px 10px;
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.04);
      color: #334155;
      font-size: 13px;
      border: 1px solid rgba(148, 163, 184, 0.16);
    }
    .chip strong { color: var(--text); }
    .grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 12px;
      margin-top: 12px;
    }
    .card { padding: 12px; }
    .settings, .mappings, .events { grid-column: span 1; }
    @media (min-width: 720px) {
      .page { width: min(1120px, calc(100% - 24px)); margin: 10px auto 24px; }
      .hero { padding: 18px; }
      .card { padding: 14px; }
      .actions { grid-template-columns: repeat(4, minmax(0, 1fr)); }
      .mapping-fields { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .toolbar { flex-direction: row; justify-content: space-between; align-items: center; }
      .mapping-top { flex-direction: row; justify-content: space-between; align-items: flex-start; }
      .mapping-url { grid-template-columns: minmax(0, 1fr) auto; align-items: center; }
      .mapping-url button { width: auto; }
      .event-head { flex-direction: row; justify-content: space-between; align-items: flex-start; }
      .row-actions { grid-template-columns: repeat(3, auto); justify-content: end; }
      .row-actions .chip { width: auto; }
    }
    .section-head {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 14px;
    }
    .muted { color: var(--muted); }
    .tiny { font-size: 12px; }
    .form { display: grid; gap: 12px; }
    .mapping-fields { display: grid; gap: 12px; grid-template-columns: minmax(0, 1fr); }
    label {
      display: grid;
      gap: 7px;
      font-size: 13px;
      font-weight: 650;
      color: #334155;
    }
    input {
      width: 100%;
      padding: 12px 13px;
      border-radius: 14px;
      border: 1px solid rgba(148, 163, 184, 0.32);
      background: white;
      font: inherit;
      color: var(--text);
      outline: none;
    }
    input:focus { border-color: rgba(15, 118, 110, 0.55); box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12); }
    .toolbar { display: flex; flex-direction: column; align-items: stretch; gap: 10px; margin-top: 14px; }
    .mapping {
      display: grid;
      gap: 14px;
      padding: 14px 0;
      border-top: 1px solid rgba(148, 163, 184, 0.14);
    }
    .mapping:first-child { border-top: 0; padding-top: 0; }
    .mapping-top {
      display: flex;
      flex-direction: column;
      gap: 12px;
      align-items: stretch;
    }
    .mapping-title { font-weight: 700; }
    .mapping-url {
      display: grid;
      gap: 8px;
      align-items: start;
      color: var(--muted);
      font-size: 13px;
      word-break: break-word;
    }
    .mapping-url span { word-break: break-word; }
    .mapping-url button { width: 100%; }
    .row-actions { display: grid; gap: 8px; }
    .row-actions .chip { width: 100%; }
    .secondary {
      background: transparent;
      border-color: rgba(148, 163, 184, 0.28);
      color: #334155;
    }
    .events-list { display: grid; gap: 10px; }
    .event {
      padding: 14px 0 0;
      border-top: 1px solid rgba(148, 163, 184, 0.14);
    }
    .event:first-child { border-top: 0; padding-top: 0; }
    .event-head { display: flex; flex-direction: column; justify-content: space-between; gap: 12px; }
    .badge {
      display: inline-flex;
      padding: 7px 10px;
      border-radius: 999px;
      background: rgba(15, 118, 110, 0.08);
      color: var(--accent-2);
      font-size: 12px;
      font-weight: 700;
    }
    pre {
      margin: 12px 0 0;
      padding: 12px;
      border-radius: 16px;
      background: #0b1120;
      color: #d9e2f2;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 12px;
      line-height: 1.55;
    }
  </style>
  <script>
    function escapeHtml(value) {
      return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function formatDate(value) {
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return escapeHtml(value);
      return new Intl.DateTimeFormat([], { dateStyle: 'medium', timeStyle: 'short' }).format(date);
    }

    function renderEvent(event) {
      const domain = event.domain || '—';
      const propertyID = event.property_id || '—';
      const forwarded = event.forwarded ? 'true' : 'false';
      const error = event.forward_error ? '<div class="notice error" style="margin-top:12px;">' + escapeHtml(event.forward_error) + '</div>' : '';
      return '' +
        '<div class="event">' +
          '<div class="event-head">' +
            '<div>' +
              '<div class="badge">' + escapeHtml(event.source || '') + '</div>' +
              '<div style="margin-top: 8px; font-weight: 700;">' + formatDate(event.received_at) + '</div>' +
            '</div>' +
            '<div class="row-actions">' +
              '<span class="chip"><strong>Domain</strong> ' + escapeHtml(domain) + '</span>' +
              '<span class="chip"><strong>Site</strong> ' + escapeHtml(propertyID) + '</span>' +
              '<span class="chip"><strong>Forwarded</strong> ' + forwarded + '</span>' +
            '</div>' +
          '</div>' +
          error +
          '<pre>' + escapeHtml(JSON.stringify(event.payload ?? null, null, 2)) + '</pre>' +
        '</div>';
    }

    async function refreshEvents() {
      const container = document.getElementById('events-list');
      if (!container) return;
      try {
        const response = await fetch('/api/events', { cache: 'no-store' });
        if (!response.ok) return;
        const events = await response.json();
        if (!Array.isArray(events) || events.length === 0) {
          container.innerHTML = '<p class="muted tiny">No events received yet.</p>';
          return;
        }
        container.innerHTML = events.map(renderEvent).join('');
      } catch (error) {
      }
    }

    async function copyWebhook(domain, button) {
      const url = window.location.origin.replace(//$/, "") + '/webhooks/shortio/' + encodeURIComponent(domain);
      try {
        await navigator.clipboard.writeText(url);
        const previous = button.textContent;
        button.textContent = 'Copied';
        setTimeout(() => { button.textContent = previous; }, 1200);
      } catch (error) {
        button.textContent = 'Copy failed';
        setTimeout(() => { button.textContent = 'Copy Webhook'; }, 1200);
      }
    }

    window.addEventListener('DOMContentLoaded', refreshEvents);
  </script>
</head>
<body>
  <main class="page">
    <div class="topbar">
      <section class="hero">
        <div class="eyebrow">Short Umami Sync</div>
        <h1>Dashboard</h1>
        <p class="subtitle">Minimal settings for forwarding Short.io events to Umami. Enter a full collect URL such as <code>https://stats.brayden.me/bray</code>.</p>
        <div class="chips">
          <span class="chip"><strong>Endpoint</strong> {{if .UmamiEndpoint}}{{.UmamiEndpoint}}{{else}}not set{{end}}</span>
          <span class="chip"><strong>Fallback Site ID</strong> {{if .DefaultPropertyID}}{{.DefaultPropertyID}}{{else}}not set{{end}}</span>
        </div>
        {{if .Message}}<div class="notice success">{{.Message}}</div>{{end}}
        {{if .Error}}<div class="notice error">{{.Error}}</div>{{end}}
      </section>
      <div class="actions">
        <a class="btn primary" href="#settings">Settings</a>
        <a class="btn" href="#mappings">Mappings</a>
        <a class="btn" href="#events">Events</a>
        <a class="btn" href="/logout">Log out</a>
      </div>
    </div>

    <section class="grid">
      <article class="card settings" id="settings">
        <div class="section-head">
          <div>
            <h2>Settings</h2>
            <p class="muted tiny">Saved to Postgres and applied immediately.</p>
          </div>
        </div>
        <form class="form" method="post" action="/dashboard/settings">
          <label>Umami Endpoint
            <input type="text" name="umami_endpoint" value="{{.UmamiEndpoint}}" placeholder="https://stats.brayden.me/bray">
            <span class="muted tiny">A path is allowed here; if you enter stats.brayden.me/bray, https:// is added automatically.</span>
          </label>
          <label>Umami API Token
            <input type="text" name="umami_api_key" value="{{.UmamiAPIKey}}" placeholder="optional bearer token">
          </label>
          <label>Fallback Site ID
            <input type="text" name="umami_website_id" value="{{.DefaultPropertyID}}" placeholder="umami-site-id">
          </label>
          <div class="toolbar">
            <span class="muted tiny">Used when a mapping doesn\u2019t exist.</span>
            <button class="primary" type="submit">Save</button>
          </div>
        </form>
      </article>

      <article class="card mappings" id="mappings">
        <div class="section-head">
          <div>
            <h2>Mappings</h2>
            <p class="muted tiny">Each domain gets its own webhook URL.</p>
          </div>
        </div>
        <form class="form" method="post" action="/dashboard/mappings">
          <div class="mapping-fields">
            <label>Short.io domain
              <input type="text" name="domain" placeholder="example.short.gy">
            </label>
            <label>Umami Site ID
              <input type="text" name="property_id" placeholder="umami-site-id">
            </label>
          </div>
          <div class="toolbar">
            <span class="muted tiny">Domains are normalized before saving.</span>
            <button class="primary" type="submit">Add mapping</button>
          </div>
        </form>

        <div class="events-list" style="margin-top: 16px;">
          {{if .Mappings}}
            {{range .Mappings}}
              <div class="mapping">
                <div class="mapping-top">
                  <div>
                    <div class="mapping-title"><code>{{.Domain}}</code></div>
                    <div class="mapping-url">
                      <span>{{printf "/webhooks/shortio/%s" .Domain}}</span>
                      <button class="secondary" type="button" onclick="copyWebhook('{{.Domain}}', this)">Copy Webhook</button>
                    </div>
                  </div>
                  <div class="row-actions">
                    <span class="chip"><strong>Site</strong> {{if .PropertyID}}{{.PropertyID}}{{else}}\u2014{{end}}</span>
                    <span class="chip"><strong>Updated</strong> {{.UpdatedAt.Format "2006-01-02 15:04 MST"}}</span>
                  </div>
                </div>
              </div>
            {{end}}
          {{else}}
            <p class="muted tiny">No mappings yet.</p>
          {{end}}
        </div>
      </article>

      <article class="card events" id="events">
        <div class="section-head">
          <div>
            <h2>Events</h2>
            <p class="muted tiny">Recent webhook activity.</p>
          </div>
        </div>
        <div class="events-list" id="events-list">
          {{if .Events}}
            {{range .Events}}
              <div class="event">
                <div class="event-head">
                  <div>
                    <div class="badge">{{.Source}}</div>
                    <div style="margin-top: 8px; font-weight: 700;">{{.ReceivedAt.Format "2006-01-02 15:04 MST"}}</div>
                  </div>
                  <div class="row-actions">
                    <span class="chip"><strong>Domain</strong> {{if .Domain}}{{.Domain}}{{else}}\u2014{{end}}</span>
                    <span class="chip"><strong>Site</strong> {{if .PropertyID}}{{.PropertyID}}{{else}}\u2014{{end}}</span>
                    <span class="chip"><strong>Forwarded</strong> {{.Forwarded}}</span>
                  </div>
                </div>
                {{if .ForwardError}}<div class="notice error" style="margin-top:12px;">{{.ForwardError}}</div>{{end}}
                <pre>{{printf "%s" .Payload}}</pre>
              </div>
            {{end}}
          {{else}}
            <p class="muted tiny">No events received yet.</p>
          {{end}}
        </div>
      </article>
    </section>
  </main>
</body>
</html>`

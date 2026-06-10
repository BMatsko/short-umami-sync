package main

import (
	"bytes"
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

const (
	persistentLogPath        = "/data/short-umami-sync.log"
	persistentLogRetention   = time.Hour
	persistentLogPruneEvery  = 5 * time.Minute
	persistentLogTimestampFm = "2006/01/02 15:04:05.000000"
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

type shortioMetadata struct {
	Hostname  string
	Path      string
	Referrer  string
	UserAgent string
	IP        string
	Title     string
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
	shortioAPIKey    string
	shortioMu        sync.Mutex
	shortioDomains   map[string]shortioDomainInfo
	shortioDomainsAt time.Time
	mu               sync.Mutex
	events           []Event
	tmplLogin        *template.Template
	tmplDash         *template.Template
}

func main() {
	setupPersistentLogging()
	cfg := mustNewApp()
	go cfg.logShortioDiagnostics(cfg.settingsSnapshot().ShortioAPIKey)

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
		shortioAPIKey:    settingOrEnvAny(storedSettings, "shortio_api_key", "SHORTIO_API_KEY"),
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
			log.Printf("event=login_failed remote=%q ua=%q", r.RemoteAddr, r.UserAgent())
			w.WriteHeader(http.StatusUnauthorized)
			_ = a.tmplLogin.Execute(w, map[string]any{"Error": "Incorrect password."})
			return
		}
		log.Printf("event=login_success remote=%q", r.RemoteAddr)
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

	forwarded := 0
	errored := 0
	for _, e := range events {
		if e.Forwarded {
			forwarded++
		} else {
			errored++
		}
	}

	settings := a.settingsSnapshot()
	_ = a.tmplDash.Execute(w, map[string]any{
		"Events":            events,
		"Mappings":          mappings,
		"UmamiEndpoint":     settings.Endpoint,
		"UmamiAPIKey":       settings.APIKey,
		"DefaultPropertyID": settings.DefaultPropertyID,
		"ShortioAPIKey":     settings.ShortioAPIKey,
		"Forwarded":         forwarded,
		"Errors":            errored,
		"TotalEvents":       len(events),
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
		log.Printf("event=mapping_upsert_failed domain=%q error=%q", domain, err)
		redirectWithError(w, r, "save failed: "+err.Error())
		return
	}
	log.Printf("event=mapping_upserted domain=%q property_id=%q", domain, propertyID)
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
		log.Printf("event=mapping_delete_failed domain=%q error=%q", domain, err)
		redirectWithError(w, r, "delete failed: "+err.Error())
		return
	}
	log.Printf("event=mapping_deleted domain=%q", domain)
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
	shortioAPIKey := strings.TrimSpace(r.FormValue("shortio_api_key"))

	if err := a.saveSettings(r.Context(), endpoint, apiKey, defaultPropertyID, shortioAPIKey); err != nil {
		log.Printf("event=settings_save_failed error=%q", err)
		redirectWithError(w, r, "save failed: "+err.Error())
		return
	}

	a.setSettings(endpoint, apiKey, defaultPropertyID, shortioAPIKey)
	log.Printf("event=settings_saved endpoint=%q api_key_set=%t default_property_id=%q shortio_api_key_set=%t", endpoint, apiKey != "", defaultPropertyID, shortioAPIKey != "")
	go a.logShortioDiagnostics(shortioAPIKey)
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
	ShortioAPIKey     string
}

func (a *app) settingsSnapshot() runtimeSettings {
	a.settingsMu.RLock()
	defer a.settingsMu.RUnlock()
	return runtimeSettings{
		Endpoint:          a.umamiEndpoint,
		APIKey:            a.umamiAPIKey,
		DefaultPropertyID: a.umamiDefaultProp,
		ShortioAPIKey:     a.shortioAPIKey,
	}
}

func (a *app) setSettings(endpoint, apiKey, defaultPropertyID, shortioAPIKey string) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	a.umamiEndpoint = normalizeUmamiEndpoint(endpoint)
	a.umamiAPIKey = apiKey
	a.umamiDefaultProp = defaultPropertyID
	a.shortioAPIKey = shortioAPIKey
}

func (a *app) saveSettings(ctx context.Context, endpoint, apiKey, defaultPropertyID, shortioAPIKey string) error {
	endpoint = normalizeUmamiEndpoint(endpoint)
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := a.db.ExecContext(queryCtx, `
		INSERT INTO app_settings (key, value, updated_at)
		VALUES
			('umami_endpoint', $1, now()),
			('umami_api_key', $2, now()),
			('umami_website_id', $3, now()),
			('shortio_api_key', $4, now())
		ON CONFLICT (key)
		DO UPDATE SET value = EXCLUDED.value, updated_at = now()
	`, endpoint, apiKey, defaultPropertyID, shortioAPIKey)
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
	payload := []byte(event.Payload)
	if !json.Valid(payload) {
		if quoted, err := json.Marshal(string(payload)); err == nil {
			payload = quoted
		} else {
			payload = []byte("\"\"")
		}
	}
	_, err := db.ExecContext(queryCtx, `
		INSERT INTO event_history (received_at, source, domain, property_id, payload, forwarded, forward_error)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
	`, event.ReceivedAt, event.Source, event.Domain, event.PropertyID, payload, event.Forwarded, event.ForwardError)
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
	payload, payloadFormat, parseErr := parseShortioWebhookPayload(body, r.Header.Get("Content-Type"))
	if parseErr != nil {
		log.Printf("event=shortio_payload_parse_failed path=%q content_type=%q raw_body=%q error=%q", r.URL.Path, r.Header.Get("Content-Type"), truncateForLog(body, 512), parseErr)
	}
	payloadDomain := extractDomain(payload)
	propertyID, resolvedFrom, resolveErr := a.resolvePropertyID(r.Context(), routeKey, payloadDomain, settings.DefaultPropertyID)
	domainForEvent := routeKey
	if domainForEvent == "" {
		domainForEvent = payloadDomain
	}
	event := Event{ReceivedAt: time.Now().UTC(), Source: "shortio", Domain: domainForEvent, PropertyID: propertyID, Payload: payload}
	log.Printf("event=webhook_resolved source=shortio format=%s path=%q route_key=%q payload_domain=%q resolved_from=%s property_id=%q resolve_err=%q", payloadFormat, r.URL.Path, routeKey, payloadDomain, resolvedFrom, propertyID, errString(resolveErr))
	if resolveErr != nil {
		event.Forwarded = false
		event.ForwardError = resolveErr.Error()
		if err := persistEvent(r.Context(), a.db, event); err != nil {
			log.Printf("failed to persist event: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "forwarded": false, "error": event.ForwardError, "domain": domainForEvent, "property_id": propertyID})
		return
	}

	// Enrichment can wait on Short.io's statistics pipeline, so respond to the
	// webhook immediately and finish forwarding in the background.
	rc := requestContext{Host: r.Host, UserAgent: r.UserAgent(), AcceptLanguage: strings.TrimSpace(r.Header.Get("Accept-Language"))}
	go a.processShortioEvent(event, rc, resolvedFrom, settings)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "accepted": true, "domain": domainForEvent, "property_id": propertyID})
}

// requestContext carries the webhook request values needed after the handler
// returns, since *http.Request must not be used from background goroutines.
type requestContext struct {
	Host           string
	UserAgent      string
	AcceptLanguage string
}

func (a *app) processShortioEvent(event Event, rc requestContext, resolvedFrom string, settings runtimeSettings) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	if settings.ShortioAPIKey != "" {
		event.Payload = a.enrichShortioPayload(ctx, settings.ShortioAPIKey, event.Domain, event.Payload)
	}

	event.Forwarded, event.ForwardError = a.forwardToUmami(rc, event.Payload, event.Domain, event.PropertyID, resolvedFrom, settings.Endpoint, settings.APIKey)
	if event.Forwarded {
		log.Printf("event=webhook_forwarded source=shortio domain=%q property_id=%q resolved_from=%s", event.Domain, event.PropertyID, resolvedFrom)
	} else {
		log.Printf("event=webhook_forward_failed source=shortio domain=%q property_id=%q resolved_from=%s error=%q", event.Domain, event.PropertyID, resolvedFrom, event.ForwardError)
	}
	if err := persistEvent(ctx, a.db, event); err != nil {
		log.Printf("failed to persist event: %v", err)
	}
}
func parseShortioWebhookPayload(body []byte, contentType string) (json.RawMessage, string, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, "", fmt.Errorf("empty payload")
	}

	var decoded any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err == nil {
		normalized, err := json.Marshal(decoded)
		if err != nil {
			return nil, "", err
		}
		return json.RawMessage(normalized), "json", nil
	} else {
		log.Printf("event=shortio_payload_json_parse_failed content_type=%q raw_body=%q error=%q", contentType, truncateForLog(body, 512), err)
	}

	values, err := url.ParseQuery(trimmed)
	if err == nil && len(values) > 0 {
		normalized := make(map[string]any, len(values))
		for key, vals := range values {
			switch len(vals) {
			case 0:
				normalized[key] = ""
			case 1:
				normalized[key] = vals[0]
			default:
				normalized[key] = vals
			}
		}
		marshaled, marshalErr := json.Marshal(normalized)
		if marshalErr != nil {
			return nil, "", marshalErr
		}
		return json.RawMessage(marshaled), "form", nil
	}

	raw, err := json.Marshal(map[string]any{"raw": trimmed})
	if err != nil {
		return nil, "", fmt.Errorf("unsupported Short.io webhook payload format: %w", err)
	}
	return json.RawMessage(raw), "raw", nil
}

func truncateForLog(body []byte, limit int) string {
	value := strings.TrimSpace(string(body))
	if len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
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

func (a *app) forwardToUmami(rc requestContext, payload json.RawMessage, domain, propertyID, resolvedFrom, endpoint, apiKey string) (bool, string) {
	endpoint = normalizeUmamiEndpoint(endpoint)
	if endpoint == "" {
		return false, "UMAMI_ENDPOINT is not configured"
	}

	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		decoded = nil
	}

	meta := extractShortioMetadata(decoded)

	hostname := meta.Hostname
	if hostname == "" {
		hostname = domain
	}
	if hostname == "" {
		hostname = normalizeDomain(rc.Host)
	}

	requestURL := meta.Path
	if requestURL == "" {
		requestURL = "/"
	}
	if !strings.HasPrefix(requestURL, "/") {
		requestURL = "/" + strings.TrimLeft(requestURL, "/")
	}
	// Short.io sends the destination query string separately; appending it lets
	// Umami pick up utm_* and click IDs from the URL.
	if query := normalizeShortioQuery(extractStringField(decoded, "shortLinkQuery", "short_link_query")); query != "" && !strings.Contains(requestURL, "?") {
		requestURL += "?" + query
	}

	title := meta.Title
	if title == "" {
		title = strings.TrimPrefix(requestURL, "/")
		if title == "" {
			title = hostname
		}
	}

	language := extractStringField(decoded, "language", "accept-language", "accept_language")
	if language == "" {
		language = rc.AcceptLanguage
	}

	screen := normalizeUmamiScreen(extractStringField(decoded, "screen", "screen_resolution", "screenResolution"))

	referrer := meta.Referrer
	visitorIP := meta.IP
	visitorUserAgent := meta.UserAgent
	if visitorUserAgent == "" {
		visitorUserAgent = rc.UserAgent
	}
	if visitorUserAgent == "" {
		visitorUserAgent = "Short-Umami-Sync/1.0"
	}

	// No "name" field: a payload without an event name is recorded as a
	// pageview, which is what populates Views/Visitors on the Umami overview.
	// A named payload becomes a custom event that only shows in the Events tab.
	umamiPayload := map[string]any{
		"hostname": hostname,
		"title":    title,
		"url":      requestURL,
		"website":  propertyID,
	}
	setIfNotEmpty(umamiPayload, "language", language)
	setIfNotEmpty(umamiPayload, "referrer", referrer)
	setIfNotEmpty(umamiPayload, "screen", screen)

	forward := map[string]any{
		"type":    "event",
		"payload": umamiPayload,
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
	req.Header.Set("User-Agent", visitorUserAgent)
	if visitorIP != "" {
		req.Header.Set("X-Forwarded-For", visitorIP)
	}
	if referrer != "" {
		req.Header.Set("Referer", referrer)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	log.Printf("event=umami_forward_request endpoint=%q domain=%q property_id=%q resolved_from=%s user_agent=%q visitor_ip=%q referrer=%q auth=%t body=%s",
		endpoint, domain, propertyID, resolvedFrom, visitorUserAgent, visitorIP, referrer, apiKey != "", string(b))

	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("event=umami_forward_transport_error endpoint=%q domain=%q property_id=%q elapsed_ms=%d error=%q",
			endpoint, domain, propertyID, time.Since(start).Milliseconds(), err.Error())
		return false, err.Error()
	}
	defer resp.Body.Close()
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		log.Printf("event=umami_forward_response_read_error endpoint=%q domain=%q property_id=%q status=%q elapsed_ms=%d error=%q",
			endpoint, domain, propertyID, resp.Status, time.Since(start).Milliseconds(), readErr.Error())
	}
	log.Printf("event=umami_forward_response endpoint=%q domain=%q property_id=%q status=%q elapsed_ms=%d response_content_type=%q body=%s",
		endpoint, domain, propertyID, resp.Status, time.Since(start).Milliseconds(), resp.Header.Get("Content-Type"), strings.TrimSpace(string(respBody)))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Sprintf("umami returned %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	// Umami answers {"beep":"boop"} with 200 OK when its bot detection drops
	// the event, so a 200 alone does not mean the click was recorded.
	if strings.Contains(string(respBody), `"beep"`) {
		log.Printf("event=umami_forward_ignored endpoint=%q domain=%q property_id=%q user_agent=%q reason=bot_user_agent",
			endpoint, domain, propertyID, visitorUserAgent)
		return true, "umami ignored event: bot user agent detected"
	}
	return true, ""
}

// normalizeShortioQuery cleans the shortLinkQuery value Short.io sends with
// click webhooks. Short.io serializes missing values as the literal string
// "null", and parameters with that value (e.g. utm_source=null) are dropped.
func normalizeShortioQuery(raw string) string {
	value := strings.TrimPrefix(strings.TrimSpace(raw), "?")
	if value == "" || value == "null" {
		return ""
	}
	parsed, err := url.ParseQuery(value)
	if err != nil {
		return value
	}
	cleaned := url.Values{}
	for key, vals := range parsed {
		for _, v := range vals {
			if v != "null" {
				cleaned.Add(key, v)
			}
		}
	}
	return cleaned.Encode()
}

// Overridable in tests.
var (
	shortioAPIBase   = "https://api.short.io"
	shortioStatsBase = "https://statistics.short.io/statistics"
)

type shortioDomainInfo struct {
	ID            int64  `json:"id"`
	Hostname      string `json:"hostname"`
	State         string `json:"state"`
	HideVisitorIP bool   `json:"hideVisitorIp"`
}

type shortioLastClick struct {
	DT      string `json:"dt"`
	IP      string `json:"ip"`
	Path    string `json:"path"`
	UA      string `json:"ua"`
	Ref     string `json:"ref"`
	Country string `json:"country"`
	City    string `json:"city"`
}

func fetchShortioDomains(ctx context.Context, apiKey string) ([]shortioDomainInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, shortioAPIBase+"/api/domains", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("short.io returned %s: %s", resp.Status, truncateForLog(body, 256))
	}
	var domains []shortioDomainInfo
	if err := json.Unmarshal(body, &domains); err != nil {
		return nil, fmt.Errorf("decode short.io domains: %w", err)
	}
	return domains, nil
}

// logShortioDiagnostics reports each domain's privacy configuration so the
// logs explain why click IPs (and therefore Umami locations) may be missing.
func (a *app) logShortioDiagnostics(apiKey string) {
	if strings.TrimSpace(apiKey) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	domains, err := fetchShortioDomains(ctx, apiKey)
	if err != nil {
		log.Printf("event=shortio_domains_fetch_failed error=%q", err)
		return
	}
	for _, d := range domains {
		log.Printf("event=shortio_domain hostname=%q id=%d state=%q hide_visitor_ip=%t", d.Hostname, d.ID, d.State, d.HideVisitorIP)
		if d.HideVisitorIP {
			log.Printf("event=shortio_domain_warning hostname=%q warning=%q", d.Hostname,
				"Hide visitor IP is enabled in Short.io; click IPs are unavailable, so Umami cannot derive visitor locations for this domain")
		}
	}
}

func (a *app) shortioDomainInfoFor(ctx context.Context, apiKey, domain string) (*shortioDomainInfo, error) {
	domain = normalizeDomain(domain)
	a.shortioMu.Lock()
	if a.shortioDomains != nil && time.Since(a.shortioDomainsAt) < 10*time.Minute {
		if info, ok := a.shortioDomains[domain]; ok {
			a.shortioMu.Unlock()
			return &info, nil
		}
	}
	a.shortioMu.Unlock()

	domains, err := fetchShortioDomains(ctx, apiKey)
	if err != nil {
		return nil, err
	}
	cache := make(map[string]shortioDomainInfo, len(domains))
	for _, d := range domains {
		cache[normalizeDomain(d.Hostname)] = d
	}
	a.shortioMu.Lock()
	a.shortioDomains = cache
	a.shortioDomainsAt = time.Now()
	a.shortioMu.Unlock()

	if info, ok := cache[domain]; ok {
		return &info, nil
	}
	return nil, fmt.Errorf("domain %q not found in Short.io account", domain)
}

func fetchShortioLastClicks(ctx context.Context, apiKey string, domainID int64) ([]shortioLastClick, error) {
	body, err := json.Marshal(map[string]any{"limit": 25, "period": "today", "tz": "UTC"})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/domain/%d/last_clicks", shortioStatsBase, domainID), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("short.io statistics returned %s: %s", resp.Status, truncateForLog(data, 256))
	}
	return decodeShortioClicks(data)
}

// decodeShortioClicks tolerates the response being either a bare array or an
// object wrapping the array under a common key.
func decodeShortioClicks(data []byte) ([]shortioLastClick, error) {
	var direct []shortioLastClick
	if err := json.Unmarshal(data, &direct); err == nil {
		return direct, nil
	}
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("decode short.io clicks: %w", err)
	}
	for _, key := range []string{"clicks", "data", "rows", "lastClicks", "items"} {
		raw, ok := wrapper[key]
		if !ok {
			continue
		}
		var clicks []shortioLastClick
		if err := json.Unmarshal(raw, &clicks); err == nil {
			return clicks, nil
		}
	}
	return nil, fmt.Errorf("unrecognized short.io last_clicks response shape: %s", truncateForLog(data, 256))
}

// matchShortioClick finds the newest click matching the webhook's path and
// user agent, no older than 15 minutes, so concurrent clicks on other links
// don't cross-contaminate.
func matchShortioClick(clicks []shortioLastClick, path, ua string, now time.Time) *shortioLastClick {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var best *shortioLastClick
	var bestDT time.Time
	for i := range clicks {
		click := &clicks[i]
		clickPath := click.Path
		if clickPath == "" {
			clickPath = "/"
		}
		if !strings.HasPrefix(clickPath, "/") {
			clickPath = "/" + clickPath
		}
		if clickPath != path {
			continue
		}
		if ua != "" && click.UA != "" && click.UA != ua {
			continue
		}
		dt, err := time.Parse(time.RFC3339, click.DT)
		if err != nil {
			continue
		}
		if now.Sub(dt) > 15*time.Minute || dt.Sub(now) > 2*time.Minute {
			continue
		}
		if best == nil || dt.After(bestDT) {
			best = click
			bestDT = dt
		}
	}
	return best
}

// enrichShortioPayload fills in the visitor IP and referrer that Short.io's
// webhook omits by matching the click in the Short.io statistics API. The IP
// is what lets Umami derive the visitor's location.
func (a *app) enrichShortioPayload(ctx context.Context, apiKey, domain string, payload json.RawMessage) json.RawMessage {
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded == nil {
		return payload
	}
	meta := extractShortioMetadata(decoded)
	if meta.IP != "" && meta.Referrer != "" {
		return payload
	}

	info, err := a.shortioDomainInfoFor(ctx, apiKey, domain)
	if err != nil {
		log.Printf("event=shortio_enrich_skipped domain=%q error=%q", domain, err)
		return payload
	}

	var click *shortioLastClick
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return payload
			case <-time.After(3 * time.Second):
			}
		}
		clicks, err := fetchShortioLastClicks(ctx, apiKey, info.ID)
		if err != nil {
			log.Printf("event=shortio_last_clicks_failed domain=%q attempt=%d error=%q", domain, attempt+1, err)
			continue
		}
		if click = matchShortioClick(clicks, meta.Path, meta.UserAgent, time.Now().UTC()); click != nil {
			break
		}
	}
	if click == nil {
		log.Printf("event=shortio_enrich_no_match domain=%q path=%q", domain, meta.Path)
		return payload
	}

	if ip := strings.TrimPrefix(strings.TrimSpace(click.IP), "::ffff:"); meta.IP == "" && ip != "" {
		decoded["ip"] = ip
	}
	if meta.Referrer == "" && click.Ref != "" {
		decoded["referrer"] = click.Ref
	}
	// Stored for dashboard visibility; Umami derives location from the IP.
	if click.Country != "" {
		decoded["country"] = click.Country
	}
	if click.City != "" {
		decoded["city"] = click.City
	}
	enriched, err := json.Marshal(decoded)
	if err != nil {
		return payload
	}
	log.Printf("event=shortio_enriched domain=%q path=%q ip_found=%t referrer_found=%t country=%q", domain, meta.Path, click.IP != "", click.Ref != "", click.Country)
	return json.RawMessage(enriched)
}

func extractShortioMetadata(value any) shortioMetadata {
	var meta shortioMetadata
	if value == nil {
		return meta
	}
	meta.Hostname = extractStringField(value, "origin", "shortDomain", "short_domain", "shortUrlDomain", "short_url_domain", "hostname", "domain")
	meta.Path = extractStringField(value, "path", "slug", "url", "uri")
	meta.Referrer = extractStringField(value, "referrer", "referer")
	meta.UserAgent = extractStringField(value, "user-agent", "user_agent", "userAgent", "agent")
	meta.IP = extractStringField(value, "ip", "host", "visitor_ip", "visitorIp", "remote_addr", "remote")
	meta.Title = extractStringField(value, "title")
	return meta
}

func extractStringField(value any, keys ...string) string {
	switch v := value.(type) {
	case map[string]any:
		for _, key := range keys {
			if raw, ok := lookupAnyKey(v, key); ok {
				if s := stringFromAny(raw); s != "" {
					return s
				}
			}
		}
		// Fall back to nested containers only. Recursing into scalar values
		// here would return an arbitrary string regardless of its key, so we
		// descend exclusively into maps and slices and rely on the keyed
		// lookup above to match the field we actually want.
		for _, raw := range v {
			switch raw.(type) {
			case map[string]any, []any:
				if s := extractStringField(raw, keys...); s != "" {
					return s
				}
			}
		}
	case []any:
		for _, item := range v {
			if s := extractStringField(item, keys...); s != "" {
				return s
			}
		}
	}
	return ""
}

func lookupAnyKey(values map[string]any, key string) (any, bool) {
	if raw, ok := values[key]; ok {
		return raw, true
	}
	normalizedKey := normalizePayloadKey(key)
	for candidate, raw := range values {
		if normalizePayloadKey(candidate) == normalizedKey {
			return raw, true
		}
	}
	return nil, false
}

func normalizePayloadKey(key string) string {
	return strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(key)))
}

func normalizeUmamiScreen(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 11 {
		return ""
	}
	parts := strings.Split(value, "x")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	for _, part := range parts {
		if len(part) > 5 {
			return ""
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return ""
			}
		}
	}
	return value
}

func setIfNotEmpty(values map[string]any, key, value string) {
	if value != "" {
		values[key] = value
	}
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
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

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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
		for _, key := range []string{"domain", "origin", "shortDomain", "short_domain", "shortUrlDomain", "short_url_domain", "shortUrl", "short_url", "hostname", "host"} {
			if raw, ok := lookupAnyKey(v, key); ok {
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
	file, err := os.OpenFile(persistentLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("failed to open persistent log file: %v", err)
		return
	}
	writer := &retainingLogWriter{file: file, path: persistentLogPath, retention: persistentLogRetention}
	log.SetOutput(io.MultiWriter(os.Stdout, writer))
	go writer.runPruner(persistentLogPruneEvery)
}

type retainingLogWriter struct {
	mu        sync.Mutex
	file      *os.File
	path      string
	retention time.Duration
}

func (w *retainingLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Write(p)
}

func (w *retainingLogWriter) runPruner(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if err := w.prune(time.Now().UTC()); err != nil {
			fmt.Fprintf(os.Stdout, "log pruner: %v\n", err)
		}
	}
}

func (w *retainingLogWriter) prune(now time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := os.ReadFile(w.path)
	if err != nil {
		return err
	}

	cutoff := now.Add(-w.retention)
	lines := bytes.Split(data, []byte("\n"))
	keep := make([][]byte, 0, len(lines))
	keeping := false
	for _, line := range lines {
		if keeping {
			keep = append(keep, line)
			continue
		}
		ts, ok := parseLogLineTimestamp(line)
		if !ok {
			continue
		}
		if !ts.Before(cutoff) {
			keeping = true
			keep = append(keep, line)
		}
	}

	rewritten := bytes.Join(keep, []byte("\n"))
	if err := w.file.Truncate(0); err != nil {
		return err
	}
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := w.file.Write(rewritten); err != nil {
		return err
	}
	return w.file.Sync()
}

func parseLogLineTimestamp(line []byte) (time.Time, bool) {
	if len(line) < len(persistentLogTimestampFm) {
		return time.Time{}, false
	}
	ts, err := time.ParseInLocation(persistentLogTimestampFm, string(line[:len(persistentLogTimestampFm)]), time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

const loginTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in · short-umami-sync</title>
  <link rel="preconnect" href="https://storage.braydenmatsko.com" crossorigin>
  <style>
    @font-face { font-family: 'Terminal Land Mono'; src: url('https://storage.braydenmatsko.com/Assets/font/TerminalLandMono-Regular.woff2') format('woff2'); font-weight: 400; font-style: normal; font-display: swap; }
    @font-face { font-family: 'Terminal Land Mono'; src: url('https://storage.braydenmatsko.com/Assets/font/TerminalLandMono-Bold.woff2') format('woff2'); font-weight: 700; font-style: normal; font-display: swap; }
    @font-face { font-family: 'Numans'; src: url('https://storage.braydenmatsko.com/Assets/font/Numans-Regular.ttf') format('truetype'); font-weight: 400; font-style: normal; font-display: swap; }
    @font-face { font-family: 'Numans'; src: url('https://storage.braydenmatsko.com/Assets/font/Numans-Bold.ttf') format('truetype'); font-weight: 700; font-style: normal; font-display: swap; }
    :root {
      --blue: #5954f9; --green: #46ca8d; --red: #fd0044;
      --ink: #0a1e2a; --bg: #f6f7f9; --surface: #ffffff;
      --border: #ebedf1; --border-strong: #dde0e6;
      --muted: #71808a;
      --font-heading: 'Terminal Land Mono', ui-monospace, 'SF Mono', Menlo, monospace;
      --font-sans: 'Numans', 'Helvetica Neue', Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; }
    body {
      min-height: 100vh;
      font-family: var(--font-sans);
      color: var(--ink);
      background: var(--bg);
      display: grid;
      place-items: center;
      padding: 56px 24px;
      position: relative;
    }
    .brand { position: absolute; top: 28px; left: 32px; display: flex; align-items: center; gap: 12px; }
    .brand-mark { width: 28px; height: 34px; flex-shrink: 0; }
    .brand-block { display: grid; gap: 3px; }
    .kicker { margin: 0; color: var(--muted); font-family: var(--font-heading); font-size: 11px; letter-spacing: 0.16em; text-transform: uppercase; font-weight: 700; }
    .brand-title { margin: 0; color: var(--ink); font-family: var(--font-heading); font-size: 18px; letter-spacing: -0.01em; font-weight: 700; }
    .status { position: absolute; top: 32px; right: 32px; display: flex; align-items: center; gap: 8px; color: var(--ink); font-size: 12px; font-family: var(--font-heading); }
    .status-dot { width: 6px; height: 6px; border-radius: 999px; background: var(--green); box-shadow: 0 0 0 3px rgba(70, 202, 141, 0.18); display: inline-block; }
    .card { width: min(100%, 400px); display: grid; gap: 22px; }
    .title { margin: 0; color: var(--ink); font-family: var(--font-heading); font-size: 30px; line-height: 1.1; letter-spacing: -0.02em; font-weight: 700; }
    .subtle { margin: 0; color: var(--muted); line-height: 1.55; font-size: 14px; }
    .field { display: grid; gap: 7px; }
    .field label { color: var(--muted); font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; font-family: var(--font-heading); }
    .input { width: 100%; min-height: 40px; padding: 9px 13px; border-radius: 10px; border: 1px solid var(--border-strong); background: var(--surface); color: var(--ink); font: inherit; font-size: 13.5px; outline: none; transition: border-color .15s, box-shadow .15s; }
    .input:focus { border-color: var(--ink); box-shadow: 0 0 0 3px rgba(10, 30, 42, 0.08); }
    .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; min-height: 44px; padding: 0 14px; border-radius: 10px; border: 1px solid var(--ink); background: var(--ink); color: #fff; font: inherit; font-size: 13px; font-weight: 600; cursor: pointer; width: 100%; transition: background .15s, border-color .15s; }
    .btn:hover { background: #1a2f3c; border-color: #1a2f3c; }
    .tiny { font-size: 12px; color: var(--muted); line-height: 1.5; margin: 0; }
    .mono { font-family: var(--font-heading); }
    .code { font-family: var(--font-heading); font-size: 11.5px; padding: .15rem .4rem; border-radius: 5px; background: rgba(10, 30, 42, 0.05); color: var(--ink); font-weight: 600; }
    .notice { padding: 10px 12px; border-radius: 10px; font-size: 12.5px; font-weight: 500; display: flex; align-items: center; gap: 10px; border: 1px solid #f7dbe2; background: #fff5f7; color: #b3003a; }
    .notice .dot { width: 6px; height: 6px; border-radius: 999px; background: currentColor; }
    .footer { position: absolute; bottom: 28px; left: 0; right: 0; text-align: center; display: flex; justify-content: center; gap: 12px; padding: 0 24px; }
  </style>
</head>
<body>
  <div class="brand">
    <svg class="brand-mark" viewBox="0 0 90 110" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <rect width="90" height="110" rx="20" fill="#f7f8fa"/>
      <path fill-rule="evenodd" clip-rule="evenodd" d="M10 6C10 8.20914 11.7909 10 14 10H48.3438C49.4044 10.0002 50.4219 10.4219 51.1719 11.1719L68.8281 28.8281C69.5781 29.5781 69.9998 30.5956 70 31.6562V46C70 48.2091 71.7909 50 74 50H86C88.2091 50 90 51.7909 90 54V90C90 101.046 81.0457 110 70 110H14C11.7909 110 10 108.209 10 106V94C10 91.7909 8.20914 90 6 90H4C1.79086 90 1.12747e-07 88.2091 0 86V34C0 31.7909 1.79086 30 4 30H6C8.20914 30 10 28.2091 10 26V14C10 11.7909 8.20914 10 6 10H5C2.23858 10 0 7.76142 0 5C0 2.23858 2.23858 0 5 0C7.76142 0 10 2.23858 10 5V6ZM14 30C11.7909 30 10 31.7909 10 34V86C10 88.2091 11.7909 90 14 90H66C68.2091 90 70 88.2091 70 86V54C70 51.7909 68.2091 50 66 50H54C51.7909 50 50 48.2091 50 46V34C50 31.7909 48.2091 30 46 30H14Z" fill="url(#brand-gradient)"/>
      <defs>
        <linearGradient id="brand-gradient" x1="0" y1="0" x2="100" y2="146" gradientUnits="userSpaceOnUse">
          <stop stop-color="#0E1AFD"/>
          <stop offset="1" stop-color="#E4BFF1"/>
        </linearGradient>
      </defs>
    </svg>
    <div class="brand-block">
      <p class="kicker">ADMIN</p>
      <h1 class="brand-title">Short Umami Sync</h1>
    </div>
  </div>
  <div class="status">
    <span class="status-dot"></span>
    <span class="mono">sync</span>
  </div>
  <main class="card">
    <div>
      <p class="kicker" style="margin-bottom: 14px;">Sign in</p>
      <h1 class="title">Welcome back.</h1>
    </div>
    <p class="subtle">Manage Short.io → Umami forwarding, domain mappings, and the live event feed.</p>
    {{if .Error}}<div class="notice"><span class="dot"></span><span>{{.Error}}</span></div>{{end}}
    <form method="post" action="/login" style="display: grid; gap: 22px;">
      <div class="field">
        <label for="pw">Dashboard password</label>
        <input id="pw" class="input" name="password" type="password" autofocus>
      </div>
      <button class="btn" type="submit">Continue</button>
    </form>
    <p class="tiny">Set via <code class="code">APP_PASSWORD</code>. Session lasts 7 days.</p>
  </main>
  <div class="footer">
    <span class="tiny">A small Go service for Short.io webhooks → Umami events.</span>
  </div>
</body>
</html>`

const dashboardTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dashboard · short-umami-sync</title>
  <link rel="preconnect" href="https://storage.braydenmatsko.com" crossorigin>
  <style>
    @font-face { font-family: 'Terminal Land Mono'; src: url('https://storage.braydenmatsko.com/Assets/font/TerminalLandMono-Regular.woff2') format('woff2'); font-weight: 400; font-style: normal; font-display: swap; }
    @font-face { font-family: 'Terminal Land Mono'; src: url('https://storage.braydenmatsko.com/Assets/font/TerminalLandMono-Bold.woff2') format('woff2'); font-weight: 700; font-style: normal; font-display: swap; }
    @font-face { font-family: 'Numans'; src: url('https://storage.braydenmatsko.com/Assets/font/Numans-Regular.ttf') format('truetype'); font-weight: 400; font-style: normal; font-display: swap; }
    @font-face { font-family: 'Numans'; src: url('https://storage.braydenmatsko.com/Assets/font/Numans-Bold.ttf') format('truetype'); font-weight: 700; font-style: normal; font-display: swap; }

    :root {
      --blue: #5954f9; --green: #46ca8d; --red: #fd0044;
      --ink: #0a1e2a; --bg: #f6f7f9; --surface: #ffffff;
      --border: #ebedf1; --border-strong: #dde0e6;
      --muted: #71808a;
      --radius-md: 14px; --radius-lg: 18px;
      --font-heading: 'Terminal Land Mono', ui-monospace, 'SF Mono', Menlo, monospace;
      --font-sans: 'Numans', 'Helvetica Neue', Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; }
    body { font-family: var(--font-sans); color: var(--ink); background: var(--bg); min-height: 100vh; }
    a { color: inherit; text-decoration: none; }
    .shell { padding: 28px 36px 36px; max-width: 1440px; margin: 0 auto; }
    @media (max-width: 720px) { .shell { padding: 20px 16px 32px; } }

    .kicker { margin: 0; color: var(--muted); font-family: var(--font-heading); font-size: 11px; letter-spacing: 0.16em; text-transform: uppercase; font-weight: 700; }
    .eyebrow { margin: 0 0 14px; font-family: var(--font-heading); font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.12em; color: var(--muted); font-weight: 700; }
    .title { margin: 0; color: var(--ink); font-family: var(--font-heading); font-size: 44px; line-height: 1.05; letter-spacing: -0.02em; font-weight: 700; }
    @media (max-width: 720px) { .title { font-size: 32px; } }
    .brand-title { margin: 0; color: var(--ink); font-family: var(--font-heading); font-size: 22px; line-height: 1.1; letter-spacing: -0.01em; font-weight: 700; }
    .h2 { margin: 0; color: var(--ink); font-family: var(--font-heading); font-size: 14px; font-weight: 700; }
    .subtle { margin: 0; color: var(--muted); line-height: 1.55; font-size: 14px; }
    .tiny { font-size: 12px; color: var(--muted); line-height: 1.5; margin: 0; }
    .mono { font-family: var(--font-heading); }

    .topbar { display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 36px; flex-wrap: wrap; }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-mark { width: 28px; height: 34px; flex-shrink: 0; }
    .brand-block { display: grid; gap: 3px; }
    .topbar-right { display: flex; gap: 18px; align-items: center; flex-wrap: wrap; }
    .status { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted); }
    .status-dot { width: 6px; height: 6px; border-radius: 999px; background: var(--green); box-shadow: 0 0 0 3px rgba(70, 202, 141, 0.18); display: inline-block; }

    .tabs { display: inline-flex; gap: 2px; }
    .tab { display: inline-flex; align-items: center; gap: 8px; padding: 8px 14px; border-radius: 999px; font-size: 13px; font-weight: 600; color: var(--muted); cursor: pointer; border: 0; background: transparent; font-family: inherit; text-decoration: none; transition: background .15s, color .15s; }
    .tab:hover { color: var(--ink); }
    .tab.active { background: var(--ink); color: #fff; }
    .tab .count { font-family: var(--font-heading); font-size: 10.5px; padding: 1px 6px; border-radius: 999px; background: rgba(10, 30, 42, 0.08); color: var(--muted); }
    .tab.active .count { background: rgba(255, 255, 255, 0.2); color: inherit; }

    .hero { margin-bottom: 36px; display: grid; grid-template-columns: minmax(0, 1.4fr) auto; gap: 36px; align-items: end; }
    @media (max-width: 880px) { .hero { grid-template-columns: 1fr; gap: 18px; } }
    .stats { display: flex; gap: 28px; align-items: baseline; flex-wrap: wrap; }
    .stat-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; font-family: var(--font-heading); }
    .stat-value { font-family: var(--font-heading); font-size: 28px; color: var(--ink); font-weight: 700; margin-top: 4px; }
    .stat-value.danger { color: var(--red); }

    .grid { display: grid; grid-template-columns: minmax(0, 380px) minmax(0, 1fr); gap: 24px; }
    @media (max-width: 1024px) { .grid { grid-template-columns: 1fr; } }
    .col { display: grid; gap: 24px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 22px; }
    .section-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 18px; flex-wrap: wrap; }

    .field { display: grid; gap: 7px; }
    .field label { color: var(--muted); font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; font-family: var(--font-heading); }
    .input { width: 100%; min-height: 40px; padding: 9px 13px; border-radius: 10px; border: 1px solid var(--border-strong); background: var(--surface); color: var(--ink); font: inherit; font-size: 13.5px; outline: none; transition: border-color .15s, box-shadow .15s; }
    .input:focus { border-color: var(--ink); box-shadow: 0 0 0 3px rgba(10, 30, 42, 0.08); }
    .hint { font-size: 11.5px; color: var(--muted); }

    .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; min-height: 38px; padding: 0 14px; border-radius: 10px; border: 1px solid transparent; font-family: inherit; font-size: 13px; font-weight: 600; cursor: pointer; white-space: nowrap; transition: background .15s, border-color .15s, color .15s; text-decoration: none; }
    .btn.primary { background: var(--ink); color: #fff; border-color: var(--ink); }
    .btn.primary:hover { background: #1a2f3c; border-color: #1a2f3c; }
    .btn.secondary { background: var(--surface); border-color: var(--border-strong); color: var(--ink); }
    .btn.secondary:hover { border-color: var(--ink); }
    .btn.ghost { background: transparent; border-color: transparent; color: var(--ink); }
    .btn.ghost:hover { background: rgba(10, 30, 42, 0.05); }
    .btn.danger { background: transparent; border: 1px solid var(--border-strong); color: var(--red); }
    .btn.danger:hover { border-color: var(--red); background: rgba(253, 0, 68, 0.04); }

    .notice { padding: 10px 12px; border-radius: 10px; font-size: 12.5px; font-weight: 500; display: flex; align-items: center; gap: 10px; border: 1px solid var(--border); margin-bottom: 18px; }
    .notice.success { background: #f1faf4; color: #1a6a45; border-color: #d5ecdf; }
    .notice.error { background: #fff5f7; color: #b3003a; border-color: #f7dbe2; }
    .notice .dot { width: 6px; height: 6px; border-radius: 999px; background: currentColor; }

    .badge { display: inline-flex; align-items: center; gap: 6px; padding: 3px 8px; border-radius: 999px; font-family: var(--font-heading); font-size: 10px; letter-spacing: 0.08em; text-transform: uppercase; font-weight: 700; background: transparent; border: 1px solid var(--border); color: var(--muted); }
    .badge.green { color: #1a6a45; border-color: rgba(70, 202, 141, 0.4); }
    .badge.red { color: var(--red); border-color: rgba(253, 0, 68, 0.25); }
    .badge.blue { color: var(--blue); border-color: rgba(89, 84, 249, 0.25); }
    .badge .dot { width: 5px; height: 5px; border-radius: 999px; background: currentColor; }

    .payload { margin: 0; padding: 14px 16px; border-radius: 12px; background: #f8f9fb; color: var(--ink); font-family: var(--font-heading); font-size: 11.5px; line-height: 1.7; overflow: auto; white-space: pre-wrap; word-break: break-word; border: 1px solid var(--border); }
    .code { font-family: var(--font-heading); font-size: 11.5px; padding: .15rem .4rem; border-radius: 5px; background: rgba(10, 30, 42, 0.05); color: var(--ink); font-weight: 600; }

    .mapping { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 18px; align-items: center; padding: 18px 0; border-top: 1px solid var(--border); }
    .mapping:first-of-type { border-top: 0; padding-top: 4px; }
    .mapping .left { min-width: 0; }
    .mapping .domain { font-family: var(--font-heading); font-size: 14px; color: var(--ink); font-weight: 700; }
    .mapping .webhook { font-family: var(--font-heading); font-size: 11.5px; color: var(--muted); margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .mapping .property { font-family: var(--font-heading); font-size: 11.5px; color: var(--ink); margin-top: 6px; word-break: break-all; }
    .mapping .right { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    @media (max-width: 720px) { .mapping { grid-template-columns: 1fr; } .mapping .right { justify-content: flex-start; } }

    .event { padding: 14px 0; border-top: 1px solid var(--border); }
    .event:first-of-type { border-top: 0; padding-top: 6px; }
    .event-head { display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; }
    .event-meta { display: flex; align-items: center; gap: 14px; min-width: 0; flex-wrap: wrap; }
    .event-time { font-family: var(--font-heading); font-size: 12px; color: var(--muted); min-width: 64px; }
    .event-domain { font-family: var(--font-heading); font-size: 13px; color: var(--ink); font-weight: 700; }
    .event-property { font-family: var(--font-heading); font-size: 12px; color: var(--blue); word-break: break-all; }
    .event-error { margin-top: 8px; font-size: 12px; color: var(--red); }
    .event-payload { margin-top: 10px; }
    details > summary { cursor: pointer; font-size: 11px; color: var(--muted); font-family: var(--font-heading); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 700; }
    details[open] > summary { margin-bottom: 8px; }

    .add-form { display: grid; gap: 14px; padding-bottom: 22px; border-bottom: 1px solid var(--border); margin-bottom: 4px; }
    .add-form-row { display: grid; gap: 14px; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }
    @media (max-width: 720px) { .add-form-row { grid-template-columns: 1fr; } }
    .end { display: flex; justify-content: flex-end; }
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
    function formatTime(value) {
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return escapeHtml(value);
      return new Intl.DateTimeFormat([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(date);
    }
    function renderEvent(event) {
      const domain = event.domain || '—';
      const propertyID = event.property_id || '—';
      const badge = event.forwarded
        ? '<span class="badge green"><span class="dot"></span>forwarded</span>'
        : '<span class="badge red"><span class="dot"></span>failed</span>';
      const error = event.forward_error ? '<div class="event-error">' + escapeHtml(event.forward_error) + '</div>' : '';
      const payload = '<details class="event-payload"><summary>Payload</summary><pre class="payload">' + escapeHtml(JSON.stringify(event.payload ?? null, null, 2)) + '</pre></details>';
      return '' +
        '<div class="event">' +
          '<div class="event-head">' +
            '<div class="event-meta">' +
              '<span class="event-time">' + formatTime(event.received_at) + '</span>' +
              '<span class="event-domain">' + escapeHtml(domain) + '</span>' +
              '<span class="event-property">' + escapeHtml(propertyID) + '</span>' +
            '</div>' +
            badge +
          '</div>' +
          error +
          payload +
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
          container.innerHTML = '<p class="tiny">No events received yet.</p>';
          return;
        }
        container.innerHTML = events.map(renderEvent).join('');
      } catch (error) {}
    }
    async function copyWebhook(domain, button) {
      const url = window.location.origin.replace(/\/$/, "") + '/webhooks/shortio/' + encodeURIComponent(domain);
      try {
        await navigator.clipboard.writeText(url);
        const previous = button.textContent;
        button.textContent = 'Copied';
        setTimeout(() => { button.textContent = previous; }, 1200);
      } catch (error) {
        button.textContent = 'Copy failed';
        setTimeout(() => { button.textContent = 'Copy'; }, 1200);
      }
    }
    window.addEventListener('DOMContentLoaded', refreshEvents);
  </script>
</head>
<body>
  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <svg class="brand-mark" viewBox="0 0 90 110" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <rect width="90" height="110" rx="20" fill="#f7f8fa"/>
          <path fill-rule="evenodd" clip-rule="evenodd" d="M10 6C10 8.20914 11.7909 10 14 10H48.3438C49.4044 10.0002 50.4219 10.4219 51.1719 11.1719L68.8281 28.8281C69.5781 29.5781 69.9998 30.5956 70 31.6562V46C70 48.2091 71.7909 50 74 50H86C88.2091 50 90 51.7909 90 54V90C90 101.046 81.0457 110 70 110H14C11.7909 110 10 108.209 10 106V94C10 91.7909 8.20914 90 6 90H4C1.79086 90 1.12747e-07 88.2091 0 86V34C0 31.7909 1.79086 30 4 30H6C8.20914 30 10 28.2091 10 26V14C10 11.7909 8.20914 10 6 10H5C2.23858 10 0 7.76142 0 5C0 2.23858 2.23858 0 5 0C7.76142 0 10 2.23858 10 5V6ZM14 30C11.7909 30 10 31.7909 10 34V86C10 88.2091 11.7909 90 14 90H66C68.2091 90 70 88.2091 70 86V54C70 51.7909 68.2091 50 66 50H54C51.7909 50 50 48.2091 50 46V34C50 31.7909 48.2091 30 46 30H14Z" fill="url(#brand-gradient)"/>
          <defs>
            <linearGradient id="brand-gradient" x1="0" y1="0" x2="100" y2="146" gradientUnits="userSpaceOnUse">
              <stop stop-color="#0E1AFD"/>
              <stop offset="1" stop-color="#E4BFF1"/>
            </linearGradient>
          </defs>
        </svg>
        <div class="brand-block">
          <p class="kicker">SHORT × UMAMI SYNC</p>
          <h1 class="brand-title">Dashboard</h1>
        </div>
      </div>
      <div class="topbar-right">
        <nav class="tabs">
          <a href="#overview" class="tab active">Overview</a>
          <a href="#mappings" class="tab">Mappings <span class="count">{{len .Mappings}}</span></a>
          <a href="#events" class="tab">Events <span class="count">{{len .Events}}</span></a>
          <a href="#settings" class="tab">Settings</a>
        </nav>
        <span class="status"><span class="status-dot"></span>all systems normal</span>
        <a class="btn ghost" href="/logout">Log out</a>
      </div>
    </header>

    {{if .Message}}<div class="notice success"><span class="dot"></span><span>{{.Message}}</span></div>{{end}}
    {{if .Error}}<div class="notice error"><span class="dot"></span><span>{{.Error}}</span></div>{{end}}

    <section class="hero" id="overview">
      <div>
        <p class="kicker" style="margin-bottom: 14px;">Forwarding · recent activity</p>
        <h1 class="title">
          {{.Forwarded}} click{{if ne .Forwarded 1}}s{{end}} routed<br>to Umami.
        </h1>
        <p class="subtle" style="margin-top: 14px; max-width: 56ch;">
          Each Short.io domain has its own webhook URL. Clicks are normalized and forwarded to the configured Umami site.
        </p>
      </div>
      <div class="stats">
        <div>
          <div class="stat-label">Forwarded</div>
          <div class="stat-value">{{.Forwarded}}</div>
        </div>
        <div>
          <div class="stat-label">Errors</div>
          <div class="stat-value{{if gt .Errors 0}} danger{{end}}">{{.Errors}}</div>
        </div>
        <div>
          <div class="stat-label">Recent</div>
          <div class="stat-value">{{.TotalEvents}}</div>
        </div>
      </div>
    </section>

    <div class="grid">
      <div class="col">
        <section class="card" id="settings">
          <div class="section-head">
            <div>
              <p class="eyebrow" style="margin-bottom: 6px;">Forwarding</p>
              <h2 class="h2">Umami destination</h2>
            </div>
          </div>
          <form method="post" action="/dashboard/settings" style="display: grid; gap: 14px;">
            <div class="field">
              <label for="umami_endpoint">Endpoint</label>
              <input id="umami_endpoint" class="input" name="umami_endpoint" value="{{.UmamiEndpoint}}" placeholder="https://stats.example.com/api/send">
              <span class="hint">A path is allowed; https:// is added if you omit it.</span>
            </div>
            <div class="field">
              <label for="umami_api_key">API token</label>
              <input id="umami_api_key" class="input" name="umami_api_key" value="{{.UmamiAPIKey}}" placeholder="optional bearer token">
            </div>
            <div class="field">
              <label for="umami_website_id">Fallback site ID</label>
              <input id="umami_website_id" class="input" name="umami_website_id" value="{{.DefaultPropertyID}}" placeholder="site uuid">
              <span class="hint">Used when a domain isn't mapped.</span>
            </div>
            <div class="field">
              <label for="shortio_api_key">Short.io API key</label>
              <input id="shortio_api_key" class="input" name="shortio_api_key" value="{{.ShortioAPIKey}}" placeholder="sk_...">
              <span class="hint">Enables click enrichment (visitor IP, referrer) from the Short.io statistics API.</span>
            </div>
            <div class="end" style="margin-top: 4px;">
              <button class="btn primary" type="submit">Save</button>
            </div>
          </form>
        </section>

        <section class="card">
          <p class="eyebrow" style="margin-bottom: 6px;">Reference</p>
          <h2 class="h2" style="margin-bottom: 12px;">Webhook recipe</h2>
          <pre class="payload">POST  /webhooks/shortio/{domain}

{
  "origin":     "example.com",
  "path":       "/launch",
  "referrer":   "...",
  "user-agent": "..."
}</pre>
        </section>
      </div>

      <div class="col">
        <section class="card" id="mappings">
          <div class="section-head">
            <div>
              <p class="eyebrow" style="margin-bottom: 6px;">Routing · {{len .Mappings}} active</p>
              <h2 class="h2">Domain → Umami site</h2>
            </div>
          </div>

          <form class="add-form" method="post" action="/dashboard/mappings">
            <div class="add-form-row">
              <div class="field">
                <label for="new-domain">Short.io domain</label>
                <input id="new-domain" class="input" name="domain" placeholder="example.short.gy">
              </div>
              <div class="field">
                <label for="new-property">Umami site ID</label>
                <input id="new-property" class="input" name="property_id" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
              </div>
            </div>
            <div class="end">
              <button class="btn primary" type="submit">Add mapping</button>
            </div>
          </form>

          {{if .Mappings}}
            {{range .Mappings}}
              <div class="mapping">
                <div class="left">
                  <div class="domain">{{.Domain}}</div>
                  <div class="webhook">/webhooks/shortio/{{.Domain}}</div>
                  <div class="property">{{.PropertyID}}</div>
                </div>
                <div class="right">
                  <button class="btn ghost" type="button" onclick="copyWebhook('{{.Domain}}', this)">Copy</button>
                  <form method="post" action="/dashboard/mappings/delete" style="display: inline-flex;">
                    <input type="hidden" name="domain" value="{{.Domain}}">
                    <button class="btn danger" type="submit" aria-label="delete mapping">Delete</button>
                  </form>
                </div>
              </div>
            {{end}}
          {{else}}
            <p class="tiny" style="padding: 16px 0;">No mappings yet — add one above and paste the webhook URL into Short.io.</p>
          {{end}}
        </section>

        <section class="card" id="events">
          <div class="section-head">
            <div>
              <p class="eyebrow" style="margin-bottom: 6px;">Activity · last {{.TotalEvents}} event{{if ne .TotalEvents 1}}s{{end}}</p>
              <h2 class="h2">Recent events</h2>
            </div>
            <span class="status"><span class="status-dot"></span>streaming</span>
          </div>
          <div id="events-list">
            {{if .Events}}
              {{range .Events}}
                <div class="event">
                  <div class="event-head">
                    <div class="event-meta">
                      <span class="event-time">{{.ReceivedAt.Format "15:04:05"}}</span>
                      <span class="event-domain">{{if .Domain}}{{.Domain}}{{else}}—{{end}}</span>
                      <span class="event-property">{{if .PropertyID}}{{.PropertyID}}{{else}}—{{end}}</span>
                    </div>
                    {{if .Forwarded}}
                      <span class="badge green"><span class="dot"></span>forwarded</span>
                    {{else}}
                      <span class="badge red"><span class="dot"></span>failed</span>
                    {{end}}
                  </div>
                  {{if .ForwardError}}<div class="event-error">{{.ForwardError}}</div>{{end}}
                  <details class="event-payload"><summary>Payload</summary><pre class="payload">{{printf "%s" .Payload}}</pre></details>
                </div>
              {{end}}
            {{else}}
              <p class="tiny">No events received yet.</p>
            {{end}}
          </div>
        </section>
      </div>
    </div>
  </main>
</body>
</html>`

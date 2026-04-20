package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Event struct {
	ReceivedAt   time.Time       `json:"received_at"`
	Source       string          `json:"source"`
	Payload      json.RawMessage `json:"payload"`
	Forwarded    bool            `json:"forwarded"`
	ForwardError string          `json:"forward_error,omitempty"`
}

type app struct {
	password      string
	sessionSecret string
	umamiEndpoint string
	umamiAPIKey   string
	umamiWebsite  string
	mu            sync.Mutex
	events        []Event
	tmplLogin     *template.Template
	tmplDash      *template.Template
}

func main() {
	cfg := newApp()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/login", cfg.loginHandler)
	mux.HandleFunc("/logout", cfg.logoutHandler)
	mux.HandleFunc("/dashboard", cfg.requireAuth(cfg.dashboardHandler))
	mux.HandleFunc("/webhooks/shortio", cfg.shortioWebhookHandler)
	mux.HandleFunc("/", cfg.rootHandler)

	addr := ":" + envOr("PORT", "8080")
	log.Printf("starting short-umami-sync on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func newApp() *app {
	return &app{
		password:      envOr("APP_PASSWORD", "changeme"),
		sessionSecret: mustEnv("SESSION_SECRET"),
		umamiEndpoint: os.Getenv("UMAMI_ENDPOINT"),
		umamiAPIKey:   os.Getenv("UMAMI_API_KEY"),
		umamiWebsite:  os.Getenv("UMAMI_WEBSITE_ID"),
		tmplLogin: template.Must(template.New("login").Parse(loginTemplate)),
		tmplDash:  template.Must(template.New("dashboard").Parse(dashboardTemplate)),
	}
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
	a.mu.Lock()
	defer a.mu.Unlock()
	items := make([]Event, len(a.events))
	copy(items, a.events)
	sort.Slice(items, func(i, j int) bool { return items[i].ReceivedAt.After(items[j].ReceivedAt) })
	_ = a.tmplDash.Execute(w, map[string]any{
		"Events":       items,
		"UmamiEndpoint": a.umamiEndpoint,
		"WebsiteID":     a.umamiWebsite,
	})
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
	payload := json.RawMessage(body)
	event := Event{ReceivedAt: time.Now().UTC(), Source: "shortio", Payload: payload}
	event.Forwarded, event.ForwardError = a.forwardToUmami(r, payload)
	a.mu.Lock()
	a.events = append(a.events, event)
	if len(a.events) > 100 {
		a.events = a.events[len(a.events)-100:]
	}
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "forwarded": event.Forwarded, "error": event.ForwardError})
}

func (a *app) forwardToUmami(r *http.Request, payload json.RawMessage) (bool, string) {
	if a.umamiEndpoint == "" {
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
	if a.umamiWebsite != "" {
		forward["website_id"] = a.umamiWebsite
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
  <p>Sign in to view recent webhook activity.</p>
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
    pre { overflow:auto; padding: 12px; }
    a { color: #0b57d0; }
  </style>
</head>
<body>
  <h1>Short Umami Sync</h1>
  <p><a href="/logout">Log out</a></p>
  <div class="card">
    <h2>Configuration</h2>
    <p class="muted">Umami endpoint: <code>{{.UmamiEndpoint}}</code></p>
    <p class="muted">Umami website ID: <code>{{.WebsiteID}}</code></p>
    <p>Short.io webhook URL: <code>/webhooks/shortio</code></p>
  </div>
  <div class="card">
    <h2>Recent webhook events</h2>
    {{if .Events}}
      {{range .Events}}
        <div class="card">
          <div><strong>{{.Source}}</strong> — {{.ReceivedAt.Format "2006-01-02 15:04:05 MST"}}</div>
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

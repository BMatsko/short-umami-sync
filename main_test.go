package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPersistEventAllowsEmptyDomainAndPropertyID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	defer db.Close()

	receivedAt := time.Date(2026, 5, 13, 1, 2, 3, 0, time.UTC)
	mock.ExpectExec("INSERT INTO event_history").
		WithArgs(receivedAt, "shortio", "", "", sqlmock.AnyArg(), false, "missing mapping").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = persistEvent(context.Background(), db, Event{
		ReceivedAt:   receivedAt,
		Source:       "shortio",
		Payload:      json.RawMessage(`{"event":"click"}`),
		Forwarded:    false,
		ForwardError: "missing mapping",
	})
	if err != nil {
		t.Fatalf("persistEvent() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestParseShortioWebhookPayloadSupportsJSONAndForm(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantFormat string
		wantJSON   string
	}{
		{
			name:       "json object",
			body:       ` {"domain":"sho.rt","path":"abc"} `,
			wantFormat: "json",
			wantJSON:   `{"domain":"sho.rt","path":"abc"}`,
		},
		{
			name:       "url encoded form",
			body:       `domain=sho.rt&path=abc&tag=one&tag=two`,
			wantFormat: "form",
			wantJSON:   `{"domain":"sho.rt","path":"abc","tag":["one","two"]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotFormat, err := parseShortioWebhookPayload([]byte(tt.body), "")
			if err != nil {
				t.Fatalf("parseShortioWebhookPayload() error = %v", err)
			}
			if gotFormat != tt.wantFormat {
				t.Fatalf("format = %q, want %q", gotFormat, tt.wantFormat)
			}
			assertJSONEqual(t, got, []byte(tt.wantJSON))
		})
	}
}

func TestForwardToUmamiBuildsTrackingPayload(t *testing.T) {
	var receivedRequestPath string
	var receivedUserAgent string
	var receivedAuthorization string
	var receivedPayload map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestPath = r.URL.Path
		receivedUserAgent = r.Header.Get("User-Agent")
		receivedAuthorization = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Fatalf("decode forwarded payload: %v", err)
		}
		w.WriteHeader(204)
	}))
	defer server.Close()

	req := httptest.NewRequest("POST", "/webhooks/shortio", nil)
	ok, forwardErr := (&app{}).forwardToUmami(req, json.RawMessage(`{
		"domain":"sho.rt",
		"path":"offer",
		"title":"Spring Offer",
		"userAgent":"ShortioBot/1.0"
	}`), "fallback.example", "website-123", "payload", server.URL+"/api/send", "api-token")
	if !ok || forwardErr != "" {
		t.Fatalf("forwardToUmami() = (%v, %q), want success", ok, forwardErr)
	}
	if receivedRequestPath != "/api/send" {
		t.Fatalf("request path = %q, want /api/send", receivedRequestPath)
	}
	if receivedUserAgent != "ShortioBot/1.0" {
		t.Fatalf("User-Agent = %q, want ShortioBot/1.0", receivedUserAgent)
	}
	if receivedAuthorization != "Bearer api-token" {
		t.Fatalf("Authorization = %q, want bearer token", receivedAuthorization)
	}

	payload, ok := receivedPayload["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %#v, want object", receivedPayload["payload"])
	}
	if receivedPayload["type"] != "event" {
		t.Fatalf("type = %#v, want event", receivedPayload["type"])
	}
	if payload["website"] != "website-123" {
		t.Fatalf("website = %#v, want website-123", payload["website"])
	}
	if payload["hostname"] != "sho.rt" {
		t.Fatalf("hostname = %#v, want sho.rt", payload["hostname"])
	}
	if payload["url"] != "/offer" {
		t.Fatalf("url = %#v, want /offer", payload["url"])
	}
	if payload["title"] != "Spring Offer" {
		t.Fatalf("title = %#v, want Spring Offer", payload["title"])
	}
	if payload["name"] != "shortio-click" {
		t.Fatalf("name = %#v, want shortio-click", payload["name"])
	}
}

func TestForwardToUmamiHandlesShortioWebhookFieldsAndOmitsInvalidScreen(t *testing.T) {
	var receivedPayload map[string]any
	var receivedUserAgent string
	var receivedVisitorIP string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUserAgent = r.Header.Get("User-Agent")
		receivedVisitorIP = r.Header.Get("X-Forwarded-For")
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Fatalf("decode forwarded payload: %v", err)
		}
		w.WriteHeader(204)
	}))
	defer server.Close()

	req := httptest.NewRequest("POST", "/webhooks/shortio", nil)
	ok, forwardErr := (&app{}).forwardToUmami(req, json.RawMessage(`{
		"Origin":"sho.rt",
		"Path":"AbC123",
		"Referrer":"https://example.com/source",
		"User-agent":"Mozilla/5.0 Shortio",
		"Host":"203.0.113.7",
		"screen":"this is too long for umami"
	}`), "fallback.example", "website-123", "payload", server.URL+"/api/send", "")
	if !ok || forwardErr != "" {
		t.Fatalf("forwardToUmami() = (%v, %q), want success", ok, forwardErr)
	}

	payload, ok := receivedPayload["payload"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %#v, want object", receivedPayload["payload"])
	}
	if receivedPayload["type"] != "event" {
		t.Fatalf("type = %#v, want event", receivedPayload["type"])
	}
	if payload["hostname"] != "sho.rt" {
		t.Fatalf("hostname = %#v, want sho.rt", payload["hostname"])
	}
	if payload["url"] != "/AbC123" {
		t.Fatalf("url = %#v, want /AbC123", payload["url"])
	}
	if payload["referrer"] != "https://example.com/source" {
		t.Fatalf("referrer = %#v, want https://example.com/source", payload["referrer"])
	}
	if _, ok := payload["screen"]; ok {
		t.Fatalf("screen = %#v, want omitted when invalid", payload["screen"])
	}
	if receivedUserAgent != "Mozilla/5.0 Shortio" {
		t.Fatalf("User-Agent = %q, want Mozilla/5.0 Shortio", receivedUserAgent)
	}
	if receivedVisitorIP != "203.0.113.7" {
		t.Fatalf("X-Forwarded-For = %q, want 203.0.113.7", receivedVisitorIP)
	}
}

func TestNormalizeUmamiScreen(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "valid", raw: "1920x1080", want: "1920x1080"},
		{name: "trims", raw: " 800x600 ", want: "800x600"},
		{name: "too long", raw: "100000x100000", want: ""},
		{name: "not resolution", raw: "Desktop browser", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeUmamiScreen(tt.raw); got != tt.want {
				t.Fatalf("normalizeUmamiScreen(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var gotDecoded any
	if err := json.Unmarshal(got, &gotDecoded); err != nil {
		t.Fatalf("got invalid JSON: %v", err)
	}
	var wantDecoded any
	if err := json.Unmarshal(want, &wantDecoded); err != nil {
		t.Fatalf("want invalid JSON: %v", err)
	}
	gotCanonical, err := json.Marshal(gotDecoded)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	wantCanonical, err := json.Marshal(wantDecoded)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	if string(gotCanonical) != string(wantCanonical) {
		t.Fatalf("JSON = %s, want %s", gotCanonical, wantCanonical)
	}
}

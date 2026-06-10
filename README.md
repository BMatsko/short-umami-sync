# short-umami-sync

Go backend for accepting Short.io webhooks, showing them in a password-protected dashboard, and forwarding normalized analytics to Umami.

## Environment variables

- `APP_PASSWORD` – dashboard password (defaults to `changeme` if unset)
- `SESSION_SECRET` – cookie signing secret (defaults to a development value if unset)
- `DATABASE_URL` – PostgreSQL connection string used to store domain-to-property mappings
- `UMAMI_ENDPOINT` – Umami tracking API endpoint to POST forwarded events to, typically `https://your-umami.example.com/api/send`
- `UMAMI_API_KEY` – optional bearer token for Umami
- `UMAMI_WEBSITE_ID` – optional fallback Umami property ID used when a domain has no explicit mapping
- `PORT` – server port, defaults to `8080`

## Routes

- `GET /login`
- `POST /login`
- `GET /dashboard`
- `POST /dashboard/mappings`
- `POST /dashboard/mappings/delete`
- `POST /webhooks/shortio`
- `GET /healthz`

## Notes

- Domain-to-property mappings are stored in PostgreSQL and can be managed from the dashboard.
- The dashboard shows recent webhook events in memory for visibility.
- When a webhook arrives, the app resolves the Short.io domain to a mapped Umami property ID and includes that property in the forwarded payload.
- Short.io click webhooks are normalized from JSON or form-encoded payloads. The receiver recognizes Short.io fields such as `Origin`, `Path`, `Referrer`, `User-agent`, and `Host` regardless of case or hyphen/underscore style.
- Umami forwarding uses the current `/api/send` shape with `type: "event"` and no event name, so clicks are recorded as pageviews and appear in the Umami overview (Views/Visitors/Pages). The short link's `shortLinkQuery` is appended to the forwarded URL (minus `null` placeholders) so UTM parameters and click IDs reach Umami.
- Umami silently drops events whose forwarded `User-Agent` looks like a bot (it responds `{"beep":"boop"}`); these are marked with a note in the dashboard instead of being counted as recorded.
- Invalid `screen` values are omitted unless they are resolution strings such as `1920x1080`.

# short-umami-sync

Go backend for accepting Short.io webhooks, showing them in a password-protected dashboard, and forwarding normalized analytics to Umami.

## Environment variables

- `APP_PASSWORD` – dashboard password (defaults to `changeme` if unset)
- `SESSION_SECRET` – cookie signing secret (defaults to a development value if unset)
- `DATABASE_URL` – PostgreSQL connection string used to store domain-to-property mappings
- `UMAMI_ENDPOINT` – Umami tracking API endpoint to POST forwarded events to
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

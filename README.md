# short-umami-sync

Go backend for accepting Short.io webhooks, showing them in a password-protected dashboard, and forwarding normalized analytics to Umami.

## Environment variables

- `APP_PASSWORD` – dashboard password
- `SESSION_SECRET` – cookie signing secret
- `UMAMI_ENDPOINT` – Umami tracking API endpoint to POST forwarded events to
- `UMAMI_API_KEY` – optional bearer token for Umami
- `UMAMI_WEBSITE_ID` – optional website identifier shown in the dashboard and included in forwarded payloads
- `PORT` – server port, defaults to `8080`

## Routes

- `GET /login`
- `POST /login`
- `GET /dashboard`
- `POST /webhooks/shortio`
- `GET /healthz`

## Notes

The dashboard uses a simple signed-cookie session and keeps recent webhook events in memory for visibility during the initial deployment.

# SenateLink

The Express backend serves the public portal and admin pages from one origin and stores application data in MongoDB. This layout supports a no-cost local demonstration; it does not require a paid hosting plan. Do not open HTML files directly from disk because API requests and admin session cookies require the server.

## Layout

```text
my-api/
  server.js                 Express API and static-page server
  setup-admin.js            One-time first-admin setup
  public/
    publicSENATE/           Public website
    admin/                  Admin pages and session guard
  .env                      Local secrets; never commit
  .env.example              Safe configuration template
```

## Free local setup

1. Create a free MongoDB Atlas M0 database, create a database user, and allow your current IP address in Atlas Network Access.
2. Copy `.env.example` to `.env`. Replace the MongoDB URI with the Atlas connection string and URL-encode any special characters in the database user's password. Set a private random `SESSION_SECRET` with at least 32 characters. Keep `.env` private and out of source control.
3. In this directory, run `npm install`.
4. Create the first admin with `npm run setup-admin`. It uses `ADMIN_EMAIL` (or `admin@senatelink.local` by default), refuses to replace an existing admin, and prints the generated password once. Save it in a password manager; it cannot be recovered from the password hash.
5. Start the app with `npm start`.
6. Open `http://localhost:8080/` for the public portal and `http://localhost:8080/admin/` for admin login. Confirm `http://localhost:8080/healthz` returns `{"status":"ok"}`.

Never paste database credentials or admin passwords into source files, commits, or chat. If an admin already exists, use the app's authenticated password-change flow; the setup command will not reset it.

## Complaint demonstration

Submit a complaint through `/publicSENATE/complaints.html`, then sign in at `/admin/` and open Complaints. The public form writes to `POST /api/complaints`; the authenticated admin page reads the same MongoDB collection from `GET /api/complaints`. The admin list refreshes every five seconds and reports new complaints and connection errors. This is near-real-time polling, not an instant push connection, and avoids adding a paid service.

The setup command creates a local `SESSION_SECRET` in `.env` if it is absent. In production, provide `SESSION_SECRET` through the hosting platform instead; use a random value of at least 32 characters and never reuse the development secret.

## Free Render deployment

The root `render.yaml` defines one free Node web service for the API, public site, and admin site. In Render, create a new Blueprint from this repository and select the `senatelink-render` branch. When prompted, provide `MONGO_URI` as a secret using the existing Atlas database; Render generates a separate production `SESSION_SECRET`. Do not add `.env` to GitHub or paste database credentials into source files.

In Atlas Network Access, allow the outbound IP ranges shown for the Render service, and use a dedicated database user with only the required database permissions. Avoid allowing all IP addresses if the service's outbound IP ranges can be allowlisted. Render's free service may sleep when idle, so the first request after inactivity can take longer. The service health check is `/healthz`; the public page is `/publicSENATE/complaints.html`, and the admin login is `/admin/`.

## Production requirements

- Set `NODE_ENV=production`, `MONGO_URI`, `SESSION_SECRET`, and `PORT` in the deployment environment.
- Serve the app only behind HTTPS. The admin session cookie is HttpOnly, SameSite strict, and Secure in production.
- Keep the API and pages on the same origin. If a separate frontend origin is required, set `CORS_ORIGINS` to an explicit comma-separated allowlist.
- When running behind one trusted reverse proxy, set `TRUST_PROXY=1` and configure the proxy to replace, not append to, forwarded client IP headers.
- Configure MongoDB backups, monitoring, and retention in the hosting provider. The admin Backup & Restore screen is intentionally marked unavailable until a real backup service is connected.
- Bursary and proposal documents are stored in MongoDB GridFS and can be downloaded only by an authenticated admin. Each file is limited to 5 MB.

The initial login is a single administrator account. Staff records are managed separately and are not separate login identities; role-based access and password reset/email delivery are not configured. Admin settings are not persisted yet, so the page reports that saving, branding uploads, and maintenance mode are unavailable instead of claiming success.
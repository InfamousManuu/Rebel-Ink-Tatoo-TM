# Rebel Ink Tattoos — Render deployment

## What this package adds
- Persistent MongoDB database for members and appointments.
- Secure password hashing with bcrypt.
- JWT login sessions that work across devices.
- Admin credentials supplied only through Render environment variables.
- Automatic admin bootstrap on first startup.
- Member approval/suspension workflow.
- Appointment request, approval, rejection, completion and cancellation workflow.
- Admin notes and appointment notes saved in the database.
- Client portal refreshes from the server every 10 seconds.
- Admin panel refreshes from the server every 10 seconds.
- CSV export of members and appointment records.
- Rate limiting, Helmet security headers and server-side validation.
- Render health check at `/api/health`.

## Required database
This app requires a persistent MongoDB database. MongoDB Atlas is suitable. Do NOT use an in-memory database or local JSON file on Render.

1. Create a MongoDB Atlas cluster.
2. Create a database user.
3. Add the Render outbound network access as permitted in Atlas (for a quick deployment, Atlas can allow `0.0.0.0/0`; use stronger network restrictions where appropriate).
4. Copy the Atlas connection string.

## Render
Push this folder to GitHub and create a Render Web Service from the repository. Render can also use the included `render.yaml`.

Set these environment variables in Render:

- `MONGODB_URI` = your Atlas connection string
- `DB_NAME` = `rebel_ink`
- `JWT_SECRET` = a long random secret (32+ characters; preferably 64+)
- `ADMIN_EMAIL` = your real admin email
- `ADMIN_PASSWORD` = your real strong admin password (12+ characters)
- `RESET_PASSWORD_KEY` = optional; leave unset unless you deliberately want the existing reset form enabled

There are NO default admin credentials in the frontend. The server creates/updates the admin account from the environment variables when it starts.

## Important security note
Do not commit `.env` or real secrets to GitHub. Only `.env.example` is included.

The existing frontend's password-reset screen is deliberately disabled by default because changing a password based only on an email address is not a safe production recovery mechanism. A proper email verification/reset-token flow should be added before enabling self-service password recovery.

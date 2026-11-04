# Mission Control

Mission Control is a single-page operations dashboard and task-dispatch server for a small fleet of Raspberry Pi machines running OpenClaw agents. A Node.js/Express backend reaches each Pi over SSH to list agents, read and edit scheduled (cron) jobs and dispatch tasks, while the browser UI shows the state in tabs. It was built for a personal home lab, so it assumes that setup.

## Stack

- Node.js 20, Express 4
- `node-ssh` for SSH from the container (or `wsl ssh` when run directly on Windows)
- `uuid`, plain file-based storage (JSON and JSONL under `data/`)
- Vanilla HTML, CSS and JavaScript front end (single `public/index.html`)
- Docker and Docker Compose

## Running

```bash
cp .env.example .env            # set OC_TOKEN
export SSH_USER=<ssh user on the Pis>
export PI1_HOST=<address of pi 1>   # likewise PI2_HOST, PI3_HOST
docker compose up --build
# open http://localhost:8095
```

Without Docker:

```bash
npm install
npm start          # or: npm run dev   (node --watch)
```

### Configuration (environment variables)

- `OC_TOKEN` - OpenClaw gateway token (read from `.env` or the environment)
- `SSH_USER` - SSH user on the Pis
- `SSH_KEY_PATH` - private key path (default `~/.ssh/id_ed25519`; the compose file mounts `~/.ssh` read-only)
- `PI1_HOST`, `PI2_HOST`, `PI3_HOST` - addresses of the three Pis (defaults are `192.0.2.x` documentation placeholders; replace with your own LAN addresses)
- `PORT` - listen port (default 8095)
- `BASE_PATH` - optional URL prefix when served behind a reverse proxy, e.g. `/mc`
- `USE_WSL_SSH` - use `wsl ssh` instead of `node-ssh` (automatic on Windows)

## Features

- **Dashboard** - per-Pi agent status (`/api/agents`)
- **Workshop** - create, update, delete and view logs for tasks (`/api/tasks`)
- **API stats** - usage tracking (`/api/stats`)
- **Cron jobs** - list and toggle scheduled jobs on each Pi (`/api/cron`)
- **Source intel** - collect, triage and queue items (`/api/intelligence`)
- **Logs** - structured server log viewer (`/api/logs`)

## Project layout

- `server.js` - Express app, SSH helpers and all API routes
- `public/index.html` - the whole UI
- `Dockerfile`, `docker-compose.yml` - container build and run

## Status

Personal project; works against the author's own Pi setup and has not been generalised. There are no automated tests and the API has no authentication, so run it only on a trusted network.

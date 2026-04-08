# Web Frontend

This folder contains the standalone Next.js frontend for browsing and operating
the vulnerability mirror API.

## Prerequisites

- Node.js 20+
- Backend API available at `http://127.0.0.1:8787` (or custom port)

## Setup

```bash
cp .env.local.example .env.local
npm install
```

`NEXT_PUBLIC_API_BASE` is read from `.env.local`.

## Run

Frontend only:

```bash
npm run dev
```

Frontend + backend together (from this `web/` directory):

```bash
npm run dev:full
```

Default UI URL: `http://127.0.0.1:3000`

## Build & Lint

```bash
npm run lint
npm run build
```

## Notes

- `dev:full` starts backend via `uv run vulndb-mirror api`.
- If backend port `8787` is occupied, run backend separately with
	`RAWDB_API_PORT=<port>` and update `NEXT_PUBLIC_API_BASE` accordingly.

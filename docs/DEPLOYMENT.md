# Deployment (FS-5)

Two supported ways to run this outside a local dev checkout: Docker, or systemd directly on a
host. Both are thin wrappers around the same `uvicorn vapt_agent.api:app` process the
[README](../README.md) already uses for local development -- nothing deployment-specific changes
about the application itself.

## Option A: Docker

```bash
docker compose up -d --build
```

This builds the image from the repo's `Dockerfile`, binds port 8000, and bind-mounts `./data` into
the container at `/app/data` -- the same directory the app already writes to when run locally, so
backups (below) work the same way whether the process runs in a container or not.

Set `ANTHROPIC_API_KEY` in the environment (or a `.env` file next to `docker-compose.yml`) to
enable LLM-phrased rationale/summaries; it is optional, never required for correctness
(`vapt_agent/llm.py` has a deterministic fallback for every LLM call site).

The image does **not** bundle `nmap`/`nikto`/`msfconsole` -- see the Dockerfile's comment for why.
Without them, live scanning fails cleanly (`ToolRun.status="unavailable"`, recorded as a
limitation in the report) while import-based ingestion, correlation, risk scoring, reporting, and
the UI all work normally. A deployment that genuinely needs live scanning from inside the
container should derive from this image and install those tools in the derived `Dockerfile`.

## Option B: systemd (bare host)

Use this when live scanning needs `nmap`/`nikto`/`msfconsole` installed directly on the host
rather than inside a container.

```bash
sudo useradd --system --create-home --home-dir /opt/vapt-agent vaptagent
sudo -u vaptagent git clone <this repo> /opt/vapt-agent
cd /opt/vapt-agent
sudo -u vaptagent python3 -m venv .venv
sudo -u vaptagent .venv/bin/pip install -r requirements.txt

sudo cp deploy/vapt-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vapt-agent
sudo systemctl status vapt-agent
```

The unit file runs as the dedicated `vaptagent` system account (never root), with
`ProtectSystem=strict` and `ReadWritePaths` scoped to exactly `/opt/vapt-agent/data` -- the one
directory this process needs to write to.

## Option C: Render (judge-facing demo, free tier)

For a quick, publicly reachable URL during the hackathon window, `render.yaml` (Blueprint) at the
repo root drives this:

1. Push the repo to GitHub (already done for this project).
2. In the Render dashboard: **New → Blueprint**, connect the `vapt-agent` repo. Render reads
   `render.yaml` and proposes one `docker` web service on the free plan.
3. Render will prompt for the two secrets marked `sync: false` in `render.yaml` — set them before
   the first deploy:
   - `VAPT_BOOTSTRAP_ADMIN_PASSWORD` — a password of your choosing (12+ characters) for the
     bootstrap `admin` account. Without this, the server falls back to generating a random one and
     printing it once to the service's log (see "First login" below) — fine on a host with a
     persistent disk, but on the free plan's ephemeral disk a *new* random password gets generated
     on every redeploy/sleep-wake cycle, and the only place it's ever shown is a log you (and
     nobody else, e.g. a judge) can read. Pinning it here keeps the login known and working across
     every restart. The account still forces a password change at first login either way.
   - `ANTHROPIC_API_KEY` — optional, enables LLM-phrased report prose; leave blank to use the
     deterministic template.
4. Deploy. Render builds the existing `Dockerfile` as-is — no changes needed.

**Known tradeoff on the free plan**: disk is ephemeral. A redeploy, or the free plan's sleep/wake
cycle after inactivity, wipes `/app/data` — the audit log, accounts, and any imported
assessments. That's an accepted tradeoff for a short-lived demo instance, not a bug; a deployment
that needs state to survive restarts should use Render's Starter plan with a persistent disk
mounted at `/app/data` (added the same way as `./data` is bind-mounted in `docker-compose.yml`),
or Option A/B above on infrastructure you control.

Live scanning (`nmap`/`nikto`/`msfconsole`) is unavailable on the Render instance by design — the
image deliberately doesn't bundle those tools (see the Dockerfile's comment). Import-based
ingestion, correlation, risk scoring, reporting, and the full UI all work normally; only live
subprocess scanning needs a build that installs them.

## First login

On first start (any option), the server bootstraps an `admin` account and forces a password change
at first login. Its initial password is `VAPT_BOOTSTRAP_ADMIN_PASSWORD` if set, otherwise a random
one, either way logged once (`accounts.ensure_bootstrap_admin`, surfaced via `logger.warning` --
see `journalctl -u vapt-agent` for systemd, or `docker compose logs`/Render's log viewer for
Docker). The password is also written once to `data/bootstrap_admin` (mode `0600`) so a restart
before first login doesn't orphan the account, and is deleted once the forced change is completed.
On a host with persistent disk, capture that first-boot log line -- it is not printed again. On a
host without one (Render's free plan), set `VAPT_BOOTSTRAP_ADMIN_PASSWORD` instead (see "Deploying
to Render" above) so you're never dependent on reading a log from a container that may already be
gone by the time you look.

## What's in `./data`, and what to back up

| Path | What it is | Backed up how |
|---|---|---|
| `data/audit.log` | Hash-chained, append-only audit trail | Copy -- **never rotate/truncate** (see below) |
| `data/auth.db` | Accounts: usernames, scrypt hashes, sessions | Copy (SQLite, stdlib, FS-1-adjacent) |
| `data/assessments.db` | FS-1: every `Assessment` (plan, findings, approvals, events) | Copy |
| `data/batches.db` | FS-4: `Batch` groupings | Copy |
| `data/<assessment-id>/raw/` | Raw tool output the audit trail's SHA-256 hashes point at | Copy |
| `data/<assessment-id>/report.pdf` | Last generated report for that assessment | Copy (regenerable from `assessments.db` via `POST .../report`) |

`deploy/backup_data.sh <data-dir> <backup-root>` copies all of the above with `rsync -a` into a
timestamped directory, with a `latest` symlink kept current. Run it from cron or a systemd timer:

```cron
0 * * * *  /opt/vapt-agent/deploy/backup_data.sh /opt/vapt-agent/data /mnt/backups/vapt-agent
```

For the Docker deployment, point `<data-dir>` at the host-side bind mount (`./data` next to
`docker-compose.yml`) -- the backup script never needs to run inside the container.

### Why `audit.log` specifically must never be rotated

`vapt_agent/audit.py`'s hash chain covers every entry back to the first line of the file --
`AuditLog.verify()` (surfaced at `GET /audit`, and demonstrated live in the UI) reads and verifies
the *whole* file. A generic logrotate rule that truncates or renames-and-recreates the file would
silently start a new, shorter chain on the next append, breaking the tamper-evidence property
SECURITY.md documents and the `GET /audit` HTTP-level tests check -- with no error, just a chain
that no longer covers the engagement's full history. Let it grow; back it up as a copy (as
`backup_data.sh` does) rather than rotating the live file. If disk usage on a very long-running
deployment is a genuine concern, archive and compress a dated copy out of band -- never the file
the process is actively appending to.

## Health check

`GET /healthz` is unauthenticated, rate-limit-free, and returns only `{"status": "ok"}` -- wire it
into a load balancer's or orchestrator's liveness probe (Docker Compose's `healthcheck:`,
systemd's own process supervision already restarts on failure via `Restart=on-failure`).

## Out of scope for this hackathon submission

Multi-instance/horizontal scaling, a managed database (Postgres/etc.) in place of the SQLite files
above, and TLS termination are all deliberately not addressed here -- this is a single-process,
single-host deployment story sized to match the project's actual current scale (see
`docs/HACKATHON_ROADMAP.md`'s Tier 5 section and SECURITY.md's "what this project is explicitly
NOT claiming"). A reverse proxy (nginx/Caddy/Traefik) terminating TLS in front of either deployment
option is the standard next step and isn't specific to this application.

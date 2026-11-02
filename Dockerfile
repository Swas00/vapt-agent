# FS-5: a deployment story. This image runs the API + static UI (vapt_agent.api:app) under
# uvicorn. It deliberately does NOT bundle nmap/nikto/msfconsole/msf -- those are the external
# tools the orchestrator shells out to for LIVE scanning (vapt_agent/adapters), and bundling a
# penetration-testing toolchain into a container image that might be pulled/run casually is its
# own risk; see SECURITY.md's threat model. Without them, live scanning fails cleanly
# (ToolRun.status="unavailable", recorded as a limitation) while import-based ingestion, analysis,
# reporting, and the whole web UI work normally. Add them with a derived image if a given
# deployment genuinely needs live scanning from inside the container.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vapt_agent/ vapt_agent/

# ./data holds everything that must survive a restart (FS-1's assessments.db/batches.db, the
# account database, the hash-chained audit log, and raw tool-output files) -- mount it as a
# volume in production. See docs/DEPLOYMENT.md for the backup plan.
RUN mkdir -p data && useradd --create-home --uid 1000 vaptagent && chown -R vaptagent /app
USER vaptagent

EXPOSE 8000
# No reload in production -- --reload re-execs the process on file changes, which is a dev
# convenience the README's "uvicorn --reload" invocation uses locally, not something to run
# unattended.
CMD ["uvicorn", "vapt_agent.api:app", "--host", "0.0.0.0", "--port", "8000"]

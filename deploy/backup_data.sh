#!/usr/bin/env bash
# FS-5: backs up everything in ./data that must survive more than a disk failure --
#   - audit.log            (hash-chained; see note below -- NEVER rotate/truncate this file)
#   - auth.db              (accounts: usernames, scrypt hashes, sessions)
#   - assessments.db       (FS-1: Assessment objects)
#   - batches.db           (FS-4: Batch groupings)
#   - <assessment-id>/raw/ (raw tool output the audit trail's SHA-256 references point at)
#
# Usage:
#   deploy/backup_data.sh /path/to/data /path/to/backup-root
#
# Intended to run from cron/systemd-timer, e.g. hourly:
#   0 * * * *  /opt/vapt-agent/deploy/backup_data.sh /opt/vapt-agent/data /mnt/backups/vapt-agent
#
# IMPORTANT -- do not point a generic logrotate rule at audit.log. audit.py's hash chain covers
# every entry back to the first line of the file (AuditLog.verify() reads the whole file); a
# logrotate rotation that truncates or renames-and-recreates it would make the NEXT append start
# a new, shorter chain, silently breaking the "the whole trail is tamper-evident" property this
# tool's SECURITY.md documents and tests/test_audit.py checks. Back it up (copy, append-only,
# never truncate the live file) the same way this script does; let it grow, and archive+compress
# a dated copy out-of-band if disk space is ever a real concern -- but keep the live file intact.
set -euo pipefail

DATA_DIR="${1:?usage: backup_data.sh <data-dir> <backup-root>}"
BACKUP_ROOT="${2:?usage: backup_data.sh <data-dir> <backup-root>}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_ROOT/$STAMP"

mkdir -p "$DEST"
# rsync (not mv/cp -f) so a backup running mid-write never sees a half-written file; --checksum
# would be slower and isn't needed since every file here is append-only or a full-row SQLite
# write (AssessmentStore.save / BatchStore.save), never edited in place byte-by-byte.
rsync -a "$DATA_DIR"/ "$DEST"/

# A rolling "latest" symlink makes `rsync --link-dest` incremental backups trivial for a caller
# that wants cheaper storage than a full copy every run; left as a plain full copy here for
# simplicity and because this is still a hackathon-scale deployment, not a reason to under-claim
# what's actually running -- see docs/HACKATHON_ROADMAP.md FS-5.
ln -sfn "$DEST" "$BACKUP_ROOT/latest"

echo "backed up $DATA_DIR -> $DEST"

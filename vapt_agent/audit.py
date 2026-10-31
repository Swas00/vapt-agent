"""Append-only, hash-chained audit trail. Every decision, tool run and approval is attributable."""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from .models import now


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _last(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, "0" * 64
        last = None
        with self.path.open() as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return 0, "0" * 64
        e = json.loads(last)
        return e["seq"], e["hash"]

    @staticmethod
    def _digest(entry: dict) -> str:
        body = {k: v for k, v in entry.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    def append(self, actor: str, action: str, **details) -> dict:
        with self._lock:
            seq, prev = self._last()
            entry = {"seq": seq + 1, "ts": now(), "actor": actor, "action": action, "details": details, "prev": prev}
            entry["hash"] = self._digest(entry)
            with self.path.open("a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
            return entry

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open() as fh:
            return [json.loads(l) for l in fh if l.strip()]

    def verify(self) -> tuple[bool, str]:
        prev = "0" * 64
        for e in self.entries():
            if e["prev"] != prev or self._digest(e) != e["hash"]:
                return False, f"chain broken at seq {e['seq']}"
            prev = e["hash"]
        return True, f"{len(self.entries())} entries, chain intact"

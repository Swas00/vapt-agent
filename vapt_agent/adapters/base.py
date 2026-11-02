"""Adapter contract. Adapters execute tools (live) and/or parse recorded outputs (import)."""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Evidence, Finding, Service, ToolRun, now
from ..risk import severity_from_cvss


@dataclass
class Parsed:
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def sha256_file(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def clip(s: str, n: int = 400) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


class Adapter:
    name = "base"
    live = False                      # can this adapter execute scans itself?
    imports = True                    # can it ingest recorded output?
    binary: str | None = None
    live_status = "planned"           # for the integration matrix: live | import-only | planned | unsupported
    note = ""
    presets: dict[str, list[str]] = {}
    intrusive_presets: set[str] = set()
    # B3: lower-cased file extensions (no dot) this adapter's import accepts, e.g. {"xml"}. Empty
    # means "no restriction" -- the default, so adding this to the base class never silently
    # breaks an adapter that doesn't override it. Checked against the UPLOADED filename in api.py,
    # before the file is even parsed: a well-formed-but-wrong-tool file (e.g. an Nmap XML export
    # uploaded to the Nessus import route) is a clean, specific 400 instead of either an opaque
    # parse-error 400 or -- worse -- parsing "successfully" into nonsense because the wrong
    # format happened to not raise.
    import_extensions: set[str] = set()

    def available(self) -> bool:
        return bool(self.binary and shutil.which(self.binary))

    # -- live ----------------------------------------------------------
    def command(self, target: str, preset: str, out: Path) -> list[str]:
        raise NotImplementedError

    def run(self, target: str, preset: str, workdir: Path, timeout: int = 900) -> ToolRun:
        run = ToolRun(tool=self.name, mode="live", target=target, preset=preset, started=now(), status="running")
        if not self.live:
            run.status, run.error, run.finished = "unavailable", f"{self.name} has no live adapter (import-only)", now()
            return run
        if not self.available():
            run.status, run.error, run.finished = "unavailable", f"'{self.binary}' not found on PATH", now()
            return run
        workdir.mkdir(parents=True, exist_ok=True)
        out = workdir / f"{self.name}-{run.id}.{self.out_ext}"
        cmd = self.command(target, preset, out)
        run.command = cmd
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
            if not out.exists() and proc.stdout:
                out.write_text(proc.stdout)
            if proc.returncode != 0 and not out.exists():
                run.status, run.error = "failed", clip(proc.stderr, 800)
            else:
                run.status = "ok"
                if proc.returncode != 0:
                    run.error = f"exit {proc.returncode}: {clip(proc.stderr, 400)}"
        except subprocess.TimeoutExpired:
            run.status, run.error = "timeout", f"exceeded {timeout}s"
        except OSError as e:
            run.status, run.error = "failed", str(e)
        run.finished = now()
        if out.exists():
            run.raw_path, run.raw_sha256 = str(out), sha256_file(out)
        return run

    out_ext = "txt"

    # -- parsing -------------------------------------------------------
    def parse(self, raw_path: Path) -> Parsed:
        raise NotImplementedError

    # helpers
    def ev(self, raw_path: Path, locator: str, snippet: str) -> Evidence:
        return Evidence(tool=self.name, raw_ref=f"{self.name}:{Path(raw_path).name}#{locator}",
                        snippet=clip(snippet), artifact_sha256=sha256_file(raw_path))

    @staticmethod
    def sev_from(cvss: float | None, fallback: str = "info") -> str:
        return severity_from_cvss(cvss) if cvss is not None else fallback

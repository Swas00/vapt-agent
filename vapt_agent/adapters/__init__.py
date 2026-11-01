from .base import Adapter, Parsed
from .infra import Metasploit, Nessus, OpenVAS
from .nmap import Nmap
from .web import Burp, Nikto, Zap

# Parsed is re-exported as part of this package's public surface (what any new adapter's
# parse() returns), even though nothing in this file uses it directly.
__all__ = ["Adapter", "Parsed", "registry", "integration_matrix", "ADAPTER_CLASSES"]

ADAPTER_CLASSES = [Nmap, Nessus, OpenVAS, Nikto, Zap, Burp, Metasploit]


def registry() -> dict[str, Adapter]:
    return {cls().name: cls() for cls in ADAPTER_CLASSES}


def integration_matrix() -> list[dict]:
    """Truthful per-tool status, derived from each adapter's own declared capability."""
    rows = []
    for a in registry().values():
        rows.append({
            "tool": a.name,
            "status": a.live_status,          # live | import-only | planned | unsupported
            "live_executable_now": bool(a.live and a.available()) if a.live else False,
            "note": a.note,
        })
    return rows

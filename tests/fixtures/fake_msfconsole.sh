#!/usr/bin/env bash
# A stand-in for msfconsole used ONLY to verify the subprocess-wiring and output-interpretation
# code in vapt_agent/adapters/infra.py:Metasploit (command construction, approval gating,
# "validated"/"not_reproducible" text parsing). This is authored locally, not downloaded, and
# contains no exploit code -- it just echoes the console phrasing Metasploit's own `check`
# command uses, so interpret() can be exercised against real stdout from a real subprocess.
set -e
args="$*"
echo "[fake-msfconsole] invoked with: $args"
if [[ "$args" == *"vuln_module"* ]]; then
  echo "[+] 10.10.10.5:445 - The target is vulnerable."
elif [[ "$args" == *"safe_module"* ]]; then
  echo "[-] 10.10.10.5:445 - The target is not exploitable."
else
  echo "[*] Check mode ran; result inconclusive."
fi

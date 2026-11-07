"""
recon.py - OSINT and recon tools for Marty, behind a hard target allowlist.

The allowlist is the point. A model will confidently ask to scan something it
should not; a prompt is a suggestion and a scope file is a rule. Every target is
resolved and checked against tools/recon.scope.json BEFORE a subprocess is spawned,
the same way tools/marty_tools.py refuses a path before opening it. Every call,
allowed or refused, appends a line to logs/marty-tools.log.

    py tools/recon.py scope                      show what is in scope
    py tools/recon.py lookup <ip>                Shodan InternetDB - keyless, sends NO packets
    py tools/recon.py certs <domain>             crt.sh certificate transparency - passive
    py tools/recon.py subdomains <domain>        subfinder - passive, queries public sources
    py tools/recon.py resolve <host> [host ...]  dnsx
    py tools/recon.py probe <host> [host ...]    httpx - ACTIVE, touches the target
    py tools/recon.py scan <host>                nuclei - ACTIVE and loud
    py tools/recon.py allow <target> --why "..."  add a target to scope (records why)

Passive commands (lookup, certs, subdomains) read third-party databases and never
send a packet to the target. Active commands (probe, scan) do. Both are scoped;
the distinction is printed so it is never a surprise.

Binaries live in tools/bin/ and are prepended to PATH for subprocesses only -
the system PATH is left alone.
"""

import argparse
import ipaddress
import json
import os
import pathlib
import socket
import subprocess
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

HERE = pathlib.Path(__file__).resolve().parent
AGENT = HERE.parent
BIN = HERE / "bin"
SCOPE_FILE = HERE / "recon.scope.json"
LOG = AGENT / "logs" / "marty-tools.log"

DEFAULT_SCOPE = {
    "_comment": "Hard allowlist. recon.py refuses any target not matched here, before spawning anything. Add entries with 'recon.py allow', which records a reason.",
    "allowed_cidrs": [
        {"cidr": "{{IP_192_168_56_0}}/24", "why": "VirtualBox host-only lab segment (legacy)"},
        {"cidr": "{{IP_10_13_37_0}}/24", "why": "VirtualBox internal-network lab segment (labnet)"},
    ],
    "allowed_domains": [
        {"domain": "scanme.nmap.org", "why": "Nmap's own publicly sanctioned scan target"},
    ],
    "_denied_always": "RFC1918 ranges outside the lab, the home LAN {{HOME_LAN_NET}}/22, the Synology, and the {{IP_100_64_0_0}}/10 tailnet are never in scope - those are Lukas's own production network, not targets.",
    "hard_denied_cidrs": ["{{HOME_LAN_NET}}/22", "{{IP_100_64_0_0}}/10"],
}


# ------------------------------------------------------------------ scope

def load_scope():
    if SCOPE_FILE.exists():
        return json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    SCOPE_FILE.write_text(json.dumps(DEFAULT_SCOPE, indent=2), encoding="utf-8")
    return dict(DEFAULT_SCOPE)


def log(action, target, verdict, note=""):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    import datetime
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{stamp}\trecon:{action}\t{verdict}\t{target}"
    if note:
        line += f"\t{note}"
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _ips_for(target):
    """Every IP a target resolves to. A hostname pointing into a denied range is
    still a denied target, so resolution happens before the verdict."""
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    try:
        return sorted({r[4][0] for r in socket.getaddrinfo(target, None)})
    except socket.gaierror:
        return []


def check_target(target, scope):
    """Authorize a target or exit. Returns a short note about why it passed."""
    target = target.strip().lower().rstrip(".")
    ips = _ips_for(target)

    # hard denies win over everything, including an explicit allow entry
    for ip in ips:
        for blocked in scope.get("hard_denied_cidrs", []):
            if ipaddress.ip_address(ip) in ipaddress.ip_network(blocked):
                log("scope", target, "DENIED", f"{ip} in hard-denied {blocked}")
                raise SystemExit(
                    f"refused: {target} resolves to {ip}, inside {blocked}.\n"
                    "  That is Lukas's own production network, not a target. This one cannot be\n"
                    "  overridden with 'recon.py allow' - edit hard_denied_cidrs by hand if you\n"
                    "  genuinely mean it."
                )

    for entry in scope.get("allowed_domains", []):
        d = entry["domain"].lower()
        if target == d or target.endswith("." + d):
            return f"domain allowlist ({d}: {entry.get('why','')})"

    for ip in ips:
        for entry in scope.get("allowed_cidrs", []):
            if ipaddress.ip_address(ip) in ipaddress.ip_network(entry["cidr"]):
                return f"{ip} in {entry['cidr']} ({entry.get('why','')})"

    log("scope", target, "DENIED", "not in allowlist")
    raise SystemExit(
        f"refused: {target} is not in scope.\n"
        f"  resolved to: {', '.join(ips) if ips else '(did not resolve)'}\n"
        f"  scope file: {SCOPE_FILE}\n"
        f"  add it deliberately:  py tools/recon.py allow {target} --why \"...\""
    )


# ------------------------------------------------------------------ running

def tool_env():
    env = dict(os.environ)
    env["PATH"] = str(BIN) + os.pathsep + env.get("PATH", "")
    return env


def run_tool(exe, args, stdin_text=None):
    path = BIN / f"{exe}.exe"
    if not path.exists():
        raise SystemExit(f"{exe} is not installed at {path}")
    r = subprocess.run([str(path)] + args, input=stdin_text, capture_output=True,
                       text=True, env=tool_env(), encoding="utf-8", errors="replace")
    if r.returncode != 0 and not r.stdout.strip():
        raise SystemExit(f"{exe} failed ({r.returncode}):\n{(r.stderr or '')[-1500:]}")
    return r.stdout


def emit_jsonl(raw):
    """These tools emit JSONL - one object per line, not one JSON document."""
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    print(json.dumps(rows, indent=2))
    return rows


def get_json(url, label):
    """Third-party JSON API. These serve HTML error pages on a bad day, so a
    decode failure is reported as an error rather than a stack trace."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "marty-recon/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"_note": f"{label}: no record for this target (404)"}
        raise SystemExit(f"{label} returned HTTP {e.code}")
    except Exception as e:
        raise SystemExit(f"{label} unreachable: {e}")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        raise SystemExit(f"{label} returned non-JSON (probably an error page): {body[:200]}")


# ------------------------------------------------------------------ commands

def cmd_scope(a, scope):
    print("PASSIVE commands (lookup, certs, subdomains) never touch the target.")
    print("ACTIVE commands (probe, scan) do.\n")
    print("allowed domains:")
    for e in scope.get("allowed_domains", []):
        print(f"  {e['domain']:<30} {e.get('why','')}")
    print("allowed CIDRs:")
    for e in scope.get("allowed_cidrs", []):
        print(f"  {e['cidr']:<30} {e.get('why','')}")
    print("hard denied (cannot be overridden by 'allow'):")
    for c in scope.get("hard_denied_cidrs", []):
        print(f"  {c}")
    print(f"\nscope file: {SCOPE_FILE}\nlog:        {LOG}")


def cmd_allow(a, scope):
    t = a.target.strip().lower()
    try:
        ipaddress.ip_network(t)
        scope.setdefault("allowed_cidrs", []).append({"cidr": t, "why": a.why})
        kind = "CIDR"
    except ValueError:
        scope.setdefault("allowed_domains", []).append({"domain": t, "why": a.why})
        kind = "domain"
    SCOPE_FILE.write_text(json.dumps(scope, indent=2), encoding="utf-8")
    log("allow", t, "ADDED", a.why)
    print(f"added {kind} {t} to scope\n  why: {a.why}")


def cmd_lookup(a, scope):
    why = check_target(a.target, scope)
    log("lookup", a.target, "OK", "passive, internetdb")
    print(f"# PASSIVE - Shodan InternetDB, no packets sent to target. In scope: {why}",
          file=sys.stderr)
    print(json.dumps(get_json(f"https://internetdb.shodan.io/{a.target}", "InternetDB"), indent=2))


def cmd_certs(a, scope):
    why = check_target(a.target, scope)
    log("certs", a.target, "OK", "passive, crt.sh")
    print(f"# PASSIVE - crt.sh certificate transparency. In scope: {why}", file=sys.stderr)
    data = get_json(f"https://crt.sh/?q={a.target}&output=json", "crt.sh")
    names = sorted({n.strip().lower() for row in data if isinstance(row, dict)
                    for n in str(row.get("name_value", "")).splitlines() if n.strip()})
    print(json.dumps({"target": a.target, "unique_names": names, "certificates": len(data)}, indent=2))


def cmd_subdomains(a, scope):
    why = check_target(a.target, scope)
    log("subdomains", a.target, "OK", "passive, subfinder")
    print(f"# PASSIVE - subfinder queries public sources only. In scope: {why}", file=sys.stderr)
    emit_jsonl(run_tool("subfinder", ["-d", a.target, "-silent", "-oJ"]))


def cmd_resolve(a, scope):
    for t in a.targets:
        check_target(t, scope)
    log("resolve", ",".join(a.targets), "OK", "dnsx")
    emit_jsonl(run_tool("dnsx", ["-silent", "-j"], stdin_text="\n".join(a.targets) + "\n"))


def cmd_probe(a, scope):
    for t in a.targets:
        check_target(t, scope)
    log("probe", ",".join(a.targets), "OK", "ACTIVE, httpx")
    print("# ACTIVE - this sends requests to the target. Rate limited to 5/s.", file=sys.stderr)
    emit_jsonl(run_tool("httpx", ["-silent", "-j", "-rl", "5", "-t", "5"],
                        stdin_text="\n".join(a.targets) + "\n"))


def cmd_scan(a, scope):
    why = check_target(a.target, scope)
    log("scan", a.target, "OK", f"ACTIVE, nuclei, severity={a.severity}")
    print(f"# ACTIVE AND LOUD - nuclei against {a.target}. In scope: {why}", file=sys.stderr)
    print("# -ni is set: no OAST callbacks, so target hostnames never reach public "
          "interactsh servers.", file=sys.stderr)
    out = HERE / "_nuclei_last.jsonl"
    run_tool("nuclei", ["-silent", "-target", a.target, "-jle", str(out), "-ni",
                        "-rl", "10", "-c", "10", "-severity", a.severity])
    emit_jsonl(out.read_text(encoding="utf-8") if out.exists() else "")


def main():
    ap = argparse.ArgumentParser(description="Scoped recon tools.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scope").set_defaults(fn=cmd_scope)

    p = sub.add_parser("allow"); p.add_argument("target")
    p.add_argument("--why", required=True, help="why this target is authorized")
    p.set_defaults(fn=cmd_allow)

    for name, fn, helptxt in [
        ("lookup", cmd_lookup, "Shodan InternetDB (passive, keyless)"),
        ("certs", cmd_certs, "crt.sh certificate transparency (passive)"),
        ("subdomains", cmd_subdomains, "subfinder (passive)"),
    ]:
        p = sub.add_parser(name, help=helptxt); p.add_argument("target"); p.set_defaults(fn=fn)

    for name, fn, helptxt in [
        ("resolve", cmd_resolve, "dnsx"),
        ("probe", cmd_probe, "httpx (ACTIVE)"),
    ]:
        p = sub.add_parser(name, help=helptxt); p.add_argument("targets", nargs="+"); p.set_defaults(fn=fn)

    p = sub.add_parser("scan", help="nuclei (ACTIVE)")
    p.add_argument("target"); p.add_argument("--severity", default="critical,high,medium")
    p.set_defaults(fn=cmd_scan)

    a = ap.parse_args()
    a.fn(a, load_scope())


if __name__ == "__main__":
    main()

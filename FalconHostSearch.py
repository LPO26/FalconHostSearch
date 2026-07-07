"""
FalconHostSearch.py
Search CrowdStrike Falcon for hosts by IP, hostname, or OS/type. With --vulns,
also pull each matched host's vulnerabilities from Tenable.

    CrowdStrike answers "which hosts."   Tenable (with --vulns) answers "what's wrong."

Examples:
    python FalconHostSearch.py Windows                 -> Falcon host list
    python FalconHostSearch.py "Windows Server"        -> Falcon: Windows servers
    python FalconHostSearch.py --user john             -> hosts where "john" recently logged in
    python FalconHostSearch.py --user john "Windows"   -> ...limited to Windows hosts (faster)
    python FalconHostSearch.py web01 --vulns           -> host info + Tenable vulnerabilities
    python FalconHostSearch.py web01 --ports           -> host info + open ports (Tenable)
    python FalconHostSearch.py web01 --ports --vulns   -> open ports and vulnerabilities
    python FalconHostSearch.py --user john --vulns     -> john's hosts + their vulnerabilities
    python FalconHostSearch.py 10.50.10.24 --vulns --days 180
    python FalconHostSearch.py web01 --vulns --min-severity medium          -> medium and above
    python FalconHostSearch.py web01 --vulns --min-severity critical,high   -> only those levels
    python FalconHostSearch.py "Windows Server" --md > report.md   -> Markdown report

Setup (two dependencies):
    pip install crowdstrike-falconpy requests

Keys come from environment variables.
  CrowdStrike (always needed):
    FALCON_CLIENT_ID, FALCON_CLIENT_SECRET   (optional FALCON_CLOUD = us1|us2|eu1|usgov1)
  Tenable (only needed when using --vulns or --ports):
    TIO_ACCESS_KEY, TIO_SECRET_KEY

  --apps uses CrowdStrike Discover (scope: Discover: READ, same Falcon keys).
  --detections uses the CrowdStrike Alerts API (scope: Alerts: READ).
  --intel-actors / --intel-reports use Falcon Intelligence (scopes: Actors /
  Reports (Falcon Intelligence): READ) and run standalone, no host search needed.

    Windows PowerShell:  $env:FALCON_CLIENT_ID="..."   (etc.)
    macOS / Linux:       export FALCON_CLIENT_ID="..." (etc.)

Falcon client needs "Hosts: READ". Tenable keys need Basic [16] read access.
"""

import os
import re
import sys
import argparse
from datetime import datetime, timedelta, timezone

# ---- shared display helpers ------------------------------------------------
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[38;5;44m"
TAG = "\033[38;5;44m"
RESET = "\033[0m"

SEV = {  # Tenable severity 0..4 -> name + color
    4: ("CRITICAL", "\033[1;38;5;196m"),
    3: ("HIGH",     "\033[38;5;208m"),
    2: ("MEDIUM",   "\033[38;5;178m"),
    1: ("LOW",      "\033[38;5;39m"),
    0: ("INFO",     "\033[38;5;245m"),
}
SEV_NAMES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def parse_severities(value):
    """Parse --min-severity into (set of severity ints, display label).

    A single level keeps the historical floor behavior ("medium" = medium and
    above). A comma-separated list selects exactly those levels
    ("critical,high" = only critical + high). Returns (None, "") for all."""
    tokens = [t.strip().lower() for t in (value or "").split(",") if t.strip()]
    if not tokens:
        return None, ""
    bad = [t for t in tokens if t not in SEV_NAMES]
    if bad:
        raise ValueError(f"unknown severity level(s): {', '.join(bad)} "
                         f"(choose from: critical, high, medium, low, info)")
    if len(tokens) == 1:
        floor = SEV_NAMES[tokens[0]]
        if floor == 0:
            return None, ""  # info+ = everything
        return {s for s in SEV if s >= floor}, f"{tokens[0]}+"
    chosen = {SEV_NAMES[t] for t in tokens}
    if chosen == set(SEV):
        return None, ""
    label = "+".join(SEV[s][0].lower() for s in sorted(chosen, reverse=True))
    return chosen, label

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
PLATFORMS = {"windows": "Windows", "linux": "Linux",
             "mac": "Mac", "macos": "Mac", "osx": "Mac"}
TYPE_WORDS = {
    "server": "Server", "servers": "Server",
    "workstation": "Workstation", "workstations": "Workstation",
    "desktop": "Workstation", "desktops": "Workstation", "pc": "Workstation",
    "dc": "Domain Controller", "dcs": "Domain Controller",
}


def enable_ansi_on_windows():
    if os.name == "nt":
        os.system("")


def clip(text, width):
    text = str(text or "")
    return text if len(text) <= width else text[: width - 1] + "\u2026"


def first(values, default="-"):
    if isinstance(values, list):
        return values[0] if values else default
    return values or default


# ===========================================================================
# CrowdStrike (host search)
# ===========================================================================

def get_falcon_client():
    from falconpy import Hosts
    cid = os.environ.get("FALCON_CLIENT_ID", "")
    secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not cid or not secret:
        print("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables first.")
        sys.exit(1)
    return Hosts(client_id=cid, client_secret=secret,
                 base_url=os.environ.get("FALCON_CLOUD", "us1"))


def build_filter(term):
    t = term.strip()
    if IP_RE.match(t):
        return f"local_ip:'{t}',external_ip:'{t}'", f"IP = {t}"
    rem = f" {t.lower()} "
    platform = ptype = None
    if " domain controller " in rem:
        ptype = "Domain Controller"
        rem = rem.replace(" domain controller ", " ")
    for word, val in PLATFORMS.items():
        if f" {word} " in rem:
            platform = val
            rem = rem.replace(f" {word} ", " ")
            break
    if not ptype:
        for word, val in TYPE_WORDS.items():
            if f" {word} " in rem:
                ptype = val
                rem = rem.replace(f" {word} ", " ")
                break
    if (platform or ptype) and not rem.strip():
        clauses, desc = [], []
        if platform:
            clauses.append(f"platform_name:'{platform}'")
            desc.append(platform)
        if ptype:
            clauses.append(f"product_type_desc:'{ptype}'")
            desc.append(ptype)
        return "+".join(clauses), " ".join(desc) + " hosts"
    return f"hostname:*'*{t}*',os_version:*'*{t}*'", f"hostname or OS contains '{t}'"


def search_hosts(client, fql=None):
    aids, offset = [], 0
    while True:
        kwargs = {"limit": 5000, "offset": offset, "sort": "hostname.asc"}
        if fql:
            kwargs["filter"] = fql
        resp = client.query_devices_by_filter(**kwargs)
        if resp["status_code"] >= 400:
            errs = resp["body"].get("errors", [])
            raise RuntimeError(errs[0].get("message") if errs else f"HTTP {resp['status_code']}")
        body = resp["body"]
        batch = body.get("resources") or []
        aids.extend(batch)
        total = body.get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(batch)
        if not batch or offset >= total:
            break
    hosts = []
    for i in range(0, len(aids), 500):
        dr = client.get_device_details(ids=aids[i:i + 500])
        if dr["status_code"] < 400:
            hosts.extend(dr["body"].get("resources") or [])
    return hosts


def add_login_users(client, hosts):
    by_id = {h["device_id"]: h for h in hosts if h.get("device_id")}
    ids = list(by_id)
    for i in range(0, len(ids), 10):
        resp = client.query_device_login_history(ids=ids[i:i + 10])
        if resp["status_code"] >= 400:
            continue
        for rec in resp["body"].get("resources") or []:
            host = by_id.get(rec.get("device_id"))
            logins = rec.get("recent_logins") or []
            if host and logins:
                logins = sorted(logins, key=lambda x: x.get("login_time", ""), reverse=True)
                host["_login_users"] = [l.get("user_name", "") for l in logins]
                if not host.get("last_login_user"):
                    host["last_login_user"] = logins[0].get("user_name", "")


def render_hosts(hosts, description, show_aid, show_login):
    print(f"\n{BOLD}Search:{RESET} {description}")
    if not hosts:
        print("No matching hosts found.\n")
        return
    hosts.sort(key=lambda h: (h.get("hostname") or "").lower())
    cols = f"{'HOSTNAME':<20} {'LOCAL IP':<15} {'OS VERSION':<20} {'TYPE':<11} {'MANUFACTURER':<16}"
    if show_login:
        cols += f" {'LAST LOGIN USER':<22}"
    cols += f" {'LAST SEEN':<10}"
    if show_aid:
        cols += f" {'AID':<32}"
    width = len(cols) + 6
    print(f"{BOLD}Matches: {len(hosts)}{RESET}")
    print("-" * width)
    print(f"{BOLD}{cols}{RESET}")
    print("-" * width)
    for h in hosts:
        row = (f"{clip(h.get('hostname'), 20):<20} "
               f"{clip(h.get('local_ip'), 15):<15} "
               f"{clip(h.get('os_version'), 20):<20} "
               f"{clip(h.get('product_type_desc'), 11):<11} "
               f"{clip(h.get('system_manufacturer'), 16):<16}")
        if show_login:
            row += f" {CYAN}{clip(h.get('last_login_user', ''), 22):<22}{RESET}"
        row += f" {(h.get('last_seen') or '')[:10]:<10}"
        if show_aid:
            row += f" {DIM}{h.get('device_id', '')}{RESET}"
        print(row)
    print("-" * width)
    print(f"{len(hosts)} host(s)")


# ===========================================================================
# User lookup  (--user)  -- filters on the SAME last-login-user data shown in
# the table, so what you see when searching a host matches what --user finds.
# (There is no server-side FQL field for login user, so this scopes to the
#  candidate hosts and filters them; narrow with a term to keep it fast.)
# ===========================================================================

def user_match(host, needle):
    """True if the search string appears in this host's recent login user(s)."""
    candidates = [host.get("last_login_user", "")] + host.get("_login_users", [])
    return any(needle in (c or "").lower() for c in candidates if c)


def hosts_by_user(falcon, username, scope_term=""):
    """Return hosts whose last/recent login user matches `username`.

    scope_term (optional): an IP/hostname/OS to narrow the candidate hosts first.
    Returns (hosts, description, scanned_all).
    """
    needle = (username or "").strip().lower()
    if not needle:
        raise RuntimeError("Provide a username, e.g. --user john")

    if scope_term:
        fql, scope_desc = build_filter(scope_term)
        scanned_all = False
    else:
        fql, scope_desc, scanned_all = None, "all hosts", True

    hosts = search_hosts(falcon, fql)

    # The login user may already be on the device record; only enrich the hosts
    # that are missing it (this is what makes a scoped search fast).
    missing = [h for h in hosts if not h.get("last_login_user")]
    if missing:
        add_login_users(falcon, missing)

    matched = [h for h in hosts if user_match(h, needle)]
    desc = f"hosts where login user contains \u201c{username}\u201d"
    if scope_term:
        desc += f" (within {scope_desc})"
    return matched, desc, scanned_all


# ===========================================================================
# Tenable (vulnerabilities)  -- only used with --vulns
# ===========================================================================
import requests  # noqa: E402  (kept here so the base tool has no hard dep on it)

TIO_BASE = "https://cloud.tenable.com"


def tio_headers():
    ak = os.environ.get("TIO_ACCESS_KEY", "")
    sk = os.environ.get("TIO_SECRET_KEY", "")
    if not ak or not sk:
        print("--vulns needs Tenable keys: set TIO_ACCESS_KEY and TIO_SECRET_KEY.")
        sys.exit(1)
    return {"X-ApiKeys": f"accessKey={ak}; secretKey={sk}", "Accept": "application/json"}


def tio_find_asset(target, headers):
    if IP_RE.match(target):
        attempts = [("ipv4", "eq")]
    else:
        attempts = [("host.target", "eq"), ("fqdn", "match"),
                    ("hostname", "match"), ("netbios_name", "eq")]
    for field, quality in attempts:
        params = {"filter.0.filter": field, "filter.0.quality": quality, "filter.0.value": target}
        r = requests.get(f"{TIO_BASE}/workbenches/assets", headers=headers, params=params, timeout=30)
        r.raise_for_status()
        assets = r.json().get("assets", [])
        if assets:
            return assets[0]
    return None


def tio_asset_vulns(asset_id, days, headers):
    params = {"date_range": days} if days else {}
    r = requests.get(f"{TIO_BASE}/workbenches/assets/{asset_id}/vulnerabilities",
                     headers=headers, params=params, timeout=60)
    r.raise_for_status()
    return r.json().get("vulnerabilities", [])


def tio_asset_tags(asset_id, headers):
    r = requests.get(f"{TIO_BASE}/tags/assets/{asset_id}/assignments", headers=headers, timeout=30)
    r.raise_for_status()
    return [f"{t.get('category_name')}:{t.get('value')}" for t in r.json().get("tags", [])]


PORT_FAMILIES = {"port scanners", "service detection"}
PORT_TXT_RE = re.compile(r"[Pp]ort (\d{1,5})/(tcp|udp)")


def tio_asset_ports(asset_id, vulns, headers):
    """Open ports for an asset, from its port-scanner / service-detection findings.

    Tenable records open ports as findings (e.g. "Port 443/tcp was found to be
    open"); we read the plugin outputs for those plugins and collect the ports.
    """
    plugin_ids = [v.get("plugin_id") for v in vulns
                  if (v.get("plugin_family") or "").lower() in PORT_FAMILIES and v.get("plugin_id")]
    found = {}  # (port, protocol) -> service name
    for pid in plugin_ids:
        r = requests.get(f"{TIO_BASE}/workbenches/assets/{asset_id}/vulnerabilities/{pid}/outputs",
                         headers=headers, timeout=60)
        if r.status_code >= 400:
            continue
        for out in r.json().get("outputs", []) or []:
            for st in out.get("states", []) or []:
                for res in st.get("results", []) or []:
                    p, proto = res.get("port"), (res.get("protocol") or "tcp").lower()
                    svc = res.get("application_protocol") or ""
                    if p and int(p) > 0:
                        key = (int(p), proto)
                        if svc or key not in found:
                            found[key] = svc or found.get(key, "")
            for m in PORT_TXT_RE.finditer(out.get("plugin_output") or ""):
                found.setdefault((int(m.group(1)), m.group(2).lower()), "")
    return [{"port": p, "protocol": proto, "service": found[(p, proto)]}
            for (p, proto) in sorted(found)]


def fmt_ports(ports):
    return [f"{x['port']}/{x['protocol']}" + (f" ({x['service']})" if x.get("service") else "")
            for x in ports]


def print_tenable_for_host(host, days, headers, want_ports, want_vulns, sev_show=None, sev_label=""):
    """Resolve a Falcon host in Tenable (by hostname, then IP) and print
    its open ports and/or vulnerabilities, per the flags."""
    name = host.get("hostname") or ""
    ip = host.get("local_ip") or ""
    asset = None
    for target in (name, ip):
        if target:
            asset = tio_find_asset(target, headers)
            if asset:
                break

    label = name or ip or "(unknown)"
    print(f"\n{BOLD}{label}{RESET} {DIM}({ip}){RESET}")
    if not asset:
        print(f"  {DIM}Not found in Tenable (no matching asset).{RESET}")
        return

    tags = tio_asset_tags(asset["id"], headers)
    vulns = tio_asset_vulns(asset["id"], days, headers)
    print(f"  {BOLD}Tenable tags:{RESET} " +
          ("  ".join(f"{TAG}{t}{RESET}" for t in tags) if tags else f"{DIM}(none){RESET}"))

    if want_ports:
        ports = tio_asset_ports(asset["id"], vulns, headers)
        if ports:
            print(f"  {BOLD}Open ports ({len(ports)}):{RESET} "
                  + "  ".join(f"{CYAN}{x}{RESET}" for x in fmt_ports(ports)))
        else:
            print(f"  {BOLD}Open ports:{RESET} {DIM}none detected in the last {days} days.{RESET}")

    if want_vulns:
        shown = vulns if sev_show is None else [v for v in vulns if v.get("severity", 0) in sev_show]
        hidden = len(vulns) - len(shown)
        if not shown:
            extra = f" matching {sev_label}" if sev_label else ""
            print(f"  {DIM}No vulnerabilities{extra} in the last {days} days"
                  + (f" ({hidden} other finding(s) filtered out)" if hidden else "") + f".{RESET}")
            return
        vulns = shown
        vulns.sort(key=lambda v: (-v.get("severity", 0), v.get("plugin_name", "")))
        tally = {4: 0, 3: 0, 2: 0, 1: 0, 0: 0}
        for v in vulns:
            tally[v.get("severity", 0)] = tally.get(v.get("severity", 0), 0) + 1
        levels = [s for s in (4, 3, 2, 1, 0) if sev_show is None or s in sev_show]
        summary = "   ".join(f"{SEV[s][1]}{SEV[s][0].title()}: {tally[s]}{RESET}" for s in levels)
        hidden_note = f"   {DIM}({hidden} other finding(s) hidden){RESET}" if hidden else ""
        print(f"  {summary}   {BOLD}Total: {len(vulns)}{RESET}{hidden_note}")
        print("  " + "-" * 88)
        print(f"  {BOLD}{'SEVERITY':<9} {'PLUGIN':<7} {'VULNERABILITY':<48} {'FAMILY':<20}{RESET}")
        print("  " + "-" * 88)
        for v in vulns:
            label_s, color = SEV.get(v.get("severity", 0), ("?", ""))
            print(f"  {color}{label_s:<9}{RESET} "
                  f"{str(v.get('plugin_id', '')):<7} "
                  f"{clip(v.get('plugin_name', ''), 48):<48} "
                  f"{DIM}{clip(v.get('plugin_family', ''), 20)}{RESET}")


# ===========================================================================
# Installed applications  (--apps)  -- CrowdStrike Discover only
# ===========================================================================

def get_discover_client():
    from falconpy import Discover
    cid = os.environ.get("FALCON_CLIENT_ID", "")
    secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not cid or not secret:
        raise RuntimeError("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET first.")
    return Discover(client_id=cid, client_secret=secret,
                    base_url=os.environ.get("FALCON_CLOUD", "us1"))


def discover_apps_for_host(discover, hostname):
    """(apps, status) for a host via Discover. status: ok | forbidden | error | empty."""
    if not hostname:
        return [], "empty"
    fql = f"host.hostname:'{hostname}'"
    apps, after, seen = [], None, set()
    for _ in range(25):  # safety cap on paging
        kwargs = {"filter": fql, "limit": 100}
        if after:
            kwargs["after"] = after
        resp = discover.query_combined_applications(**kwargs)
        sc = resp["status_code"]
        if sc in (401, 403):
            return [], "forbidden"
        if sc >= 400:
            return [], "error"
        body = resp["body"]
        batch = body.get("resources") or []
        for a in batch:
            key = (a.get("name", ""), a.get("version", ""))
            if a.get("name") and key not in seen:
                seen.add(key)
                apps.append({"name": a.get("name", ""), "version": a.get("version", ""),
                             "vendor": a.get("vendor", "")})
        after = body.get("meta", {}).get("pagination", {}).get("after")
        if not after or not batch:
            break
    apps.sort(key=lambda a: a["name"].lower())
    return apps, "ok"


def apps_for_host(host, discover):
    """Installed applications for a host, from CrowdStrike Discover.
    Returns (apps, note)."""
    apps, status = discover_apps_for_host(discover, host.get("hostname"))
    if status == "ok":
        return apps, (None if apps else "no apps recorded in Discover")
    if status == "forbidden":
        return [], "Discover not available (needs Discover: READ)"
    if status == "empty":
        return [], "no hostname to look up"
    return [], "Discover query failed"


def print_apps_for_host(host, discover):
    name = host.get("hostname") or ""
    ip = host.get("local_ip") or ""
    print(f"\n{BOLD}{name or ip or '(unknown)'}{RESET} {DIM}({ip}){RESET}")
    apps, note = apps_for_host(host, discover)
    if not apps:
        print(f"  {DIM}No application data{(' \u2014 ' + note) if note else ''}.{RESET}")
        return
    print(f"  {BOLD}Applications ({len(apps)}){RESET} {DIM}[source: CrowdStrike Discover]{RESET}")
    for a in apps:
        line = f"  {CYAN}{a['name']}{RESET}"
        if a.get("version"):
            line += f" {a['version']}"
        if a.get("vendor"):
            line += f"  {DIM}({a['vendor']}){RESET}"
        print(line)


def apps_for_host_md(host, discover):
    name = host.get("hostname") or ""
    ip = host.get("local_ip") or ""
    print(f"\n### {name or ip or '(unknown)'} ({ip})\n")
    apps, note = apps_for_host(host, discover)
    if not apps:
        print(f"_No application data{(' — ' + note) if note else ''}._")
        return
    print(f"**Installed applications ({len(apps)})** — source: CrowdStrike Discover\n")
    print("| Application | Version | Vendor |")
    print("| --- | --- | --- |")
    for a in apps:
        print(f"| {mdcell(a['name'])} | {mdcell(a.get('version'), default='')} | {mdcell(a.get('vendor'), default='')} |")


# ===========================================================================
# Endpoint detections  (--detections)  -- CrowdStrike Alerts API, per host
# ===========================================================================
# The legacy Detects API was decommissioned (2025-09-30); detections now come
# from the Alerts API and need the "Alerts: READ" scope.

def get_alerts_client():
    from falconpy import Alerts
    cid = os.environ.get("FALCON_CLIENT_ID", "")
    secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not cid or not secret:
        raise RuntimeError("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET first.")
    return Alerts(client_id=cid, client_secret=secret,
                  base_url=os.environ.get("FALCON_CLOUD", "us1"))


ALERT_SEV = {  # alert severity_name -> color (reuses the Tenable palette)
    "critical": SEV[4][1], "high": SEV[3][1], "medium": SEV[2][1],
    "low": SEV[1][1], "informational": SEV[0][1], "info": SEV[0][1],
}


def detections_for_host(alerts, host, days, limit=20):
    """Recent alerts (detections) for one host, newest first.
    Returns (rows, note); note is set when the data can't be read."""
    aid = host.get("device_id", "")
    if not aid:
        return [], "no agent ID for this host"
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fql = f"device.device_id:'{aid}'+created_timestamp:>='{since}'"
    resp = alerts.query_alerts_v2(filter=fql, limit=limit, sort="created_timestamp|desc")
    sc = resp["status_code"]
    if sc in (401, 403):
        return [], "no access (client needs the Alerts: READ scope)"
    if sc >= 400:
        errs = (resp["body"].get("errors") or [{}])
        return [], f"Alerts API error: {errs[0].get('message', f'HTTP {sc}')}"
    ids = resp["body"].get("resources") or []   # composite IDs
    total = resp["body"].get("meta", {}).get("pagination", {}).get("total", len(ids))
    if not ids:
        return [], None
    d = alerts.get_alerts_v2(composite_ids=ids)
    if d["status_code"] >= 400:
        return [], f"Alerts API error reading details (HTTP {d['status_code']})"
    rows = []
    for a in d["body"].get("resources") or []:
        rows.append({
            "severity": (a.get("severity_name") or "").lower() or "info",
            "name": a.get("display_name") or a.get("description") or "(unnamed)",
            "tactic": a.get("tactic") or "",
            "technique": a.get("technique") or "",
            "status": a.get("status") or "",
            "when": (a.get("created_timestamp") or "")[:10],
        })
    rows.sort(key=lambda r: r["when"], reverse=True)
    return rows, ("showing latest %d of %s" % (len(rows), commas(total)) if total > len(rows) else None)


def commas(n):
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def print_detections_for_host(host, alerts, days):
    name = host.get("hostname") or host.get("local_ip") or "(unknown)"
    print(f"\n{BOLD}{name}{RESET} {DIM}({host.get('local_ip', '')}){RESET}")
    rows, note = detections_for_host(alerts, host, days)
    if not rows:
        print(f"  {DIM}{note or f'No detections in the last {days} days.'}{RESET}")
        return
    if note:
        print(f"  {DIM}{note}{RESET}")
    print(f"  {BOLD}{'SEVERITY':<9} {'DATE':<11} {'DETECTION':<44} {'TACTIC / TECHNIQUE':<30} {'STATUS'}{RESET}")
    print("  " + "-" * 104)
    for r in rows:
        color = ALERT_SEV.get(r["severity"], "")
        tt = clip(" / ".join(x for x in (r["tactic"], r["technique"]) if x), 30)
        print(f"  {color}{r['severity'].upper():<9}{RESET} {DIM}{r['when']:<11}{RESET} "
              f"{clip(r['name'], 44):<44} {tt:<30} {DIM}{r['status']}{RESET}")


def detections_for_host_md(host, alerts, days):
    name = host.get("hostname") or host.get("local_ip") or "(unknown)"
    print(f"\n### {name} ({host.get('local_ip', '')})\n")
    rows, note = detections_for_host(alerts, host, days)
    if not rows:
        print(f"_{note or f'No detections in the last {days} days.'}_")
        return
    if note:
        print(f"_{note}_\n")
    print("| Severity | Date | Detection | Tactic / Technique | Status |")
    print("| --- | --- | --- | --- | --- |")
    for r in rows:
        tt = " / ".join(x for x in (r["tactic"], r["technique"]) if x)
        print(f"| {r['severity'].title()} | {r['when']} | {mdcell(r['name'])} | "
              f"{mdcell(tt, default='')} | {mdcell(r['status'], default='')} |")


# ===========================================================================
# Threat intel  (--intel-actors / --intel-reports)  -- standalone, no host needed
# ===========================================================================

def get_intel_client():
    from falconpy import Intel
    cid = os.environ.get("FALCON_CLIENT_ID", "")
    secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not cid or not secret:
        raise RuntimeError("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET first.")
    return Intel(client_id=cid, client_secret=secret,
                 base_url=os.environ.get("FALCON_CLOUD", "us1"))


def intel_query(intel, kind, query, limit=10):
    """Query threat actors or reports. Returns (items, total, note)."""
    fn = intel.query_actor_entities if kind == "actors" else intel.query_report_entities
    kwargs = {"limit": limit}
    if query:
        kwargs["q"] = query
    resp = fn(**kwargs)
    sc = resp["status_code"]
    scope = "Actors (Falcon Intelligence): READ" if kind == "actors" else "Reports (Falcon Intelligence): READ"
    if sc in (401, 403):
        return [], 0, f"no access (client needs the {scope} scope / Intel subscription)"
    if sc >= 400:
        errs = (resp["body"].get("errors") or [{}])
        return [], 0, f"Intel API error: {errs[0].get('message', f'HTTP {sc}')}"
    body = resp["body"]
    items = body.get("resources") or []
    total = body.get("meta", {}).get("pagination", {}).get("total", len(items))
    return items, total, None


def print_intel_actors(intel, query, as_md, limit=10):
    items, total, note = intel_query(intel, "actors", query, limit)
    heading = "Threat intel: actors" + (f" matching \u201c{query}\u201d" if query else "")
    if as_md:
        print(f"\n## {heading}\n")
        if note:
            print(f"_{note}_")
            return
        if not items:
            print("_No actors found._")
            return
        print(f"_{commas(total)} total; showing {len(items)}_\n")
        print("| Actor | Origins | Target industries | Last active |")
        print("| --- | --- | --- | --- |")
        for a in items:
            origins = ", ".join(o.get("value", "") for o in (a.get("origins") or [])[:3])
            targets = ", ".join(t.get("value", "") for t in (a.get("target_industries") or [])[:3])
            last = ""
            if a.get("last_activity_date"):
                last = datetime.fromtimestamp(a["last_activity_date"], tz=timezone.utc).strftime("%Y-%m-%d")
            print(f"| {mdcell(a.get('name'))} | {mdcell(origins, default='')} | "
                  f"{mdcell(targets, default='')} | {mdcell(last, default='')} |")
        return
    print(f"\n{BOLD}{'=' * 92}{RESET}\n{BOLD}{heading}{RESET}")
    if note:
        print(f"  {DIM}{note}{RESET}")
        return
    if not items:
        print(f"  {DIM}No actors found.{RESET}")
        return
    print(f"  {DIM}{commas(total)} total; showing {len(items)}{RESET}")
    for a in items:
        origins = ", ".join(o.get("value", "") for o in (a.get("origins") or [])[:3])
        targets = ", ".join(t.get("value", "") for t in (a.get("target_industries") or [])[:3])
        last = ""
        if a.get("last_activity_date"):
            last = datetime.fromtimestamp(a["last_activity_date"], tz=timezone.utc).strftime("%Y-%m-%d")
        line = f"  {CYAN}{a.get('name', '?')}{RESET}"
        extras = "  ".join(x for x in (origins, f"targets: {targets}" if targets else "",
                                       f"last active: {last}" if last else "") if x)
        print(line + (f"  {DIM}{extras}{RESET}" if extras else ""))


def print_intel_reports(intel, query, as_md, limit=10):
    items, total, note = intel_query(intel, "reports", query, limit)
    heading = "Threat intel: reports" + (f" matching \u201c{query}\u201d" if query else "")
    if as_md:
        print(f"\n## {heading}\n")
        if note:
            print(f"_{note}_")
            return
        if not items:
            print("_No reports found._")
            return
        print(f"_{commas(total)} total; showing {len(items)}. "
              f"Read one with `--report ID`, save its PDF with `--report-pdf ID`._\n")
        print("| ID | Report | Type | Published |")
        print("| --- | --- | --- | --- |")
        for r in items:
            rtype = (r.get("type") or {}).get("name", "") if isinstance(r.get("type"), dict) else (r.get("type") or "")
            when = (r.get("created_date") and
                    datetime.fromtimestamp(r["created_date"], tz=timezone.utc).strftime("%Y-%m-%d")) or ""
            print(f"| {mdcell(r.get('id'))} | {mdcell(r.get('name'))} | {mdcell(rtype, default='')} | {mdcell(when, default='')} |")
        return
    print(f"\n{BOLD}{'=' * 92}{RESET}\n{BOLD}{heading}{RESET}")
    if note:
        print(f"  {DIM}{note}{RESET}")
        return
    if not items:
        print(f"  {DIM}No reports found.{RESET}")
        return
    print(f"  {DIM}{commas(total)} total; showing {len(items)}. "
          f"Read one: --report ID   Save its PDF: --report-pdf ID{RESET}")
    for r in items:
        rtype = (r.get("type") or {}).get("name", "") if isinstance(r.get("type"), dict) else (r.get("type") or "")
        when = (r.get("created_date") and
                datetime.fromtimestamp(r["created_date"], tz=timezone.utc).strftime("%Y-%m-%d")) or ""
        extras = "  ".join(x for x in (rtype, when) if x)
        rid = r.get("id", "")
        print(f"  {DIM}[{rid}]{RESET} {CYAN}{r.get('name', '?')}{RESET}"
              + (f"  {DIM}{extras}{RESET}" if extras else ""))


# ---- reading a single report ----------------------------------------------

TAG_RE = re.compile(r"<[^>]+>")


def strip_html(text):
    """Report rich text is HTML; reduce it to plain text for the terminal."""
    text = re.sub(r"(?i)</(p|div|h\d|li|br)>", "\n", text or "")
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = TAG_RE.sub("", text)
    text = text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def intel_report_detail(intel, report_id):
    """Full detail for one report. Returns (report dict, note)."""
    resp = intel.get_report_entities(ids=[str(report_id)])
    sc = resp["status_code"]
    if sc in (401, 403):
        return None, "no access (client needs the Reports (Falcon Intelligence): READ scope)"
    if sc >= 400:
        errs = (resp["body"].get("errors") or [{}])
        return None, f"Intel API error: {errs[0].get('message', f'HTTP {sc}')}"
    res = resp["body"].get("resources") or []
    if not res:
        return None, f"report {report_id} not found"
    r = res[0]

    def names(key):
        return [v.get("value") or v.get("name", "") for v in (r.get(key) or [])]

    rtype = (r.get("type") or {}).get("name", "") if isinstance(r.get("type"), dict) else (r.get("type") or "")
    body = r.get("description") or strip_html(r.get("rich_text_description") or "") \
        or r.get("short_description") or ""
    return {
        "id": r.get("id"), "name": r.get("name", "?"), "type": rtype,
        "when": (r.get("created_date") and
                 datetime.fromtimestamp(r["created_date"], tz=timezone.utc).strftime("%Y-%m-%d")) or "",
        "actors": [a.get("name", "") for a in (r.get("actors") or [])],
        "industries": names("target_industries"),
        "countries": names("target_countries"),
        "motivations": names("motivations"),
        "body": body, "url": r.get("url") or "",
    }, None


def print_report(intel, report_id, as_md):
    rep, note = intel_report_detail(intel, report_id)
    if rep is None:
        if as_md:
            print(f"\n## Intel report {report_id}\n\n_{note}_")
        else:
            print(f"\n{BOLD}{'=' * 92}{RESET}\n{BOLD}Intel report {report_id}{RESET}")
            print(f"  {DIM}{note}{RESET}")
        return
    facts = [("Actors", rep["actors"]), ("Target industries", rep["industries"]),
             ("Target countries", rep["countries"]), ("Motivations", rep["motivations"])]
    if as_md:
        print(f"\n## {rep['name']}\n")
        meta = " \u00b7 ".join(x for x in (rep["type"], f"published {rep['when']}" if rep["when"] else "",
                                          f"id {rep['id']}") if x)
        print(f"_{meta}_\n")
        for label, vals in facts:
            if vals:
                print(f"**{label}:** {', '.join(vals)}  ")
        if rep["url"]:
            print(f"**Falcon console:** {rep['url']}  ")
        print()
        print(rep["body"] if rep["body"] else
              "_This report has no inline text; use --report-pdf for the full document._")
        return
    print(f"\n{BOLD}{'=' * 92}{RESET}\n{BOLD}{rep['name']}{RESET}")
    meta = "  ".join(x for x in (rep["type"], rep["when"], f"id {rep['id']}") if x)
    print(f"  {DIM}{meta}{RESET}")
    for label, vals in facts:
        if vals:
            print(f"  {BOLD}{label}:{RESET} " + "  ".join(f"{TAG}{v}{RESET}" for v in vals))
    if rep["url"]:
        print(f"  {BOLD}Falcon console:{RESET} {DIM}{rep['url']}{RESET}")
    print()
    if rep["body"]:
        for line in rep["body"].splitlines():
            print(f"  {line}")
    else:
        print(f"  {DIM}This report has no inline text; use --report-pdf {report_id} "
              f"for the full document.{RESET}")


def save_report_pdf(intel, report_id, as_md):
    resp = intel.get_report_pdf(id=str(report_id))
    if isinstance(resp, (bytes, bytearray)):
        path = f"intel-report-{report_id}.pdf"
        with open(path, "wb") as f:
            f.write(resp)
        msg = f"Saved PDF: {path} ({len(resp):,} bytes)"
        print(f"\n{msg}" if as_md else f"\n{BOLD}{msg}{RESET}")
        return
    sc = resp.get("status_code", 0) if isinstance(resp, dict) else 0
    if sc in (401, 403):
        note = "no access (client needs the Reports (Falcon Intelligence): READ scope)"
    elif sc == 404:
        note = f"no PDF is available for report {report_id}"
    else:
        note = f"Intel API error (HTTP {sc})"
    print(f"\nCould not download the PDF: {note}")


# ===========================================================================
# Markdown output  (--md)
# ===========================================================================

def mdcell(value, default="-"):
    """Make a value safe for a Markdown table cell."""
    s = str(value) if value not in (None, "") else default
    return s.replace("|", "\\|").replace("\n", " ").strip()


def render_hosts_md(hosts, description, show_aid, show_login):
    print(f"## Hosts \u2014 {description}\n")
    print(f"*{len(hosts)} match{'' if len(hosts) == 1 else 'es'}*\n")
    if not hosts:
        print("_No matching hosts found._")
        return
    hosts.sort(key=lambda h: (h.get("hostname") or "").lower())
    cols = ["Hostname", "Local IP", "OS Version", "Type", "Manufacturer"]
    if show_login:
        cols.append("Last Login User")
    cols.append("Last Seen")
    if show_aid:
        cols.append("Agent ID")
    print("| " + " | ".join(cols) + " |")
    print("|" + "|".join([" --- "] * len(cols)) + "|")
    for h in hosts:
        cells = [mdcell(h.get("hostname")), mdcell(h.get("local_ip")),
                 mdcell(h.get("os_version")), mdcell(h.get("product_type_desc")),
                 mdcell(h.get("system_manufacturer"))]
        if show_login:
            cells.append(mdcell(h.get("last_login_user"), default=""))
        cells.append(mdcell((h.get("last_seen") or "")[:10]))
        if show_aid:
            cells.append(mdcell(h.get("device_id"), default=""))
        print("| " + " | ".join(cells) + " |")


def tenable_for_host_md(host, days, headers, want_ports, want_vulns, sev_show=None, sev_label=""):
    name = host.get("hostname") or ""
    ip = host.get("local_ip") or ""
    asset = None
    for target in (name, ip):
        if target:
            asset = tio_find_asset(target, headers)
            if asset:
                break

    print(f"\n### {name or ip or '(unknown)'} ({ip})\n")
    if not asset:
        print("_Not found in Tenable (no matching asset)._")
        return

    tags = tio_asset_tags(asset["id"], headers)
    vulns = tio_asset_vulns(asset["id"], days, headers)
    print("**Tags:** " + (", ".join(tags) if tags else "_(none)_") + "\n")

    if want_ports:
        ports = tio_asset_ports(asset["id"], vulns, headers)
        if ports:
            print(f"**Open ports ({len(ports)}):** " + ", ".join(fmt_ports(ports)) + "\n")
        else:
            print(f"**Open ports:** _none detected in the last {days} days._\n")

    if want_vulns:
        shown = vulns if sev_show is None else [v for v in vulns if v.get("severity", 0) in sev_show]
        hidden = len(vulns) - len(shown)
        if not shown:
            extra = f" matching {sev_label}" if sev_label else ""
            print(f"_No vulnerabilities{extra} in the last {days} days"
                  + (f" ({hidden} other finding(s) filtered out)" if hidden else "") + "._")
            return
        vulns = shown
        vulns.sort(key=lambda v: (-v.get("severity", 0), v.get("plugin_name", "")))
        tally = {4: 0, 3: 0, 2: 0, 1: 0, 0: 0}
        for v in vulns:
            tally[v.get("severity", 0)] = tally.get(v.get("severity", 0), 0) + 1
        levels = [s for s in (4, 3, 2, 1, 0) if sev_show is None or s in sev_show]
        summary = " \u00b7 ".join(f"{SEV[s][0].title()}: {tally[s]}" for s in levels)
        hidden_note = f" \u00b7 _{hidden} other finding(s) hidden_" if hidden else ""
        print(f"**{summary} \u00b7 Total: {len(vulns)}**{hidden_note}\n")
        print("| Severity | Plugin | Vulnerability | Family |")
        print("| --- | --- | --- | --- |")
        for v in vulns:
            label_s = SEV.get(v.get("severity", 0), ("?", ""))[0].title()
            print(f"| {label_s} | {mdcell(v.get('plugin_id'))} | "
                  f"{mdcell(v.get('plugin_name'))} | {mdcell(v.get('plugin_family'))} |")


# ===========================================================================
# Main
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(description="Find Falcon hosts; optionally show Tenable vulnerabilities.")
    ap.add_argument("term", nargs="*", help="an IP, hostname, or OS/type (e.g. Windows, 'Windows Server')")
    ap.add_argument("--user", help="hosts where this user recently logged in, e.g. --user john "
                                    "(matches the Last Login User column; add a term to narrow/speed it up)")
    ap.add_argument("--vulns", action="store_true", help="also pull each host's vulnerabilities from Tenable")
    ap.add_argument("--min-severity", dest="min_severity", default="", metavar="LEVELS",
                    help="Tenable severities to show. One level = that level and above "
                         "('medium'). A comma list = exactly those levels ('critical,high'). "
                         "Levels: critical, high, medium, low, info.")
    ap.add_argument("--ports", action="store_true", help="also show each host's open ports from Tenable")
    ap.add_argument("--apps", action="store_true",
                    help="also show each host's installed applications (CrowdStrike Discover)")
    ap.add_argument("--detections", action="store_true",
                    help="also show each host's recent detections (CrowdStrike Alerts API)")
    ap.add_argument("--intel-actors", nargs="?", const="", default=None, metavar="QUERY",
                    help="threat intel: list/search actors (standalone; no host search needed)")
    ap.add_argument("--intel-reports", nargs="?", const="", default=None, metavar="QUERY",
                    help="threat intel: list/search reports (standalone; no host search needed)")
    ap.add_argument("--report", metavar="ID",
                    help="read one intel report in the terminal (get the ID from --intel-reports)")
    ap.add_argument("--report-pdf", metavar="ID", dest="report_pdf",
                    help="save one intel report as a PDF file (intel-report-ID.pdf)")
    ap.add_argument("--days", type=int, default=90, help="Tenable look-back window in days (default 90)")
    ap.add_argument("--no-login", action="store_true", help="skip the Falcon login-user lookup (faster)")
    ap.add_argument("--aid", action="store_true", help="also show the Falcon Agent ID")
    ap.add_argument("--md", "--markdown", action="store_true", dest="md",
                    help="output as Markdown (e.g. redirect to a file: ... --md > report.md)")
    args = ap.parse_args()

    intel_wanted = (args.intel_actors is not None or args.intel_reports is not None
                    or args.report or args.report_pdf)
    host_search = bool(args.term or args.user)
    if not host_search and not intel_wanted:
        ap.error("provide a search term (IP / hostname / OS), --user NAME, "
                 "or a threat-intel flag (--intel-actors / --intel-reports / --report / --report-pdf)")

    for flag, val in (("--report", args.report), ("--report-pdf", args.report_pdf)):
        if val and not val.isdigit():
            ap.error(f"{flag} takes a numeric report ID (see the ID column in --intel-reports)")

    try:
        sev_show, sev_label = parse_severities(args.min_severity)
    except ValueError as e:
        ap.error(str(e))

    if not args.md:
        enable_ansi_on_windows()
    # In user mode the login data IS the search, so always show that column.
    show_login = True if args.user else (not args.no_login)

    hosts = []
    if host_search:
        # Step 1: resolve hosts -- either a normal IP/hostname/OS search, or a user lookup.
        try:
            falcon = get_falcon_client()
            if args.user:
                scope_term = " ".join(args.term)
                if not scope_term:
                    print("Searching all hosts for that login user. Add a term "
                          "(e.g. a platform, OS, or subnet) to narrow and speed this up.")
                hosts, description, scanned_all = hosts_by_user(falcon, args.user, scope_term)
                # hosts_by_user already populated login data for matching.
            else:
                fql, description = build_filter(" ".join(args.term))
                hosts = search_hosts(falcon, fql)
                if show_login and hosts:
                    add_login_users(falcon, hosts)
        except RuntimeError as e:
            print(f"\nError: {e}")
            sys.exit(1)

        if args.md:
            render_hosts_md(hosts, description, args.aid, show_login)
        else:
            render_hosts(hosts, description, args.aid, show_login)

    # Step 2: Tenable lookups (open ports and/or vulnerabilities).
    if (args.vulns or args.ports) and hosts:
        headers = tio_headers()
        wanted = " + ".join(w for w, on in (("open ports", args.ports), ("vulnerabilities", args.vulns)) if on)
        floor = f", {sev_label} only" if (args.vulns and sev_label) else ""
        if args.md:
            print(f"\n## Tenable: {wanted} (last {args.days} days{floor})")
        else:
            print(f"\n{BOLD}{'=' * 92}{RESET}")
            print(f"{BOLD}Tenable: {wanted} (last {args.days} days{floor}){RESET}")
        for h in hosts:
            try:
                if args.md:
                    tenable_for_host_md(h, args.days, headers, args.ports, args.vulns, sev_show, sev_label)
                else:
                    print_tenable_for_host(h, args.days, headers, args.ports, args.vulns, sev_show, sev_label)
            except requests.HTTPError as e:
                code = e.response.status_code
                if code in (401, 403):
                    print(f"\nTenable auth failed (HTTP {code}). Check TIO keys / permissions.")
                    break
                print(f"  Tenable HTTP {code}: {e.response.text[:120]}")
            except requests.RequestException as e:
                print(f"  Could not reach Tenable: {e}")

    # Step 3: Installed applications (--apps) via CrowdStrike Discover.
    if args.apps and hosts:
        try:
            discover = get_discover_client()
        except RuntimeError as e:
            print(f"\nError: {e}")
            discover = None
        if discover is not None:
            if args.md:
                print("\n## Installed applications (CrowdStrike Discover)")
            else:
                print(f"\n{BOLD}{'=' * 92}{RESET}")
                print(f"{BOLD}Installed applications (CrowdStrike Discover){RESET}")
            for h in hosts:
                if args.md:
                    apps_for_host_md(h, discover)
                else:
                    print_apps_for_host(h, discover)
    # Step 4: Endpoint detections (--detections) via the Alerts API, per host.
    if args.detections and hosts:
        try:
            alerts = get_alerts_client()
        except RuntimeError as e:
            print(f"\nError: {e}")
            alerts = None
        if alerts is not None:
            if args.md:
                print(f"\n## Endpoint detections (last {args.days} days)")
            else:
                print(f"\n{BOLD}{'=' * 92}{RESET}")
                print(f"{BOLD}Endpoint detections (last {args.days} days){RESET}")
            for h in hosts:
                if args.md:
                    detections_for_host_md(h, alerts, args.days)
                else:
                    print_detections_for_host(h, alerts, args.days)
    elif args.detections and host_search and not hosts:
        pass  # no hosts matched; nothing to look up

    # Step 5: Threat intel (standalone; runs with or without a host search).
    if intel_wanted:
        try:
            intel = get_intel_client()
        except RuntimeError as e:
            print(f"\nError: {e}")
            intel = None
        if intel is not None:
            if args.intel_actors is not None:
                print_intel_actors(intel, args.intel_actors.strip(), args.md)
            if args.intel_reports is not None:
                print_intel_reports(intel, args.intel_reports.strip(), args.md)
            if args.report:
                print_report(intel, args.report, args.md)
            if args.report_pdf:
                save_report_pdf(intel, args.report_pdf, args.md)
    print()


if __name__ == "__main__":
    main()

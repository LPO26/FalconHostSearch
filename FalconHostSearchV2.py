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

Setup (two dependencies, python required):
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

Falcon client needs "Hosts: READ" for searching. The only write action is
--tag / --untag (Falcon grouping tags), which needs "Hosts: WRITE" and prompts
to confirm. Everything else is read-only.
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


VERSION_RE = re.compile(r"^\d+(\.\d+)*$")
# Words that signal an OS/type phrase (so it stays one search, not split into
# separate targets). Built from the platform/type vocabulary plus common OS
# names that appear in os_version strings.
PHRASE_HINTS = set(PLATFORMS) | set(TYPE_WORDS) | {
    "domain", "controller", "enterprise", "datacenter", "professional", "pro",
    "ubuntu", "debian", "centos", "rhel", "redhat", "red", "hat", "fedora",
    "suse", "opensuse", "rocky", "alma", "amazon", "oracle", "windows", "win",
}


def _phrase_token(tok):
    """True if a token suggests its segment is an OS/type phrase, not a host."""
    if tok.lower() in PHRASE_HINTS:
        return True
    # a bare or dotted version number (e.g. 22.04, 10, 2019) -- but not an IP
    return bool(VERSION_RE.match(tok)) and not IP_RE.match(tok)


def parse_targets(term_list):
    """Split the positional argument into one or more search targets.

    Commas always separate targets. Within a segment, multiple whitespace-
    separated tokens are also split into separate targets (so "web01 web02" or
    "1.1.1.1 8.8.8.8" become two searches) UNLESS the segment looks like an OS
    phrase -- i.e. it contains a platform/type keyword or a version number
    ("Windows Server", "Ubuntu 22.04") -- in which case it stays a single search.
    Quote a phrase to force it to stay whole.
    """
    targets = []
    for seg in (s.strip() for s in " ".join(term_list or []).split(",")):
        if not seg:
            continue
        toks = seg.split()
        if len(toks) > 1 and not any(_phrase_token(t) for t in toks):
            targets.extend(toks)          # host / IP list -> separate targets
        else:
            targets.append(seg)           # single token, or an OS phrase
    return targets


TAG_OK_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def normalize_tags(raw_list):
    """Flatten repeated/comma-separated --tag values into a clean list."""
    tags = []
    for item in raw_list or []:
        for t in str(item).split(","):
            t = t.strip()
            if t and t not in tags:
                tags.append(t)
    return tags


def apply_tags(falcon, hosts, tags, action, assume_yes):
    """Add or remove Falcon grouping tags on the matched hosts. WRITE action.

    Requires Hosts: WRITE. Prompts for confirmation unless assume_yes. FalconPy
    prepends the FalconGroupingTags/ prefix, so plain tag names are fine."""
    bad = [t for t in tags if not TAG_OK_RE.match(t)]
    if bad:
        print(f"\nInvalid tag name(s): {', '.join(bad)}. Use letters, numbers, "
              f"hyphens, or underscores -- no spaces or slashes.")
        return
    aids = [h.get("device_id") for h in hosts if h.get("device_id")]
    if not aids:
        print("\nNo hosts with an agent ID to tag.")
        return

    verb = "add" if action == "add" else "remove"
    prep = "to" if action == "add" else "from"
    names = ", ".join((h.get("hostname") or h.get("local_ip") or "?") for h in hosts[:10])
    more = f" (+{len(aids) - 10} more)" if len(aids) > 10 else ""
    print(f"\n{BOLD}About to {verb} grouping tag(s) {tags} {prep} {len(aids)} host(s):{RESET} {names}{more}")
    print(f"{DIM}This modifies hosts in Falcon. Grouping tags can change dynamic host-group "
          f"membership, which can affect policy assignment. Requires Hosts: WRITE.{RESET}")

    if not assume_yes:
        try:
            ans = input("Proceed? [y/N] ").strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("y", "yes"):
            print("Aborted. No changes made.")
            return

    updated, errors = 0, []
    for i in range(0, len(aids), 500):  # API accepts up to 500 IDs per call
        batch = aids[i:i + 500]
        resp = falcon.update_device_tags(action_name=action, ids=batch, tags=tags)
        sc = resp["status_code"]
        if sc >= 400:
            errs = resp["body"].get("errors") or [{}]
            if sc in (401, 403):
                errors.append("no access -- the client needs the Hosts: WRITE scope")
                break
            errors.append(errs[0].get("message", f"HTTP {sc}"))
            continue
        res = resp["body"].get("resources") or []
        updated += sum(1 for r in res if r.get("updated", True)) if res else len(batch)

    if updated:
        done = "added to" if action == "add" else "removed from"
        print(f"{BOLD}Done: tag(s) {done} {updated} host(s).{RESET}")
    if errors:
        for e in errors:
            print(f"  {DIM}{e}{RESET}")
    elif not updated:
        print("No hosts were updated.")


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


def host_tags(host):
    """Grouping / sensor tag names on a host, with the API prefix stripped."""
    out = []
    for t in host.get("tags") or []:
        name = t.split("/", 1)[-1] if "/" in t else t
        if name:
            out.append(name)
    return out


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


def parse_os_spec(words):
    """Turn --os words into {platform, ptype, version} using the same vocabulary
    as build_filter. Leftover words become an os_version 'contains' match."""
    text = " ".join(words or []).strip()
    rem = f" {text.lower()} "
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
    return {"platform": platform, "ptype": ptype, "version": rem.strip(), "raw": text}


def os_spec_desc(spec):
    parts = [p for p in (spec.get("platform"), spec.get("ptype")) if p]
    if spec.get("version"):
        parts.append(f"os~'{spec['version']}'")
    return " ".join(parts) or spec.get("raw", "")


def os_server_filter(spec):
    """FQL for a standalone --os search (no positional target)."""
    clauses = []
    if spec.get("platform"):
        clauses.append(f"platform_name:'{spec['platform']}'")
    if spec.get("ptype"):
        clauses.append(f"product_type_desc:'{spec['ptype']}'")
    if spec.get("version"):
        clauses.append(f"os_version:*'*{spec['version']}*'")
    return "+".join(clauses)


def os_match(host, spec):
    """Client-side check that a host satisfies the --os spec (used when a
    hostname/IP target is also given, so we don't fight FQL precedence)."""
    if spec.get("platform") and (host.get("platform_name") or "") != spec["platform"]:
        return False
    if spec.get("ptype") and (host.get("product_type_desc") or "") != spec["ptype"]:
        return False
    if spec.get("version") and spec["version"].lower() not in (host.get("os_version") or "").lower():
        return False
    return True


def build_target_filter(term):
    """Hostname/IP-only filter, used when --os supplies the OS constraints
    separately (so the positional is treated purely as a host/IP)."""
    t = term.strip()
    if IP_RE.match(t):
        return f"local_ip:'{t}',external_ip:'{t}'", f"IP = {t}"
    return f"hostname:*'*{t}*'", f"hostname contains '{t}'"


# ---- combined attribute criteria: --os and --manufacturer ------------------

def criteria_server_filter(os_spec, manuf, tag=None):
    """ANDed FQL for a standalone attribute search (no positional target)."""
    clauses = []
    if os_spec:
        f = os_server_filter(os_spec)
        if f:
            clauses.append(f)
    if manuf:
        clauses.append(f"system_manufacturer:*'*{manuf}*'")
    if tag:
        clauses.append(f"tags:*'*{tag}*'")
    return "+".join(clauses)


def criteria_match(host, os_spec, manuf, tag=None, tag_none=False):
    """Client-side check that a host satisfies the --os / --manufacturer /
    --tag-search filters (used when a hostname/IP or user match is also in play)."""
    if os_spec and not os_match(host, os_spec):
        return False
    if manuf and manuf.lower() not in (host.get("system_manufacturer") or "").lower():
        return False
    if tag_none and host_tags(host):
        return False
    if tag and not any(tag.lower() in t.lower() for t in host_tags(host)):
        return False
    return True


def criteria_desc(os_spec, manuf, tag=None, tag_none=False):
    parts = []
    if os_spec:
        parts.append(f"OS {os_spec_desc(os_spec)}")
    if manuf:
        parts.append(f"manufacturer~'{manuf}'")
    if tag_none:
        parts.append("no tags")
    elif tag:
        parts.append(f"tag~'{tag}'")
    return " + ".join(parts)


def read_target_file(path):
    """Read a list of IPs/hostnames from a text file (one per line; blank lines
    and #-comments ignored; comma/space-separated entries on a line are split)."""
    targets = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                targets.extend(parse_targets([line]))
    except OSError as e:
        raise RuntimeError(f"could not read list file '{path}': {e}")
    return targets


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


def render_hosts(hosts, description, show_aid, show_login, show_tags=False, show_domain=False):
    print(f"\n{BOLD}Search:{RESET} {description}")
    if not hosts:
        print("No matching hosts found.\n")
        return
    hosts.sort(key=lambda h: (h.get("hostname") or "").lower())
    cols = ""
    if show_tags:
        cols += f"{'TAGS':<26} "
    cols += f"{'HOSTNAME':<20} {'LOCAL IP':<15} {'OS VERSION':<20} {'TYPE':<11} {'MANUFACTURER':<16}"
    if show_domain:
        cols += f" {'AD DOMAIN':<24}"
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
        row = ""
        if show_tags:
            tags = ", ".join(host_tags(h))
            row += f"{TAG}{clip(tags, 26):<26}{RESET} " if tags else f"{DIM}{'-':<26}{RESET} "
        row += (f"{clip(h.get('hostname'), 20):<20} "
                f"{clip(h.get('local_ip'), 15):<15} "
                f"{clip(h.get('os_version'), 20):<20} "
                f"{clip(h.get('product_type_desc'), 11):<11} "
                f"{clip(h.get('system_manufacturer'), 16):<16}")
        if show_domain:
            dom = h.get("machine_domain") or ""
            row += f" {clip(dom, 24):<24}" if dom else f" {DIM}{'-':<24}{RESET}"
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


def discover_unmanaged(discover, extra_fql, limit=100, cap=5000):
    """Unmanaged assets (seen by Falcon, no sensor). Returns (assets, note).

    The Discover query endpoint caps limit at 100 per page, so we page through."""
    filt = "entity_type:'unmanaged'" + (f"+{extra_fql}" if extra_fql else "")
    limit = max(1, min(limit, 100))
    ids, offset = [], 0
    while True:
        r = discover.query_hosts(filter=filt, limit=limit, offset=offset)
        sc = r["status_code"]
        if sc in (401, 403):
            return None, "no access (client needs the Discover: READ scope / Discover licensing)"
        if sc >= 400:
            errs = (r["body"].get("errors") or [{}])
            return None, f"Discover API error: {errs[0].get('message', f'HTTP {sc}')}"
        batch = r["body"].get("resources") or []
        ids.extend(batch)
        total = r["body"].get("meta", {}).get("pagination", {}).get("total", len(ids))
        offset += len(batch)
        if not batch or offset >= total or len(ids) >= cap:
            break
    if not ids:
        return [], None
    assets = []
    for i in range(0, len(ids), 100):
        d = discover.get_hosts(ids=ids[i:i + 100])
        if d["status_code"] < 400:
            assets.extend(d["body"].get("resources") or [])
    assets.sort(key=lambda a: (a.get("hostname") or "").lower())
    return assets, None


def _disc_ip(a):
    if a.get("current_local_ip"):
        return a["current_local_ip"]
    for key in ("local_ip_addresses", "local_ips"):
        v = a.get(key) or []
        if v:
            return v[0]
    for ni in a.get("network_interfaces") or []:
        if ni.get("local_ip"):
            return ni["local_ip"]
    return ""


def render_discover(assets, description, as_md):
    if as_md:
        print(f"## Unmanaged assets \u2014 {description}\n")
        print(f"*{len(assets)} asset{'' if len(assets) == 1 else 's'} without a Falcon sensor*\n")
        if not assets:
            print("_None found._")
            return
        print("| Hostname | Local IP | OS Version | Type | Manufacturer | AD Domain | Last Seen | Seen By | Internet |")
        print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for a in assets:
            print(f"| {mdcell(a.get('hostname'))} | {mdcell(_disc_ip(a), default='')} | "
                  f"{mdcell(a.get('os_version'), default='')} | {mdcell(a.get('product_type_desc'), default='')} | "
                  f"{mdcell(a.get('system_manufacturer'), default='')} | "
                  f"{mdcell(a.get('machine_domain'), default='')} | "
                  f"{mdcell((a.get('last_seen_timestamp') or '')[:10], default='')} | "
                  f"{mdcell(a.get('discoverer_count'), default='')} | "
                  f"{mdcell(a.get('internet_exposure'), default='')} |")
        return

    print(f"\n{BOLD}Discover (unmanaged assets):{RESET} {description}")
    if not assets:
        print("No unmanaged assets found.\n")
        return
    cols = (f"{'HOSTNAME':<24} {'LOCAL IP':<15} {'OS VERSION':<22} {'TYPE':<12} "
            f"{'MANUFACTURER':<18} {'AD DOMAIN':<22} {'LAST SEEN':<11} {'SEEN BY':<8} {'INTERNET':<10}")
    width = len(cols) + 4
    print(f"{BOLD}Assets without a Falcon sensor: {len(assets)}{RESET}")
    print("-" * width)
    print(f"{BOLD}{cols}{RESET}")
    print("-" * width)
    for a in assets:
        seen_by = a.get("discoverer_count")
        dom = a.get("machine_domain") or ""
        print(f"{clip(a.get('hostname'), 24):<24} "
              f"{clip(_disc_ip(a), 15):<15} "
              f"{clip(a.get('os_version'), 22):<22} "
              f"{clip(a.get('product_type_desc'), 12):<12} "
              f"{clip(a.get('system_manufacturer'), 18):<18} "
              f"{clip(dom, 22):<22} "
              f"{(a.get('last_seen_timestamp') or '')[:10]:<11} "
              f"{DIM}{str(seen_by if seen_by is not None else ''):<8}{RESET} "
              f"{DIM}{clip(a.get('internet_exposure'), 10):<10}{RESET}")
    print("-" * width)
    print(f"{len(assets)} unmanaged asset(s)")


def _csv_path(prefix, given):
    if given:
        return given if given.lower().endswith(".csv") else given + ".csv"
    return f"{prefix}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"


def render_hosts_csv(hosts, path, show_login=True):
    import csv
    out = _csv_path("falcon-hosts", path)
    cols = ["Hostname", "Local IP", "OS Version", "Type", "Manufacturer", "AD Domain",
            "Last Login User", "Last Seen", "Tags", "Agent ID"]
    try:
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for h in sorted(hosts, key=lambda x: (x.get("hostname") or "").lower()):
                w.writerow([h.get("hostname", ""), h.get("local_ip", ""), h.get("os_version", ""),
                            h.get("product_type_desc", ""), h.get("system_manufacturer", ""),
                            h.get("machine_domain", ""),
                            h.get("last_login_user", "") if show_login else "",
                            (h.get("last_seen") or "")[:19].replace("T", " "),
                            "; ".join(host_tags(h)), h.get("device_id", "")])
    except OSError as e:
        print(f"\nCould not write CSV: {e}")
        return
    print(f"\nSaved {len(hosts)} host(s) to {out}")


def render_discover_csv(assets, path):
    import csv
    out = _csv_path("falcon-unmanaged", path)
    cols = ["Hostname", "Local IP", "OS Version", "Type", "Manufacturer", "AD Domain",
            "Last Seen", "First Seen", "Seen By", "Internet Exposure", "Entity ID"]
    try:
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for a in assets:
                w.writerow([a.get("hostname", ""), _disc_ip(a), a.get("os_version", ""),
                            a.get("product_type_desc", ""), a.get("system_manufacturer", ""),
                            a.get("machine_domain", ""),
                            (a.get("last_seen_timestamp") or "")[:19].replace("T", " "),
                            (a.get("first_seen_timestamp") or "")[:19].replace("T", " "),
                            a.get("discoverer_count", ""), a.get("internet_exposure", ""),
                            a.get("id", "")])
    except OSError as e:
        print(f"\nCould not write CSV: {e}")
        return
    print(f"\nSaved {len(assets)} unmanaged asset(s) to {out}")


def run_discover(args):
    """Standalone Discover mode (--discover): list unmanaged assets, optionally
    filtered by --os / --manufacturer / a hostname term."""
    try:
        disc = get_discover_client()
    except RuntimeError as e:
        print(f"\nError: {e}")
        return
    os_spec = parse_os_spec(args.os) if args.os else None
    manuf = " ".join(args.manufacturer).strip() if args.manufacturer else None
    term = " ".join(args.term).strip()
    extra = criteria_server_filter(os_spec, manuf, None)
    if term:
        extra = (extra + "+" if extra else "") + f"hostname:*'*{term}*'"
    desc_bits = ["all"] if not (os_spec or manuf or term) else []
    if term:
        desc_bits.append(f"hostname~'{term}'")
    cd = criteria_desc(os_spec, manuf, None)
    if cd:
        desc_bits.append(cd)
    description = ", ".join(desc_bits) or "all"
    assets, note = discover_unmanaged(disc, extra)
    if assets is None:
        print(f"\n{BOLD}Discover (unmanaged assets){RESET}\n  {DIM}{note}{RESET}")
        return
    if args.csv is not None:
        render_discover_csv(assets, args.csv or None)
    else:
        render_discover(assets, description, args.md)


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
# Real Time Response -- READ-ONLY visibility only
# ===========================================================================
# This tool NEVER opens an RTR session or runs a command on a host. It only
# reads session audit history and shows, from data already fetched, whether a
# host would currently be reachable. Opening sessions and running commands is
# left to the Falcon console, where per-command auditing and role controls live.

def get_rtr_audit_client():
    from falconpy import RealTimeResponseAudit
    cid = os.environ.get("FALCON_CLIENT_ID", "")
    secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not cid or not secret:
        raise RuntimeError("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET first.")
    return RealTimeResponseAudit(client_id=cid, client_secret=secret,
                                 base_url=os.environ.get("FALCON_CLOUD", "us1"))


def _rtr_commands(session):
    """Pull command strings out of a session record (shape varies)."""
    out = []
    for c in (session.get("commands") or session.get("Commands") or []):
        if isinstance(c, str):
            out.append(c)
        elif isinstance(c, dict):
            out.append(c.get("command_string") or c.get("base_command")
                       or c.get("command") or "")
    return [c for c in out if c]


def rtr_audit(audit, query, limit=20):
    """Read recent RTR session audit records. Returns (rows, total, note).
    Optional query filters by hostname (contains)."""
    # This endpoint rejects most sort keys, so we don't send one -- we sort the
    # results ourselves below. with_command_info enriches records with hostname
    # and the commands that were run.
    kwargs = {"limit": limit, "with_command_info": "true"}
    if query:
        kwargs["filter"] = f"hostname:*'*{query}*'"
    resp = audit.audit_sessions(**kwargs)
    sc = resp["status_code"]
    if sc in (401, 403):
        return [], 0, "no access (client needs the Real time response audit: READ scope)"
    if sc >= 400:
        errs = (resp["body"].get("errors") or [{}])
        return [], 0, f"RTR audit API error: {errs[0].get('message', f'HTTP {sc}')}"
    body = resp["body"]
    records = body.get("resources") or []
    total = body.get("meta", {}).get("pagination", {}).get("total", len(records))
    rows = []
    for s in records:
        start = s.get("start_timestamp") or s.get("created_at") or s.get("start") or ""
        cmds = _rtr_commands(s)
        rows.append({
            "when": str(start)[:19].replace("T", " "),
            "host": s.get("hostname") or s.get("aid") or "(unknown)",
            "user": s.get("username") or s.get("user_name") or s.get("user_uuid") or "",
            "commands": cmds,
        })
    rows.sort(key=lambda r: r["when"], reverse=True)   # newest first, client-side
    return rows, total, None


def print_rtr_audit(audit, query, as_md, limit=20):
    rows, total, note = rtr_audit(audit, query, limit)
    heading = "RTR session audit" + (f" for hosts matching \u201c{query}\u201d" if query else "")
    if as_md:
        print(f"\n## {heading}\n")
        if note:
            print(f"_{note}_")
            return
        if not rows:
            print("_No RTR sessions found in the audit history._")
            return
        print(f"_{commas(total)} session(s); showing {len(rows)}. Read-only audit view._\n")
        print("| When | Host | User | Commands run |")
        print("| --- | --- | --- | --- |")
        for r in rows:
            cmds = ", ".join(r["commands"][:6]) + (" \u2026" if len(r["commands"]) > 6 else "")
            print(f"| {r['when']} | {mdcell(r['host'])} | {mdcell(r['user'], default='')} | {mdcell(cmds, default='(none)')} |")
        return
    print(f"\n{BOLD}{'=' * 92}{RESET}\n{BOLD}{heading}{RESET} {DIM}(read-only){RESET}")
    if note:
        print(f"  {DIM}{note}{RESET}")
        return
    if not rows:
        print(f"  {DIM}No RTR sessions found in the audit history.{RESET}")
        return
    print(f"  {DIM}{commas(total)} session(s); showing {len(rows)}{RESET}")
    for r in rows:
        head = f"  {DIM}{r['when']}{RESET}  {CYAN}{r['host']}{RESET}"
        if r["user"]:
            head += f"  {DIM}by {r['user']}{RESET}"
        print(head)
        if r["commands"]:
            shown = r["commands"][:6]
            for cmd in shown:
                print(f"      {DIM}${RESET} {clip(cmd, 84)}")
            if len(r["commands"]) > 6:
                print(f"      {DIM}... {len(r['commands']) - 6} more{RESET}")
        else:
            print(f"      {DIM}(no commands recorded){RESET}")


# ---- RTR readiness (derived from host data already fetched; opens nothing) ----

def rtr_readiness(host):
    """Would RTR reach this host right now? Informational, from last-seen and
    sensor state. Returns (verdict, color, details)."""
    from datetime import datetime, timezone
    last = host.get("last_seen") or ""
    age_txt, online = "unknown", False
    if last:
        try:
            seen = datetime.fromisoformat(last.replace("Z", "+00:00"))
            mins = (datetime.now(timezone.utc) - seen).total_seconds() / 60
            online = mins <= 60
            if mins < 60:
                age_txt = f"{int(mins)}m ago"
            elif mins < 1440:
                age_txt = f"{int(mins / 60)}h ago"
            else:
                age_txt = f"{int(mins / 1440)}d ago"
        except ValueError:
            pass
    status = (host.get("status") or "normal").lower()
    rfm = (host.get("reduced_functionality_mode") or "no").lower()
    details = [f"seen {age_txt}", host.get("platform_name", ""),
               f"status: {status}", f"RFM: {rfm}"]
    details = [d for d in details if d]
    if rfm == "yes":
        return "LIMITED", SEV[2][1], details + ["(RFM restricts RTR)"]
    if not online:
        return "OFFLINE?", SEV[1][1], details
    if status not in ("normal", "lift_containment_pending"):
        return "CONTAINED", SEV[3][1], details
    return "READY", SEV[0][1].replace("245", "71"), details


def print_rtr_ready(hosts, as_md):
    if as_md:
        print("\n## RTR readiness (informational; no session is opened)\n")
        print("| Host | Readiness | Details |")
        print("| --- | --- | --- |")
        for h in hosts:
            verdict, _, details = rtr_readiness(h)
            name = h.get("hostname") or h.get("local_ip") or "(unknown)"
            print(f"| {mdcell(name)} | {verdict} | {mdcell(', '.join(details), default='')} |")
        print("\n_Reachability is inferred from last-seen and sensor state, not a live probe. "
              "Open sessions from the Falcon console._")
        return
    print(f"\n{BOLD}{'=' * 92}{RESET}")
    print(f"{BOLD}RTR readiness{RESET} {DIM}(informational; no session is opened){RESET}")
    for h in hosts:
        verdict, color, details = rtr_readiness(h)
        name = h.get("hostname") or h.get("local_ip") or "(unknown)"
        print(f"  {color}{verdict:<9}{RESET} {BOLD}{name:<22}{RESET} {DIM}{'  '.join(details)}{RESET}")
    print(f"  {DIM}Reachability is inferred from last-seen and sensor state, not a live "
          f"probe. Open sessions from the Falcon console.{RESET}")


# ===========================================================================
# Identity Protection: user account info  (--show-userinfo)  -- READ-ONLY
# ===========================================================================
# Requires Falcon Identity Protection (ITP) and the "Identity Protection
# Entities: READ" scope. Resolves the LAST LOGIN USER string to its AD entity
# and shows the account's description and identity context. Read-only.

def get_identity_client():
    from falconpy import IdentityProtection
    cid = os.environ.get("FALCON_CLIENT_ID", "")
    secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not cid or not secret:
        raise RuntimeError("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET first.")
    return IdentityProtection(client_id=cid, client_secret=secret,
                              base_url=os.environ.get("FALCON_CLOUD", "us1"))


def _idp_query(filter_field):
    return ("query ($names: [String!]) { entities(types: [USER], "
            "dataSources: [ACTIVE_DIRECTORY], " + filter_field + ": $names, first: 10) { nodes { "
            "primaryDisplayName secondaryDisplayName riskScoreSeverity "
            "riskFactors { type severity } "
            "isHuman: hasRole(type: HumanUserAccountRole) "
            "isProgrammatic: hasRole(type: ProgrammaticUserAccountRole) "
            "roles { fullPath } "
            "accounts { description "
            "... on ActiveDirectoryAccountDescriptor { samAccountName domain upn ou "
            "department title enabled } } } } }")


def _sam_of(node):
    for a in node.get("accounts") or []:
        if a.get("samAccountName"):
            return a["samAccountName"]
    return ""


def lookup_user_idp(idp, name):
    """Resolve a login-user string to its ITP AD entity. Returns (info, note)."""
    sam = name.replace("/", "\\").split("\\")[-1].strip()
    if not sam:
        return None, "no username to look up"
    body = None
    for field in ("secondaryDisplayNames", "primaryDisplayNames"):
        resp = idp.graphql(body={"query": _idp_query(field), "variables": {"names": [sam]}})
        sc = resp["status_code"]
        if sc in (401, 403):
            return None, "no access (needs Identity Protection Entities: READ and an ITP license)"
        if sc >= 400:
            return None, f"ITP API error (HTTP {sc})"
        b = resp["body"] or {}
        if b.get("errors"):
            return None, "ITP query error: " + (b["errors"][0].get("message", "") or "unknown")
        nodes = (((b.get("data") or {}).get("entities") or {}).get("nodes")) or []
        if nodes:
            body = nodes
            break
    if not body:
        return None, f"no ITP entity found for '{sam}'"
    node = next((n for n in body if _sam_of(n).lower() == sam.lower()), body[0])
    ad, desc = {}, ""
    for a in node.get("accounts") or []:
        if a.get("description") and not desc:
            desc = a["description"]
        if a.get("samAccountName"):
            ad = a
    return {
        "primary": node.get("primaryDisplayName", ""),
        "secondary": node.get("secondaryDisplayName", ""),
        "severity": node.get("riskScoreSeverity", ""),
        "risk_factors": [f"{rf.get('type')} ({rf.get('severity')})"
                         for rf in (node.get("riskFactors") or [])],
        "human": node.get("isHuman"), "programmatic": node.get("isProgrammatic"),
        "roles": [r.get("fullPath", "") for r in (node.get("roles") or []) if r.get("fullPath")],
        "description": desc,
        "sam": ad.get("samAccountName", ""), "domain": ad.get("domain", ""),
        "upn": ad.get("upn", ""), "ou": ad.get("ou", ""),
        "department": ad.get("department", ""), "title": ad.get("title", ""),
        "enabled": ad.get("enabled"),
    }, None


def load_user_notes(path):
    """Alternative annotation source: a local JSON map of {username: note}."""
    import json
    p = path or "user_notes.json"
    if not os.path.exists(p):
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return {str(k).replace("/", "\\").split("\\")[-1].lower(): v for k, v in data.items()}
    except (OSError, ValueError):
        return {}


def print_user_info(idp, name, notes, as_md):
    info, note = (lookup_user_idp(idp, name) if idp else (None, "Identity Protection client unavailable"))
    local = notes.get(name.replace("/", "\\").split("\\")[-1].lower())

    if as_md:
        print(f"\n## User: {name}\n")
        if info:
            ident = " \u00b7 ".join(x for x in (info["sam"] and f"sam: {info['sam']}",
                                               info["domain"] and f"domain: {info['domain']}",
                                               info["upn"] and f"UPN: {info['upn']}") if x)
            print(f"**{info['primary'] or name}**" + (f" \u2014 {ident}" if ident else "") + "\n")
            if info["description"]:
                print(f"**Description (AD, via ITP):** {info['description']}\n")
            kind = "Service/programmatic" if info["programmatic"] else ("Human" if info["human"] else "Unknown")
            meta = [("Type", kind), ("Title", info["title"]), ("Department", info["department"]),
                    ("OU", info["ou"]), ("Risk", info["severity"]),
                    ("Enabled", info["enabled"]), ("Roles", ", ".join(info["roles"]))]
            for k, v in meta:
                if v not in (None, "", []):
                    print(f"- **{k}:** {v}")
            if info["risk_factors"]:
                print(f"- **Risk factors:** {', '.join(info['risk_factors'])}")
        else:
            print(f"_ITP: {note}_")
        if local:
            print(f"\n**Local note:** {local}")
        return

    print(f"\n{BOLD}{'=' * 92}{RESET}\n{BOLD}User: {name}{RESET} {DIM}(read-only){RESET}")
    if info:
        print(f"  {BOLD}{info['primary'] or name}{RESET}")
        idline = "  ".join(x for x in (info["sam"] and f"sam: {info['sam']}",
                                       info["domain"] and f"domain: {info['domain']}",
                                       info["upn"] and f"UPN: {info['upn']}") if x)
        if idline:
            print(f"  {DIM}{idline}{RESET}")
        if info["description"]:
            print(f"  {BOLD}Description:{RESET} {CYAN}{info['description']}{RESET}  {DIM}(AD, via ITP){RESET}")
        else:
            print(f"  {DIM}No description set on the AD account.{RESET}")
        kind = "Service / programmatic" if info["programmatic"] else ("Human" if info["human"] else "Unknown")
        bits = [("Type", kind), ("Title", info["title"]), ("Department", info["department"]),
                ("OU", info["ou"]), ("Risk", info["severity"]),
                ("Enabled", "yes" if info["enabled"] else ("no" if info["enabled"] is False else "")),
                ("Roles", ", ".join(info["roles"]))]
        for k, v in bits:
            if v not in (None, "", []):
                print(f"  {BOLD}{k}:{RESET} {v}")
        if info["risk_factors"]:
            print(f"  {BOLD}Risk factors:{RESET} {DIM}{', '.join(info['risk_factors'])}{RESET}")
    else:
        print(f"  {DIM}ITP: {note}{RESET}")
    if local:
        print(f"  {BOLD}Local note:{RESET} {local}")


# ---- AD user description via Get-ADUser (PowerShell / RSAT) -----------------
# Reads directly from Active Directory -- the system of record for the account
# description -- instead of ITP. Runs on a domain-joined Windows host (or one
# with the ActiveDirectory RSAT module). Read-only: only Get-ADUser is invoked.

SAM_RE = re.compile(r"^[A-Za-z0-9._$-]{1,64}$")   # safe sAMAccountName charset
PROP_RE = re.compile(r"^[A-Za-z0-9]+$")           # safe AD property names
DEFAULT_AD_PROPS = ["Description", "info", "extensionAttribute1"]


def _powershell_exe():
    import shutil
    return (shutil.which("pwsh") or shutil.which("powershell")
            or shutil.which("powershell.exe"))


def get_aduser_description(name, props):
    """Run Get-ADUser for one account and return ({field: value}, note).

    The username is reduced to a sAMAccountName and validated to a safe charset,
    then embedded in a single-quoted PowerShell string -- so no user input can
    break out of the command. Properties are validated too."""
    import subprocess
    import json
    sam = name.replace("/", "\\").split("\\")[-1].strip()
    if not SAM_RE.match(sam):
        return None, "username has characters not valid for an AD sAMAccountName"
    props = [p for p in (props or DEFAULT_AD_PROPS) if PROP_RE.match(p)] or DEFAULT_AD_PROPS
    ps = _powershell_exe()
    if not ps:
        return None, ("PowerShell not found -- Get-ADUser needs Windows PowerShell "
                      "(or pwsh) with the ActiveDirectory RSAT module")
    prop_list = ",".join(props)
    cmd = (f"Get-ADUser -Identity '{sam}' -Properties {prop_list} | "
           f"Select-Object Name,{prop_list} | ConvertTo-Json -Compress")
    try:
        res = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", cmd],
                             capture_output=True, text=True, timeout=45)
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"could not run PowerShell: {e}"
    out, err = (res.stdout or "").strip(), (res.stderr or "").strip()
    if res.returncode != 0 or not out:
        low = err.lower()
        if "cannot find an object" in low or "identity not found" in low:
            return None, f"no AD user found for '{sam}'"
        if "not recognized" in low or "activedirectory" in low or "get-aduser" in low:
            return None, "the ActiveDirectory module (Get-ADUser) isn't available here -- install RSAT"
        return None, (err.splitlines()[0] if err else "Get-ADUser returned no output")
    try:
        data = json.loads(out)
    except ValueError:
        return {"_raw": out}, None
    if isinstance(data, list):   # more than one match
        data = data[0] if data else {}
    return data, None


def print_user_description(name, props, notes, as_md):
    data, note = get_aduser_description(name, props)
    local = notes.get(name.replace("/", "\\").split("\\")[-1].lower())
    fields = props or DEFAULT_AD_PROPS

    if as_md:
        print(f"\n## AD user: {name}\n")
        if data and "_raw" not in data:
            print(f"**{data.get('Name') or name}**\n")
            for f in fields:
                v = data.get(f)
                print(f"- **{f}:** {v if v not in (None, '') else '_(not set)_'}")
        elif data:
            print("```\n" + data["_raw"] + "\n```")
        else:
            print(f"_Get-ADUser: {note}_")
        if local:
            print(f"\n**Local note:** {local}")
        return

    print(f"\n{BOLD}{'=' * 92}{RESET}\n{BOLD}AD user: {name}{RESET} {DIM}(Get-ADUser, read-only){RESET}")
    if data and "_raw" not in data:
        print(f"  {BOLD}{data.get('Name') or name}{RESET}")
        for f in fields:
            v = data.get(f)
            shown = f"{CYAN}{v}{RESET}" if v not in (None, "") else f"{DIM}(not set){RESET}"
            print(f"  {BOLD}{f}:{RESET} {shown}")
    elif data:
        for line in data["_raw"].splitlines():
            print(f"  {line}")
    else:
        print(f"  {DIM}Get-ADUser: {note}{RESET}")
    if local:
        print(f"  {BOLD}Local note:{RESET} {local}")


# ===========================================================================
# Markdown output  (--md)
# ===========================================================================

def mdcell(value, default="-"):
    """Make a value safe for a Markdown table cell."""
    s = str(value) if value not in (None, "") else default
    return s.replace("|", "\\|").replace("\n", " ").strip()


def render_hosts_md(hosts, description, show_aid, show_login, show_tags=False, show_domain=False):
    print(f"## Hosts \u2014 {description}\n")
    print(f"*{len(hosts)} match{'' if len(hosts) == 1 else 'es'}*\n")
    if not hosts:
        print("_No matching hosts found._")
        return
    hosts.sort(key=lambda h: (h.get("hostname") or "").lower())
    cols = ["Tags"] if show_tags else []
    cols += ["Hostname", "Local IP", "OS Version", "Type", "Manufacturer"]
    if show_domain:
        cols.append("AD Domain")
    if show_login:
        cols.append("Last Login User")
    cols.append("Last Seen")
    if show_aid:
        cols.append("Agent ID")
    print("| " + " | ".join(cols) + " |")
    print("|" + "|".join([" --- "] * len(cols)) + "|")
    for h in hosts:
        cells = [mdcell(", ".join(host_tags(h)), default="")] if show_tags else []
        cells += [mdcell(h.get("hostname")), mdcell(h.get("local_ip")),
                  mdcell(h.get("os_version")), mdcell(h.get("product_type_desc")),
                  mdcell(h.get("system_manufacturer"))]
        if show_domain:
            cells.append(mdcell(h.get("machine_domain"), default=""))
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
    ap.add_argument("--os", nargs="+", metavar="WORD", dest="os",
                    help="filter by OS / platform / type, e.g. --os windows 11 or --os windows servers. "
                         "Works alone or alongside a hostname/IP or --user.")
    ap.add_argument("--manufacturer", "--vendor", nargs="+", metavar="WORD", dest="manufacturer",
                    help="filter by system manufacturer, e.g. --manufacturer Dell (contains match). "
                         "Works alone or alongside a hostname/IP, --os, or --user.")
    ap.add_argument("--list", metavar="FILE", dest="list",
                    help="read targets (IPs/hostnames) from a text file, one per line "
                         "(blank lines and #-comments ignored). Combines with any typed targets.")
    ap.add_argument("--tag-search", metavar="TAG", dest="tag_search",
                    help="find hosts that carry this Falcon grouping/sensor tag (contains match). "
                         "Use !* (or 'none'/'untagged') to find hosts with NO tags. "
                         "Works alone or alongside a hostname/IP, --os, --manufacturer, or --user.")
    ap.add_argument("--discover", action="store_true", dest="discover",
                    help="list UNMANAGED assets (seen by Falcon Discover but with no sensor). "
                         "Standalone; optionally filter with --os / --manufacturer / a hostname term.")
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
    ap.add_argument("--rtr-audit", nargs="?", const="", default=None, metavar="HOST",
                    dest="rtr_audit",
                    help="READ-ONLY: show RTR session audit history (who ran what, where, when); "
                         "optional hostname filter. Standalone; no host search needed. "
                         "Never opens a session or runs a command.")
    ap.add_argument("--rtr-ready", action="store_true", dest="rtr_ready",
                    help="show whether each matched host looks reachable for RTR "
                         "(from last-seen and sensor state; opens nothing)")
    ap.add_argument("--tag", action="append", metavar="TAG",
                    help="WRITE: add Falcon grouping tag(s) to the matched hosts "
                         "(needs Hosts: WRITE). Repeatable or comma-separated. Prompts to confirm.")
    ap.add_argument("--untag", action="append", metavar="TAG",
                    help="WRITE: remove Falcon grouping tag(s) from the matched hosts "
                         "(needs Hosts: WRITE). Repeatable or comma-separated. Prompts to confirm.")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="skip the confirmation prompt for --tag / --untag")
    ap.add_argument("--days", type=int, default=90, help="Tenable look-back window in days (default 90)")
    ap.add_argument("--no-login", action="store_true", help="skip the Falcon login-user lookup (faster)")
    ap.add_argument("--aid", action="store_true", help="also show the Falcon Agent ID")
    ap.add_argument("--show-tags", action="store_true", dest="show_tags",
                    help="show the host's Falcon grouping/sensor tags column (hidden by default)")
    ap.add_argument("--show-domain", action="store_true", dest="show_domain",
                    help="show the host's Active Directory domain column (hidden by default)")
    ap.add_argument("--show-userinfo", "--show-user-info", action="store_true", dest="show_userinfo",
                    help="with --user: show that AD account's description and identity context "
                         "from Falcon Identity Protection (read-only; needs ITP)")
    ap.add_argument("--user-notes", metavar="FILE", dest="user_notes",
                    help="path to a local JSON map of {username: note} shown with --show-userinfo "
                         "or --user-description (alternative annotation source; defaults to ./user_notes.json)")
    ap.add_argument("--user-description", action="store_true", dest="user_description",
                    help="with --user: show the AD account's description via Get-ADUser "
                         "(PowerShell/RSAT, read-only). Shows Description, info, extensionAttribute1 by default.")
    ap.add_argument("--user-props", nargs="+", metavar="PROP", dest="user_props",
                    help="AD properties for --user-description (default: Description info extensionAttribute1)")
    ap.add_argument("--md", "--markdown", action="store_true", dest="md",
                    help="output as Markdown (e.g. redirect to a file: ... --md > report.md)")
    ap.add_argument("--csv", nargs="?", const="", default=None, metavar="FILE", dest="csv",
                    help="export results to a CSV file (optionally name it; otherwise a timestamped "
                         "file is created). Works for host searches and --discover.")
    args = ap.parse_args()

    intel_wanted = (args.intel_actors is not None or args.intel_reports is not None
                    or args.report or args.report_pdf)
    standalone = intel_wanted or args.rtr_audit is not None
    # --discover is its own mode: unmanaged assets, not the managed host pipeline.
    host_search = (not args.discover) and bool(args.term or args.user or args.os
                                               or args.manufacturer or args.tag_search or args.list)
    if not host_search and not standalone and not args.discover:
        ap.error("provide a search term (IP / hostname / OS), --user NAME, --discover, or a standalone "
                 "flag (--intel-actors / --intel-reports / --report / --report-pdf / --rtr-audit)")

    for flag, val in (("--report", args.report), ("--report-pdf", args.report_pdf)):
        if val and not val.isdigit():
            ap.error(f"{flag} takes a numeric report ID (see the ID column in --intel-reports)")

    try:
        sev_show, sev_label = parse_severities(args.min_severity)
    except ValueError as e:
        ap.error(str(e))

    if not args.md:
        enable_ansi_on_windows()

    if args.discover:
        run_discover(args)
        print()
        return
    # In user mode the login data IS the search, so always show that column.
    show_login = True if args.user else (not args.no_login)

    hosts = []
    if host_search:
        # Step 1: resolve hosts -- either a normal IP/hostname/OS search, or a user lookup.
        try:
            falcon = get_falcon_client()
            os_spec = parse_os_spec(args.os) if args.os else None
            manuf = " ".join(args.manufacturer).strip() if args.manufacturer else None
            raw_tag = args.tag_search.strip() if args.tag_search else None
            # Sentinels for "systems with no tags at all".
            tag_none = bool(raw_tag) and raw_tag.lower() in ("!*", "!", "none", "-", "untagged")
            tag = None if (tag_none or not raw_tag) else raw_tag
            has_criteria = bool(os_spec or manuf or tag or tag_none)
            if args.user:
                scope_term = " ".join(args.term)
                if not scope_term and not has_criteria:
                    print("Searching all hosts for that login user. Add a term "
                          "(e.g. a platform, OS, or subnet) to narrow and speed this up.")
                hosts, description, scanned_all = hosts_by_user(falcon, args.user, scope_term)
                if has_criteria:
                    hosts = [h for h in hosts if criteria_match(h, os_spec, manuf, tag, tag_none)]
                    description += " + " + criteria_desc(os_spec, manuf, tag, tag_none)
                # hosts_by_user already populated login data for matching.
            else:
                targets = parse_targets(args.term)
                if args.list:
                    file_targets = read_target_file(args.list)
                    seen = set(targets)
                    targets = targets + [t for t in file_targets if not (t in seen or seen.add(t))]
                if has_criteria and not targets:
                    # Standalone attribute search (no hostname/IP given).
                    if tag_none and not (os_spec or manuf):
                        print("Scanning all hosts for systems with no tags; this can take a moment "
                              "on a large tenant.")
                    fql = criteria_server_filter(os_spec, manuf, tag)  # tag is None when tag_none
                    hosts = search_hosts(falcon, fql or None)
                    if tag_none:   # empty-tags check is done reliably client-side
                        hosts = [h for h in hosts if not host_tags(h)]
                        hosts.sort(key=lambda h: (h.get("hostname") or "").lower())
                    description = criteria_desc(os_spec, manuf, tag, tag_none)
                elif targets:
                    # Search each target; when criteria are set the targets are
                    # host/IP only and the criteria apply client-side.
                    by_id = {}
                    for t in targets:
                        fql, _ = (build_target_filter(t) if has_criteria else build_filter(t))
                        for h in search_hosts(falcon, fql):
                            by_id[h.get("device_id")] = h
                    hosts = list(by_id.values())
                    if has_criteria:
                        hosts = [h for h in hosts if criteria_match(h, os_spec, manuf, tag, tag_none)]
                    hosts.sort(key=lambda h: (h.get("hostname") or "").lower())
                    if len(targets) > 1:
                        src = f" (from {args.list})" if args.list and not args.term else ""
                        description = f"{len(targets)} targets{src}: " + ", ".join(targets[:8]) \
                            + (" ..." if len(targets) > 8 else "")
                    else:
                        _, description = (build_target_filter(targets[0]) if has_criteria
                                          else build_filter(targets[0]))
                    if has_criteria:
                        description += " + " + criteria_desc(os_spec, manuf, tag, tag_none)
                else:
                    fql, description = build_filter("")
                    hosts = search_hosts(falcon, fql)
                if show_login and hosts:
                    add_login_users(falcon, hosts)
        except RuntimeError as e:
            print(f"\nError: {e}")
            sys.exit(1)

        if args.csv is not None:
            render_hosts_csv(hosts, args.csv or None, show_login)
        elif args.md:
            render_hosts_md(hosts, description, args.aid, show_login, args.show_tags, args.show_domain)
        else:
            render_hosts(hosts, description, args.aid, show_login, args.show_tags, args.show_domain)

        # Step 1b: apply Falcon grouping tags (the one WRITE action; confirmed).
        add_tags = normalize_tags(args.tag)
        del_tags = normalize_tags(args.untag)
        if (add_tags or del_tags):
            if not hosts:
                print("\nNo matched hosts to tag.")
            else:
                if add_tags:
                    apply_tags(falcon, hosts, add_tags, "add", args.yes)
                if del_tags:
                    apply_tags(falcon, hosts, del_tags, "remove", args.yes)

        # Step 1c: Identity Protection user info (--show-userinfo, with --user).
        if args.show_userinfo:
            if not args.user:
                print("\n--show-userinfo needs --user NAME (the account to look up).")
            else:
                notes = load_user_notes(args.user_notes)
                try:
                    idp = get_identity_client()
                except RuntimeError as e:
                    print(f"\nError: {e}")
                    idp = None
                print_user_info(idp, args.user, notes, args.md)

        # Step 1d: AD account description via Get-ADUser (--user-description).
        if args.user_description:
            if not args.user:
                print("\n--user-description needs --user NAME (the account to look up).")
            else:
                notes = load_user_notes(args.user_notes)
                print_user_description(args.user, args.user_props, notes, args.md)

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
    # Step 6: RTR readiness (per matched host; derived from data already fetched).
    if args.rtr_ready and hosts:
        print_rtr_ready(hosts, args.md)

    # Step 7: RTR session audit (standalone, read-only).
    if args.rtr_audit is not None:
        try:
            audit = get_rtr_audit_client()
        except RuntimeError as e:
            print(f"\nError: {e}")
            audit = None
        if audit is not None:
            print_rtr_audit(audit, args.rtr_audit.strip(), args.md)
    print()


if __name__ == "__main__":
    main()

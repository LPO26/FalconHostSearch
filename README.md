# FalconHostSearch.py

A command-line tool to search **CrowdStrike Falcon** for hosts by IP, hostname, OS/type, or login user, and optionally pull each host's **vulnerabilities and open ports from Tenable**, its **installed applications** (CrowdStrike Discover), and its **recent detections** (CrowdStrike Alerts API). It can also query **CrowdStrike threat intelligence** (actors and reports) standalone, with no host search at all.

> CrowdStrike answers *"which hosts."* Tenable (with `--vulns`) answers *"what's wrong with them."*

The tool is **read-only**. It only ever searches and displays; it never takes action on a host.

---

## Requirements

- Python 3.8+
- Two packages:

```bash
pip install crowdstrike-falconpy requests
```

`requests` is only used for the Tenable lookups (`--vulns`); the rest of the tool runs without it.

---

## Setup

Credentials are read from environment variables — nothing is stored in the script.

**CrowdStrike (always required):**

| Variable | Notes |
| --- | --- |
| `FALCON_CLIENT_ID` | API client ID |
| `FALCON_CLIENT_SECRET` | API client secret |
| `FALCON_CLOUD` | Optional. `us1` (default), `us2`, `eu1`, or `usgov1` |

**Tenable (only needed for `--vulns` or `--ports`):**

| Variable | Notes |
| --- | --- |
| `TIO_ACCESS_KEY` | Tenable access key |
| `TIO_SECRET_KEY` | Tenable secret key |

Setting them:

```powershell
# Windows PowerShell
$env:FALCON_CLIENT_ID="your-client-id"
$env:FALCON_CLIENT_SECRET="your-client-secret"
$env:TIO_ACCESS_KEY="your-access-key"
$env:TIO_SECRET_KEY="your-secret-key"
```

```bash
# macOS / Linux
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"
```

### Required API scopes (keep these read-only)

- **Falcon:** `Hosts: READ` (the login-user column also uses host login history, covered by Hosts: READ). For `--apps`, also `Discover: READ`. For `--detections`, also `Alerts: READ`. For the intel flags, also `Actors (Falcon Intelligence): READ` / `Reports (Falcon Intelligence): READ`.
- **Tenable:** a Basic / **Can View** user is enough.

---

## Usage

```
python FalconHostSearch.py [TERM ...] [--user NAME] [--vulns] [--min-severity LEVEL] [--ports] [--apps]
                      [--detections] [--intel-actors [QUERY]] [--intel-reports [QUERY]]
                      [--report ID] [--report-pdf ID]
                      [--days N] [--no-login] [--aid] [--md]
```

You must provide a search term (IP / hostname / OS), `--user NAME`, **or** one of the threat-intel flags — the intel flags work standalone with no host search.

---

## The four ways to search

### 1. By IP
A value that looks like an IPv4 address matches on local or external IP.
```bash
python FalconHostSearch.py 10.50.10.24
```

### 2. By hostname
Any free-text term is matched as a case-insensitive *contains* against the hostname.
```bash
python FalconHostSearch.py web01
```

### 3. By OS / type
- A platform word — `Windows`, `Linux`, `Mac` — returns all hosts on that platform.
- Adding a type word narrows by device type: `Server`, `Workstation`, or `Domain Controller`.
- A specific OS string is matched against the OS version.

```bash
python FalconHostSearch.py Windows                # all Windows hosts
python FalconHostSearch.py "Windows Server"       # only Windows servers
python FalconHostSearch.py "Windows Workstation"  # only Windows workstations
python FalconHostSearch.py server                 # all servers, any platform
python FalconHostSearch.py Ubuntu                 # OS version contains "Ubuntu"
```

> **Domain Controllers are their own type.** `"Windows Server"` returns hosts typed `Server`, *not* your DCs. Search `"domain controller"` for those.

### 4. By login user (`--user`)
Returns hosts where the given user recently logged in. This reads the **same data shown in the `LAST LOGIN USER` column**, so what you see on a host search is what `--user` finds.

```bash
python FalconHostSearch.py --user john              # any host john logged into
python FalconHostSearch.py --user john "Windows"    # scoped to Windows hosts (faster)
```

- Match on a **fragment** (e.g. `john`), not the full `DOMAIN\user` string.
- An optional term after `--user` **scopes** the search to those hosts, which keeps it fast (see Performance).

---

## Options

| Flag | Description |
| --- | --- |
| `--user NAME` | Find hosts where this user recently logged in. Matches the `LAST LOGIN USER` column. |
| `--vulns` | Also pull each matched host's vulnerabilities from Tenable. |
| `--min-severity LEVELS` | Choose which Tenable severities to show. One level = that level **and above** (`--min-severity medium`). A comma list = **exactly those levels** (`--min-severity critical,high`). Levels: `critical`, `high`, `medium`, `low`, `info`; default shows all. Affects the table and the severity tally. |
| `--ports` | Also show each matched host's open ports from Tenable. |
| `--apps` | Also show each matched host's installed applications, from CrowdStrike Discover. |
| `--detections` | Also show each matched host's recent detections (CrowdStrike Alerts API), within the `--days` window. |
| `--intel-actors [QUERY]` | Threat intel: list actors, or search them by keyword. Standalone — no host search needed. |
| `--intel-reports [QUERY]` | Threat intel: list reports, or search them by keyword. Standalone — no host search needed. The list shows each report's ID. |
| `--report ID` | Read one intel report in the terminal: metadata, related actors/industries, and the full report text. |
| `--report-pdf ID` | Save one intel report as `intel-report-ID.pdf` in the current directory. |
| `--days N` | Tenable look-back window in days (default `90`). Only used with `--vulns`. |
| `--no-login` | Skip the Falcon login-user lookup for a faster host list. (Ignored in `--user` mode, where the login data is the search.) |
| `--aid` | Also show the Falcon Agent ID (device ID) column. |
| `--md`, `--markdown` | Output as Markdown instead of the colored table — ideal for saving to a file. |

---

## Examples

```bash
# Host lists
python FalconHostSearch.py "Windows Server"
python FalconHostSearch.py 10.50.10.0           # partial IP / hostname fragment
python FalconHostSearch.py linux server

# User lookups
python FalconHostSearch.py --user maria
python FalconHostSearch.py --user svc-backup --aid

# With Tenable vulnerabilities and/or open ports
python FalconHostSearch.py web01 --vulns
python FalconHostSearch.py web01 --ports
python FalconHostSearch.py web01 --apps
python FalconHostSearch.py web01 --detections
python FalconHostSearch.py 10.50.10.24 --detections --days 30
python FalconHostSearch.py web01 --ports --vulns --apps --detections

# Threat intel (standalone; no host search needed)
python FalconHostSearch.py --intel-actors
python FalconHostSearch.py --intel-actors "bear"
python FalconHostSearch.py --intel-reports "ransomware"
python FalconHostSearch.py --report 41712                 # read a report in the terminal
python FalconHostSearch.py --report 41712 --md > report.md
python FalconHostSearch.py --report-pdf 41712             # save the official PDF
python FalconHostSearch.py web01 --detections --intel-reports   # can combine
python FalconHostSearch.py 10.50.10.24 --vulns --days 180
python FalconHostSearch.py web01 --vulns --min-severity medium          # medium and above
python FalconHostSearch.py web01 --vulns --min-severity critical,high --ports   # only those levels
python FalconHostSearch.py --user john --vulns

# Markdown output (save to a file)
python FalconHostSearch.py "Windows Server" --md > servers.md
python FalconHostSearch.py --user john --vulns --md > john_report.md
```

---

## Understanding the output

### Host table
Columns: `HOSTNAME`, `LOCAL IP`, `OS VERSION`, `TYPE` (Server / Workstation / Domain Controller), `MANUFACTURER`, `LAST LOGIN USER`, `LAST SEEN`, and `AID` (only with `--aid`).

### Vulnerabilities (`--vulns`)
Under the host table, each host gets a section showing:
- its **Tenable tags** (e.g. `Owner:InfraSec`),
- a **severity tally** (Critical / High / Medium / Low / Info and a total),
- a table of findings: severity, plugin ID, vulnerability name, and plugin family. Use `--min-severity` to control which severities appear: a single level means that level and above (`medium`), a comma list means exactly those levels (`critical,high` — any combination works, even non-contiguous like `critical,low`); the tally and header note how many findings were hidden.

Each Falcon host is matched in Tenable **by hostname first, then by IP**. A host that exists in Falcon but not Tenable prints *"Not found in Tenable"* and the run continues.

### Open ports (`--ports`)
For each matched host, shows the open ports Tenable detected, as `port/protocol` with the service name in parentheses when known (e.g. `443/tcp (www)`). Ports come from Tenable's port-scanner and service-detection findings, so they reflect the most recent scan — a host that hasn't been scanned (or has no network scan data) shows none. `--ports` and `--vulns` can be used together or separately; both need the Tenable keys.

### Installed applications (`--apps`)
For each matched host, lists installed applications as `name version (vendor)`, from **CrowdStrike Discover** (scope `Discover: READ`, using the same Falcon keys), scoped to the host. If Discover isn't available (not licensed / no scope) or has no apps for the host, it says so. This requires Falcon Discover; it does not use Tenable.

### Detections (`--detections`)
For each matched host, shows its recent detections from the **CrowdStrike Alerts API** (the legacy Detects API was decommissioned in Sept 2025, so this needs the `Alerts: READ` scope): severity, date, detection name, tactic/technique, and status, newest first, within the `--days` window. It shows the latest 20 per host and notes the total if there are more.

### Threat intel (`--intel-actors`, `--intel-reports`)
Standalone lookups against **Falcon Intelligence** — no host search required. With no value they list recent entries; with a keyword they search (`--intel-actors "bear"`). Actors show origins, target industries, and last-active date; reports show an **ID**, type, and publish date. These need an Intel subscription and the matching `READ` scope, and print a clear "no access" note otherwise.

**Reading a report:** take an ID from the list and use `--report ID` to read it in the terminal — type, publish date, related actors, target industries/countries, motivations, a link to the report in the Falcon console, and the full report text (the API's rich-text HTML is stripped to plain text). `--report-pdf ID` downloads the official PDF to `intel-report-ID.pdf`. Some report types have no inline text; the output says so, and the PDF is the full document. Both use the same `Reports (Falcon Intelligence): READ` scope as the list — still read-only.

### Markdown mode (`--md`)
Produces clean Markdown — a host table plus per-host vulnerability tables — with no color codes. It renders as real tables in GitHub, Obsidian, or any Markdown viewer. Redirect it to a file with `>`.

---

## Performance notes

- **Narrow searches are fast; fleet-wide searches are heavier.** A specific hostname, IP, or `"Windows Server"` returns quickly. A broad term that matches thousands of hosts pulls details (and login history) for all of them.
- **User search has a tradeoff.** Falcon has no server-side filter for login user, so `--user` pulls the candidate hosts and matches them locally. Scope it with a term (`--user john "Windows"`, a subnet, etc.) to keep it fast; `--user john` alone scans the whole fleet and prints a heads-up. It skips the per-host login-history calls when your device records already carry the last login user.
- **`--vulns` calls Tenable once per matched host.** Pair it with a narrow search rather than a fleet-wide one.
- **`--ports` adds a few more Tenable calls per host** (it reads the port-scanner findings' output), so it's also best paired with a narrow search.
- **`--apps` and `--detections` query per host too** (Discover / Alerts scoped to each host), so pair them with a narrow search as well. The intel flags are one query each regardless of hosts.
- **`--no-login`** skips the login-user lookup for the quickest possible host list.

---

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET...` | Falcon env vars aren't set in this shell. |
| `--vulns needs Tenable keys...` | `TIO_ACCESS_KEY` / `TIO_SECRET_KEY` aren't set. |
| `Falcon API error` / auth failure | Check the client ID/secret, the `FALCON_CLOUD` region, and that the client has `Hosts: READ`. |
| `Tenable auth failed (HTTP 401/403)` | Check the Tenable keys and that the user has view access. |
| `"Windows Server"` returns nothing | Your tenant may label that type differently — run a plain `Windows` search and read the `TYPE` column to see the exact values in use. |
| `LAST LOGIN USER` is blank for a host | That host has no recent interactive login in Falcon's retained window (e.g. a service-only server). |
| `--ports` shows nothing for a host | The host hasn't had a network/port scan in the window, or Tenable holds no port-scanner findings for it. |
| `--apps` says "Discover not available" | Your API client lacks `Discover: READ` or the tenant isn't licensed for Discover. |
| `--apps` shows no apps for a host | Discover has no application records for that host. |
| `--detections` says "no access" | Add the `Alerts: READ` scope to your API client (detections moved to the Alerts API). |
| Intel flags say "no access" | Your client lacks the Falcon Intelligence `READ` scopes, or the tenant has no Intel subscription. |
| `--report` shows no text | That report type has no inline body; `--report-pdf ID` gets the full document. |
| `--user NAME` finds nothing you expect | Search a shorter fragment; the stored value often includes a domain prefix or a different account-name form. |
| Host shows in Falcon but `Not found in Tenable` | The host's name/IP differs between the two systems, or it isn't in Tenable. |

---

## Notes

- **Read-only:** the tool performs no containment, scanning, or any other action — it only searches and displays.
- Output is colorized in a terminal; use `--md` for plain Markdown.

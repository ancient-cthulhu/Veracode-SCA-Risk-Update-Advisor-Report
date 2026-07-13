#!/usr/bin/env python3
"""
Veracode SCA Risk & Update Advisor Report (hardened)

Two outputs from one run:
  1. ACTIONABLE  - per-issue rows ranked by risk, with Update Advisor fix target
  2. EXECUTIVE   - top-N worst libraries rolled up across the whole scope

Scope is filterable by --workspace and/or --team.

Data sourced from the SCA Agent API (base: https://api.veracode.com/srcclr):
  getWorkspaces         GET /v3/workspaces
  getWorkspaceTeams     GET /v3/workspaces/{id}/teams
  getWorkspaceProjects  GET /v3/workspaces/{id}/projects
  getProjectIssues      GET /v3/workspaces/{id}/projects/{projectId}/issues

READ-ONLY GUARANTEE: this module performs HTTP GET requests exclusively.
No POST/PUT/PATCH/DELETE verb exists anywhere in this file; a unit test
(tests/test_report.py::test_read_only_guarantee) enforces it.

AUTH
----
    pip install -r requirements.txt
    export VERACODE_API_KEY_ID=...     (or ~/.veracode/credentials)
    export VERACODE_API_KEY_SECRET=...
The SCA REST API requires a HUMAN user credential, not an API service account.

EXIT CODES
----------
    0  clean run (or clean under --fail-on-* thresholds)
    1  a --fail-on-* threshold was breached
    2  runtime / auth / configuration error
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
import random
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import urlsplit

import requests

try:
    from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency. Run: pip install -r requirements.txt")

TOOL_NAME = "veracode-sca-risk-report"
TOOL_VERSION = "2.0.0"

# Region base URLs are a hardcoded allowlist. There is deliberately no flag
# and no environment variable that can point this tool at an arbitrary host.
REGION_HOSTS: dict[str, str] = {
    "us": "https://api.veracode.com/srcclr",
    "eu": "https://api.veracode.eu/srcclr",
    "fed": "https://api.veracode.us/srcclr",
}

PAGE_SIZE = 500
MAX_PAGES = 2000  # hard ceiling per collection; guards malformed page metadata

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2

log = logging.getLogger(TOOL_NAME)


class FatalError(RuntimeError):
    """Raised for unrecoverable auth/config errors. Maps to exit code 2."""


# --------------------------------------------------------------------------- #
# Security helpers
# --------------------------------------------------------------------------- #
_CSV_INJECTION_LEADS = ("=", "+", "-", "@", "\t", "\r")


def neutralize_csv(value: Any) -> Any:
    """Defang spreadsheet formula injection in attacker-influenced fields.

    Library names, versions, CVE strings and exploit sources originate from
    upstream package metadata. Any cell starting with =, +, -, @, TAB or CR is
    prefixed with a single quote so Excel/Sheets treat it as text.
    Numeric values in this dataset are non-negative, so the '-' rule cannot
    corrupt legitimate numbers.
    """
    s = str(value)
    if s and s.startswith(_CSV_INJECTION_LEADS):
        return "'" + s
    return value if not isinstance(value, str) else s


def safe_url_for_log(url: str) -> str:
    """Never log query strings or credentials; scheme+host+path only."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def atomic_write(path: str, force: bool, writer_fn: Callable[[Any], None],
                 newline: str | None = "") -> None:
    """Write via temp file in the same directory, chmod 0600, atomic rename.

    Refuses to overwrite an existing file unless force=True (fail closed).
    """
    if os.path.exists(path) and not force:
        raise FatalError(
            f"Refusing to overwrite existing file: {path} (pass --force)")
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".sca_tmp_")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", newline=newline, encoding="utf-8") as fh:
            writer_fn(fh)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- #
# HTTP client: pooled sessions, shared throttle, hardened retries
# --------------------------------------------------------------------------- #
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class GlobalThrottle:
    """Shared across worker threads: one 429 pauses everyone, not one thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hold_until = 0.0

    def wait(self) -> None:
        while True:
            with self._lock:
                remaining = self._hold_until - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(remaining, 1.0))

    def hold(self, seconds: float) -> None:
        with self._lock:
            self._hold_until = max(self._hold_until,
                                   time.monotonic() + seconds)


class ApiClient:
    """Thread-local requests.Session per worker; HMAC auth created once each.

    All requests are GET. TLS verification is the requests default (on) and is
    never disabled. Connect and read timeouts are separate.
    """

    def __init__(self, host: str, retries: int, base_delay: float,
                 read_timeout: float, connect_timeout: float = 10.0) -> None:
        self.host = host
        self.retries = retries
        self.base_delay = base_delay
        self.timeout = (connect_timeout, read_timeout)
        self.throttle = GlobalThrottle()
        self._local = threading.local()

    def _session(self) -> requests.Session:
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.auth = RequestsAuthPluginVeracodeHMAC()
            sess.headers["User-Agent"] = f"{TOOL_NAME}/{TOOL_VERSION}"
            self._local.session = sess
        return sess

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> dict:
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            self.throttle.wait()
            try:
                resp = self._session().get(url, params=params,
                                           timeout=self.timeout)
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_exc = exc
                delay = self._delay(attempt)
                log.debug("Retryable %s on %s; retry in %.1fs",
                          type(exc).__name__, safe_url_for_log(url), delay)
                time.sleep(delay)
                continue

            if resp.status_code in (401, 403):
                # Fail fast; do not retry auth failures.
                raise FatalError(
                    f"HTTP {resp.status_code} on {safe_url_for_log(url)}. "
                    "The SCA REST API requires HUMAN USER API credentials; "
                    "API service accounts are rejected. Also confirm the "
                    "credential has visibility into the target workspaces "
                    "and that --region matches your tenant.")

            if resp.status_code in _RETRYABLE_STATUS:
                delay = self._retry_after(resp) or self._delay(attempt)
                if resp.status_code == 429:
                    self.throttle.hold(delay)
                log.debug("HTTP %d on %s; retry in %.1fs", resp.status_code,
                          safe_url_for_log(url), delay)
                time.sleep(delay)
                last_exc = requests.HTTPError(
                    f"HTTP {resp.status_code} on {safe_url_for_log(url)}",
                    response=resp)
                continue

            if resp.status_code >= 400:
                # Non-retryable client error: log path only, never the query
                # string or headers (signed URLs must not leak).
                raise requests.HTTPError(
                    f"HTTP {resp.status_code} on {safe_url_for_log(url)}",
                    response=resp)
            return resp.json()

        raise last_exc if last_exc else FatalError(
            f"Exhausted retries on {safe_url_for_log(url)}")

    def _delay(self, attempt: int) -> float:
        return min(self.base_delay * (2 ** attempt), 60.0) + random.uniform(0, 0.5)

    @staticmethod
    def _retry_after(resp: requests.Response) -> float | None:
        raw = resp.headers.get("Retry-After")
        if raw is None:
            return None
        try:
            return max(float(raw), 0.0)
        except ValueError:
            return None


# --------------------------------------------------------------------------- #
# HAL pagination
# --------------------------------------------------------------------------- #
def embedded_list(payload: dict) -> list:
    """SCA responses are HAL. Collections live under _embedded keyed by name."""
    emb = payload.get("_embedded") or {}
    if isinstance(emb, list):
        return emb
    for value in emb.values():
        if isinstance(value, list):
            return value
    return []


def paged(client: ApiClient, base_url: str,
          params: dict[str, Any] | None = None) -> Iterator[dict]:
    page = 0
    while True:
        # Fresh copy per request: never mutate the caller's dict.
        call_params = dict(params or {})
        call_params["size"] = PAGE_SIZE
        call_params["page"] = page
        data = client.get_json(base_url, params=call_params)
        items = embedded_list(data)
        yield from items
        meta = data.get("page") or {}
        total_pages = meta.get("total_pages", 1)
        page += 1
        if page >= MAX_PAGES:
            log.warning("Page ceiling (%d) hit on %s; results may be "
                        "truncated. Malformed pagination metadata?",
                        MAX_PAGES, safe_url_for_log(base_url))
            break
        if page >= total_pages or not items:
            break


# --------------------------------------------------------------------------- #
# API wrappers (GET only)
# --------------------------------------------------------------------------- #
def list_workspaces(client: ApiClient, name_filter: str | None = None) -> list[dict]:
    params: dict[str, Any] = {}
    if name_filter:
        params["filter[workspace]"] = name_filter
    return list(paged(client, f"{client.host}/v3/workspaces", params))


def list_workspace_teams(client: ApiClient, workspace_id: str) -> list[dict]:
    try:
        return list(paged(client,
                          f"{client.host}/v3/workspaces/{workspace_id}/teams"))
    except requests.HTTPError as exc:
        log.debug("Team resolution failed for workspace %s: %s",
                  workspace_id, exc)
        return []


def list_projects(client: ApiClient, workspace_id: str) -> list[dict]:
    return list(paged(client,
                      f"{client.host}/v3/workspaces/{workspace_id}/projects"))


def list_project_issues(client: ApiClient, workspace_id: str,
                        project_id: str) -> list[dict]:
    url = f"{client.host}/v3/workspaces/{workspace_id}/projects/{project_id}/issues"
    params = {"status": "open", "type": ["vulnerability", "library"]}
    return list(paged(client, url, params))


# --------------------------------------------------------------------------- #
# Risk model
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Weights:
    cvss: float = 5.0      # x CVSS3 (0-10)      -> up to 50
    epss: float = 30.0     # x scaled EPSS (0-1) -> up to 30
    exploit: float = 15.0  # flat, observed exploit (KEV etc.)
    method: float = 5.0    # flat, reachable vulnerable method
    legacy: bool = False   # restore v1 linear-EPSS, no-tiebreaker scoring


@dataclass(slots=True)
class Row:
    workspace: str
    team: str
    project: str
    project_id: str
    languages: str
    issue_type: str
    library: str
    version: str
    direct: str
    cve: str = ""
    cvss3: float = 0.0
    cvss2: float = 0.0
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    exploit_observed: str = ""
    exploit_source: str = ""
    vulnerable_method: str = ""
    severity: float = 0.0
    fixable: str = "no"
    safe_version: str = ""
    safe_release_date: str = ""
    risk_score: float = 0.0
    # v2 columns (appended at the end to preserve dashboard column order)
    remediation: str = ""
    fix_age_days: str = ""
    kev: str = ""
    language: str = ""


def scale_epss(epss: float, legacy: bool) -> float:
    """EPSS is heavily right-skewed. Legacy linear x30 undervalues the
    0.1-0.5 band; sqrt scaling lifts the middle while keeping 0->0 and 1->1.

        contribution = w_epss * sqrt(epss)        (default)
        contribution = w_epss * epss              (--legacy-scoring)
    """
    if legacy:
        return epss
    return math.sqrt(max(epss, 0.0))


def compute_risk(cvss3: float, epss: float, exploit_observed: bool,
                 vuln_method: bool, weights: Weights,
                 severity: float = 0.0, direct: bool = False) -> float:
    """Explainable 0-100 prioritization score.

    Default formula:
        cvss3 * w_cvss
      + sqrt(epss) * w_epss
      + w_exploit if observed exploit
      + w_method  if reachable vulnerable method
      + 2.0 if direct dependency AND reachable method (reachability tiebreak)
      + severity * 0.1 (native Veracode severity tiebreak, max +1)
    Capped at 100. --legacy-scoring reproduces the v1 formula exactly.
    """
    score = (cvss3 or 0.0) * weights.cvss
    score += scale_epss(epss or 0.0, weights.legacy) * weights.epss
    if exploit_observed:
        score += weights.exploit
    if vuln_method:
        score += weights.method
    if not weights.legacy:
        if direct and vuln_method:
            score += 2.0
        score += (severity or 0.0) * 0.1
    return round(min(score, 100.0), 2)


def is_kev(exploit_source: str) -> bool:
    src = (exploit_source or "").upper()
    return "KEV" in src or "CISA" in src


def fix_age_days(safe_release_date: str,
                 now: datetime | None = None) -> str:
    """Days since the safe version was released. Empty string if unknown."""
    if not safe_release_date:
        return ""
    raw = safe_release_date.strip()
    try:
        # API dates are ISO 8601; tolerate a trailing Z and date-only forms.
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return str(max((now - dt).days, 0))


def guess_language(lib: dict, project_languages: list[str]) -> str:
    """Best-available ecosystem hint for rollup keys.

    Assumption (guarded): the library object may expose 'language' or
    'coordinate_type' depending on agent version; fall back to the project's
    first language, then empty.
    """
    return (lib.get("language") or lib.get("coordinate_type")
            or (project_languages[0] if project_languages else "") or "")


def build_row(ws_name: str, ws_team: str, proj: dict, issue: dict,
              weights: Weights) -> Row:
    lib = issue.get("library") or {}
    vuln = issue.get("vulnerability") or {}
    exp = vuln.get("exploitability") or {}

    safe_version = issue.get("library_updated_version") or ""
    exploit_observed = bool(exp.get("exploit_observed"))
    vuln_method = bool(issue.get("vulnerable_method"))
    cvss3 = vuln.get("cvss3_score") or 0.0
    epss = exp.get("epss_score") or 0.0
    severity = issue.get("severity") or 0.0
    direct = bool(lib.get("direct"))
    project_languages = proj.get("languages") or []
    lib_name = lib.get("name", "")
    version = lib.get("version", "")
    exploit_source = exp.get("exploit_source", "") or ""

    if safe_version:
        remediation = f"upgrade {lib_name} {version} -> {safe_version}"
        if not direct:
            remediation += " (transitive: bump the direct parent dependency)"
    else:
        remediation = ""

    return Row(
        workspace=ws_name,
        team=ws_team,
        project=proj.get("name", ""),
        project_id=proj.get("id", ""),
        languages=",".join(project_languages),
        issue_type=issue.get("issue_type", ""),
        library=lib_name,
        version=version,
        direct="direct" if direct else "transitive",
        cve=vuln.get("cve", "") or "",
        cvss3=cvss3,
        cvss2=vuln.get("cvss2_score") or 0.0,
        epss_score=epss,
        epss_percentile=exp.get("epss_percentile") or 0.0,
        exploit_observed="yes" if exploit_observed else "",
        exploit_source=exploit_source,
        vulnerable_method="yes" if vuln_method else "",
        severity=severity,
        fixable="yes" if safe_version else "no",
        safe_version=safe_version,
        safe_release_date=issue.get("library_updated_release_date", "") or "",
        risk_score=compute_risk(cvss3, epss, exploit_observed, vuln_method,
                                weights, severity=severity, direct=direct),
        remediation=remediation,
        fix_age_days=fix_age_days(
            issue.get("library_updated_release_date", "") or ""),
        kev="yes" if is_kev(exploit_source) else "",
        language=guess_language(lib, project_languages),
    )


def dedup_rows(rows: list[Row]) -> tuple[list[Row], int]:
    """The same CVE on the same library+version in the same repo can surface
    as both a 'vulnerability' and a 'library' issue. Collapse duplicates,
    keeping the richer record (vulnerability type, then higher risk score).
    Rows without a CVE are never merged.
    """
    def richness(r: Row) -> tuple:
        return (r.issue_type == "vulnerability", r.risk_score,
                bool(r.safe_version))

    best: dict[tuple, Row] = {}
    order: list[tuple] = []
    merged = 0
    for r in rows:
        if not r.cve:
            key = ("__nocve__", id(r))
        else:
            key = (r.project_id, r.library, r.version, r.cve)
        if key in best:
            merged += 1
            if richness(r) > richness(best[key]):
                best[key] = r
        else:
            best[key] = r
            order.append(key)
    return [best[k] for k in order], merged


# --------------------------------------------------------------------------- #
# Executive rollup: worst libraries across the whole scope
# --------------------------------------------------------------------------- #
def spread_bonus(repo_n: int, weight: float, legacy: bool) -> float:
    """Exposure spread bonus for a library seen in repo_n repos.

    Legacy: (repo_n - 1) * 5   -- linear; saturates the 100 cap quickly and
    implies 100 repos is 20x worse than 5, which mismatches how blast radius
    grows in practice.
    Default: weight * log2(repo_n) -- concave; each doubling of spread adds a
    constant increment, so widely-spread libraries still rank up without one
    popular utility library pinning the whole board at 100.
    """
    if legacy:
        return (repo_n - 1) * 5.0
    return weight * math.log2(max(repo_n, 1))


def library_rollup(rows: Iterable[Row], spread_weight: float = 6.0,
                   legacy: bool = False) -> list[dict]:
    """Aggregate by (language, library name) across every repo in scope.

    Keying on the ecosystem hint prevents cross-ecosystem collisions
    (npm 'core' vs Maven 'core'). Ranked by:
        exposure = min(max single-issue risk + spread_bonus(repos), 100)
    """
    agg: dict[tuple[str, str], dict] = {}
    for r in rows:
        if not r.library:
            continue
        key = (r.language, r.library)
        b = agg.setdefault(key, {
            "library": r.library,
            "language": r.language,
            "repos": set(),
            "versions": set(),
            "issues": 0,
            "vulns": set(),
            "max_cvss": 0.0,
            "max_epss": 0.0,
            "exploited": 0,
            "kev": 0,
            "fixable_issues": 0,
            "max_risk": 0.0,
            "safe_targets": set(),
        })
        b["repos"].add(r.project)
        if r.version:
            b["versions"].add(r.version)
        b["issues"] += 1
        if r.cve:
            b["vulns"].add(r.cve)
        b["max_cvss"] = max(b["max_cvss"], r.cvss3)
        b["max_epss"] = max(b["max_epss"], r.epss_score)
        if r.exploit_observed == "yes":
            b["exploited"] += 1
        if r.kev == "yes":
            b["kev"] += 1
        if r.fixable == "yes":
            b["fixable_issues"] += 1
            if r.safe_version:
                b["safe_targets"].add(r.safe_version)
        b["max_risk"] = max(b["max_risk"], r.risk_score)

    out = []
    for b in agg.values():
        repo_n = len(b["repos"])
        exposure = round(min(b["max_risk"]
                             + spread_bonus(repo_n, spread_weight, legacy),
                             100.0), 1)
        out.append({
            "library": b["library"],
            "repos_affected": repo_n,
            "issues": b["issues"],
            "distinct_cves": len(b["vulns"]),
            "max_cvss3": round(b["max_cvss"], 1),
            "max_epss": round(b["max_epss"], 4),
            "exploited_issues": b["exploited"],
            "fixable_issues": b["fixable_issues"],
            "fully_fixable": ("yes" if b["fixable_issues"] == b["issues"]
                              else "partial" if b["fixable_issues"] else "no"),
            "safe_versions": ",".join(sorted(b["safe_targets"])[:5]),
            "versions_in_use": ",".join(sorted(b["versions"])[:5]),
            "exposure_score": exposure,
            # v2 columns appended at the end
            "language": b["language"],
            "kev_issues": b["kev"],
        })
    out.sort(key=lambda d: (d["exposure_score"], d["issues"]), reverse=True)
    return out


# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #
def write_csv(path: str, dicts: list[dict], force: bool) -> None:
    if not dicts:
        log.warning("Nothing to write for %s; skipping file.", path)
        return
    fieldnames = list(dicts[0].keys())

    def _write(fh: Any) -> None:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for d in dicts:
            writer.writerow({k: neutralize_csv(v) for k, v in d.items()})

    atomic_write(path, force, _write)


def write_json(path: str, payload: Any, force: bool) -> None:
    atomic_write(path, force,
                 lambda fh: json.dump(payload, fh, indent=2, default=str),
                 newline=None)


def write_jsonl(path: str, dicts: list[dict], force: bool) -> None:
    def _write(fh: Any) -> None:
        for d in dicts:
            fh.write(json.dumps(d, default=str) + "\n")
    atomic_write(path, force, _write, newline=None)


def sarif_level(cvss3: float) -> str:
    if cvss3 >= 7.0:
        return "error"
    if cvss3 >= 4.0:
        return "warning"
    return "note"


def build_sarif(rows: list[Row]) -> dict:
    """Minimal SARIF 2.1.0: one result per issue, CVE as ruleId, so the file
    can gate CI and upload to GitHub code scanning."""
    rules: dict[str, dict] = {}
    results = []
    for r in rows:
        rule_id = r.cve or f"SRCCLR-{r.library}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", "").replace(".", "") or "SCAIssue",
                "shortDescription": {
                    "text": f"{rule_id} in {r.library}"},
                "helpUri": (f"https://nvd.nist.gov/vuln/detail/{r.cve}"
                            if r.cve else "https://sca.analysiscenter.veracode.com/"),
            }
        msg = (f"{r.library} {r.version} in {r.project}: risk {r.risk_score}, "
               f"CVSS3 {r.cvss3}, EPSS {r.epss_score}.")
        if r.remediation:
            msg += f" Remediation: {r.remediation}."
        results.append({
            "ruleId": rule_id,
            "level": sarif_level(r.cvss3),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": r.project or "unknown"},
                },
            }],
            "properties": {
                "workspace": r.workspace,
                "team": r.team,
                "riskScore": r.risk_score,
                "epss": r.epss_score,
                "kev": r.kev == "yes",
                "direct": r.direct,
                "fixable": r.fixable,
                "safeVersion": r.safe_version,
            },
        })
    return {
        "$schema": ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                    "master/Schemata/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri":
                    "https://docs.veracode.com/r/c_sc_agent_api",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|")
                                     for c in row) + " |")
    return "\n".join(out)


def build_markdown(rows: list[Row], libs: list[dict], scope: str,
                   top: int, top_libs: int) -> str:
    total_repos = len({r.project for r in rows})
    fixable_n = sum(1 for r in rows if r.fixable == "yes")
    exploited_n = sum(1 for r in rows if r.exploit_observed == "yes")
    kev_n = sum(1 for r in rows if r.kev == "yes")

    parts = [f"# SCA Risk Report — scope: {scope}", ""]
    parts.append(f"Open issues: **{len(rows)}** across **{total_repos}** "
                 f"repos. Update Advisor fixable: **{fixable_n}** "
                 f"({fixable_n * 100 // max(len(rows), 1)}%). Observed "
                 f"exploit: **{exploited_n}** (KEV: **{kev_n}**).")

    parts += ["", f"## Top {top_libs} highest-exposure libraries", ""]
    parts.append(md_table(
        ["Exposure", "Library", "Lang", "Repos", "Issues", "CVEs",
         "MaxCVSS", "MaxEPSS", "KEV", "Fixable", "Safe versions"],
        [[d["exposure_score"], d["library"], d["language"],
          d["repos_affected"], d["issues"], d["distinct_cves"],
          d["max_cvss3"], d["max_epss"], d["kev_issues"],
          d["fully_fixable"], d["safe_versions"]]
         for d in libs[:top_libs]]))

    parts += ["", f"## Top {top} highest-risk issues", ""]
    parts.append(md_table(
        ["Risk", "CVE", "Library", "Version", "Repo", "Direct",
         "Fix age (days)", "Remediation"],
        [[r.risk_score, r.cve or "-", r.library, r.version, r.project,
          r.direct, r.fix_age_days or "-", r.remediation or "-"]
         for r in rows[:top]]))

    # Per-team section with fixable % and average fix latency.
    teams: dict[str, dict] = {}
    for r in rows:
        t = teams.setdefault(r.team or "(no team)",
                             {"total": 0, "fixable": 0, "ages": []})
        t["total"] += 1
        if r.fixable == "yes":
            t["fixable"] += 1
        if r.fix_age_days:
            t["ages"].append(int(r.fix_age_days))
    parts += ["", "## Per-team", ""]
    parts.append(md_table(
        ["Team", "Issues", "Fixable %", "Avg fix age (days)"],
        [[team, t["total"], t["fixable"] * 100 // max(t["total"], 1),
          (sum(t["ages"]) // len(t["ages"])) if t["ages"] else "-"]
         for team, t in sorted(teams.items(),
                               key=lambda kv: kv[1]["total"], reverse=True)]))
    parts.append("")
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Console rendering
# --------------------------------------------------------------------------- #
def print_group_table(rows: list[Row], group_by: str) -> None:
    keyfn = {
        "repo": lambda r: r.project,
        "team": lambda r: r.team or "(no team)",
        "cve": lambda r: r.cve or "(no CVE)",
        "library": lambda r: r.library or "(no library)",
    }[group_by]
    agg: dict[str, dict] = {}
    for r in rows:
        b = agg.setdefault(keyfn(r), {"total": 0, "fixable": 0,
                                      "max_risk": 0.0, "ages": []})
        b["total"] += 1
        b["fixable"] += 1 if r.fixable == "yes" else 0
        b["max_risk"] = max(b["max_risk"], r.risk_score)
        if r.fix_age_days:
            b["ages"].append(int(r.fix_age_days))
    title = {"repo": "Per-repo risk", "team": "Per-team risk",
             "cve": "Per-CVE risk", "library": "Per-library risk"}[group_by]
    print(f"\n{title} (sorted by max risk):")
    print(f"{'KEY':<40} {'ISSUES':>7} {'FIXABLE':>8} {'MAXRISK':>8} {'AVGFIXAGE':>10}")
    for key, b in sorted(agg.items(), key=lambda kv: kv[1]["max_risk"],
                         reverse=True):
        avg_age = (str(sum(b["ages"]) // len(b["ages"]))
                   if b["ages"] else "-")
        print(f"{key[:39]:<40} {b['total']:>7} {b['fixable']:>8} "
              f"{b['max_risk']:>8.1f} {avg_age:>10}")


def severity_band(cvss3: float) -> str:
    if cvss3 >= 9.0:
        return "critical"
    if cvss3 >= 7.0:
        return "high"
    if cvss3 >= 4.0:
        return "medium"
    if cvss3 > 0.0:
        return "low"
    return "none"


def print_console(rows: list[Row], libs: list[dict], args: argparse.Namespace,
                  merged: int) -> None:
    scope = args.workspace or args.workspace_contains or args.team \
        or "ALL workspaces"
    print("\n" + "=" * 78)
    print(f"EXECUTIVE SUMMARY  |  scope: {scope}")
    print("=" * 78)
    total_repos = len({r.project for r in rows})
    fixable_n = sum(1 for r in rows if r.fixable == "yes")
    exploited_n = sum(1 for r in rows if r.exploit_observed == "yes")
    kev_n = sum(1 for r in rows if r.kev == "yes")
    print(f"Open issues: {len(rows)}   Repos affected: {total_repos}")
    print(f"Update Advisor fixable: {fixable_n} "
          f"({fixable_n * 100 // len(rows)}%)   "
          f"With observed exploit: {exploited_n}   KEV: {kev_n}")
    bands: dict[str, int] = {}
    for r in rows:
        bands[severity_band(r.cvss3)] = bands.get(severity_band(r.cvss3), 0) + 1
    print("By severity band: " + "  ".join(
        f"{b}={bands[b]}" for b in ("critical", "high", "medium", "low", "none")
        if b in bands))
    kev_cves = sorted({r.cve for r in rows if r.kev == "yes" and r.cve})
    if kev_cves:
        print("Exploited (KEV) CVEs: " + ", ".join(kev_cves[:15])
              + (" ..." if len(kev_cves) > 15 else ""))
    if merged:
        print(f"Duplicate vulnerability/library records merged: {merged}")

    print(f"\nTop {args.top_libs} highest-exposure libraries:")
    hdr = (f"{'EXPO':>5} {'LIBRARY':<30} {'REPOS':>5} {'ISS':>4} {'CVEs':>4} "
           f"{'CVSS':>4} {'EPSS':>6} {'EXPL':>4} {'FIX':<7} SAFE->")
    print(hdr)
    for d in libs[:args.top_libs]:
        print(f"{d['exposure_score']:>5.0f} {d['library'][:29]:<30} "
              f"{d['repos_affected']:>5} {d['issues']:>4} {d['distinct_cves']:>4} "
              f"{d['max_cvss3']:>4.1f} {d['max_epss']:>6.3f} "
              f"{d['exploited_issues']:>4} "
              f"{d['fully_fixable']:<7} {d['safe_versions'][:20]}")

    print_group_table(rows, args.group_by)

    print(f"\nTop {args.top} highest-risk issues (actionable):")
    print(f"{'RISK':>5} {'CVSS3':>5} {'EPSS':>6} {'CVE':<16} {'LIB':<26} "
          f"{'FIX->':<14} REPO")
    for r in rows[:args.top]:
        fix = r.safe_version if r.fixable == "yes" else "-"
        print(f"{r.risk_score:>5.0f} {r.cvss3:>5.1f} {r.epss_score:>6.3f} "
              f"{r.cve[:15]:<16} {r.library[:25]:<26} {fix[:13]:<14} "
              f"{r.project[:30]}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def float_range(lo: float, hi: float) -> Callable[[str], float]:
    def parse(s: str) -> float:
        try:
            v = float(s)
        except ValueError:
            raise argparse.ArgumentTypeError(f"not a number: {s!r}")
        if math.isnan(v) or not (lo <= v <= hi):
            raise argparse.ArgumentTypeError(
                f"must be a number in [{lo}, {hi}], got {s!r}")
        return v
    return parse


def positive_int(s: str) -> int:
    try:
        v = int(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {s!r}")
    if v <= 0:
        raise argparse.ArgumentTypeError(f"must be a positive integer: {s!r}")
    return v


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Veracode SCA risk + Update Advisor report (read-only)")
    # Scope
    ap.add_argument("--region", choices=sorted(REGION_HOSTS), default="us")
    ap.add_argument("--workspace",
                    help="Restrict to a single workspace by EXACT name "
                         "(case-insensitive)")
    ap.add_argument("--workspace-contains",
                    help="Restrict to workspaces whose name contains this "
                         "substring (v1 behavior)")
    ap.add_argument("--team",
                    help="Restrict to workspaces associated with these team "
                         "name(s); comma-separated, case-insensitive")
    ap.add_argument("--label-teams", action=argparse.BooleanOptionalAction,
                    default=True,
                    help="Resolve and label each row with workspace teams "
                         "(default on; --no-label-teams skips the calls)")
    # Filters
    ap.add_argument("--fixable-only", action="store_true",
                    help="Only issues Update Advisor can fix")
    ap.add_argument("--min-cvss", type=float_range(0.0, 10.0), default=0.0)
    ap.add_argument("--min-epss", type=float_range(0.0, 1.0), default=0.0)
    ap.add_argument("--min-severity", type=float_range(0.0, 100.0),
                    default=0.0,
                    help="Drop issues below this native Veracode severity")
    ap.add_argument("--exploited-only", action="store_true",
                    help="Only vulns with an observed exploit (KEV etc.)")
    direct_group = ap.add_mutually_exclusive_group()
    direct_group.add_argument("--direct-only", action="store_true",
                              help="Only direct dependencies")
    direct_group.add_argument("--transitive-only", action="store_true",
                              help="Only transitive dependencies")
    # Output
    ap.add_argument("--out", default="sca_actionable.csv",
                    help="Per-issue actionable output path")
    ap.add_argument("--exec-out", default="sca_executive_libraries.csv",
                    help="Executive library-rollup output path")
    ap.add_argument("--md-out", help="Also write a Markdown report here")
    ap.add_argument("--format", choices=("csv", "json", "jsonl", "sarif"),
                    default="csv",
                    help="Per-issue output format. json also switches the "
                         "executive file to JSON; jsonl/sarif apply to --out "
                         "only (executive stays CSV)")
    ap.add_argument("--force", action="store_true",
                    help="Overwrite existing output files")
    ap.add_argument("--top", type=positive_int, default=25,
                    help="Top issues to print")
    ap.add_argument("--top-libs", type=positive_int, default=10,
                    help="Top libraries to print")
    ap.add_argument("--group-by", choices=("repo", "team", "cve", "library"),
                    default="repo",
                    help="Console rollup table grouping (default: repo, "
                         "matches v1 layout)")
    # Scoring
    ap.add_argument("--w-cvss", type=float_range(0.0, 100.0), default=5.0)
    ap.add_argument("--w-epss", type=float_range(0.0, 100.0), default=30.0)
    ap.add_argument("--w-exploit", type=float_range(0.0, 100.0), default=15.0)
    ap.add_argument("--w-method", type=float_range(0.0, 100.0), default=5.0)
    ap.add_argument("--spread-weight", type=float_range(0.0, 100.0),
                    default=6.0,
                    help="Executive exposure spread bonus per doubling of "
                         "repos affected")
    ap.add_argument("--legacy-scoring", action="store_true",
                    help="Reproduce v1 risk and exposure formulas exactly")
    # CI gating
    ap.add_argument("--fail-on-exploited", action="store_true",
                    help="Exit 1 if any matched issue has an observed exploit")
    ap.add_argument("--fail-on-risk", type=float_range(0.0, 100.0),
                    default=None, metavar="N",
                    help="Exit 1 if any matched issue has risk_score >= N")
    ap.add_argument("--fail-on-count", type=positive_int, default=None,
                    metavar="N",
                    help="Exit 1 if the matched issue count >= N")
    # Runtime
    ap.add_argument("--workers", type=positive_int, default=4,
                    help="Concurrent issue-fetch workers (max 8)")
    ap.add_argument("--retries", type=positive_int, default=3,
                    help="Retry attempts for retryable HTTP failures")
    ap.add_argument("--retry-delay", type=float_range(0.0, 300.0), default=1.0,
                    help="Base backoff delay in seconds")
    ap.add_argument("--timeout", type=float_range(1.0, 600.0), default=60.0,
                    help="HTTP read timeout in seconds (connect is 10s)")
    ap.add_argument("--limit-projects", type=positive_int, default=None,
                    metavar="N", help="Stop after N projects (safe testing)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Enumerate scope only; make zero issue calls")
    verb = ap.add_mutually_exclusive_group()
    verb.add_argument("--verbose", action="store_true", help="Debug logging")
    verb.add_argument("--quiet", action="store_true", help="Warnings only")
    return ap


def configure_logging(args: argparse.Namespace) -> None:
    level = (logging.DEBUG if args.verbose
             else logging.WARNING if args.quiet else logging.INFO)
    if not log.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(handler)
    log.setLevel(level)


# --------------------------------------------------------------------------- #
# Fetch pipeline
# --------------------------------------------------------------------------- #
def resolve_scope(client: ApiClient,
                  args: argparse.Namespace) -> list[tuple[dict, str]]:
    """Returns [(workspace, team_label), ...] after workspace/team filters."""
    name_filter = args.workspace or args.workspace_contains
    workspaces = list_workspaces(client, name_filter)
    if args.workspace:
        # filter[workspace] is a server-side substring search; enforce the
        # exact (case-insensitive) match the flag promises, client-side.
        want = args.workspace.casefold()
        workspaces = [w for w in workspaces
                      if (w.get("name") or "").casefold() == want]
    if not workspaces:
        raise FatalError("No workspaces matched. Check credentials, region, "
                         "or the --workspace/--workspace-contains value.")

    wanted_teams = None
    if args.team:
        wanted_teams = {t.strip().casefold()
                        for t in args.team.split(",") if t.strip()}

    scoped: list[tuple[dict, str]] = []
    for ws in workspaces:
        team_names: list[str] = []
        if wanted_teams is not None or args.label_teams:
            teams = list_workspace_teams(client, ws.get("id", ""))
            team_names = [t.get("name", "") for t in teams if t.get("name")]
        if wanted_teams is not None:
            have = {t.casefold() for t in team_names}
            if not (wanted_teams & have):
                continue
        scoped.append((ws, ";".join(team_names)))
    if not scoped:
        raise FatalError("No workspaces matched the --team filter.")
    return scoped


def fetch_all_rows(client: ApiClient, scoped: list[tuple[dict, str]],
                   args: argparse.Namespace, weights: Weights) -> list[Row]:
    # Enumerate projects serially (cheap), then fetch issue lists concurrently
    # with deterministic output ordering.
    tasks: list[tuple[dict, str, dict]] = []
    for ws, team_label in scoped:
        ws_name = ws.get("name", "")
        log.info("[workspace] %s  teams=[%s]", ws_name, team_label)
        for proj in list_projects(client, ws.get("id", "")):
            tasks.append((ws, team_label, proj))
            if args.limit_projects and len(tasks) >= args.limit_projects:
                break
        if args.limit_projects and len(tasks) >= args.limit_projects:
            log.info("--limit-projects %d reached", args.limit_projects)
            break

    if args.dry_run:
        log.info("[dry-run] would fetch issues for %d project(s) across %d "
                 "workspace(s); zero issue calls made.",
                 len(tasks), len({t[0].get('id') for t in tasks}))
        for ws, team_label, proj in tasks:
            log.info("[dry-run]   %s / %s", ws.get("name", ""),
                     proj.get("name", ""))
        return []

    total = len(tasks)
    results: dict[int, list[Row]] = {}
    counter_lock = threading.Lock()
    done = 0

    def fetch(idx: int, ws: dict, team_label: str, proj: dict) -> None:
        nonlocal done
        proj_name = proj.get("name", "")
        out: list[Row] = []
        try:
            issues = list_project_issues(client, ws.get("id", ""),
                                         proj.get("id", ""))
        except requests.HTTPError as exc:
            log.warning("  ! skip %s: %s", proj_name, exc)
            results[idx] = out
            return
        for issue in issues:
            out.append(build_row(ws.get("name", ""), team_label, proj, issue,
                                 weights))
        results[idx] = out
        with counter_lock:
            done += 1
            log.info("  [project %d/%d] %s: %d open issues",
                     done, total, proj_name, len(issues))

    workers = min(args.workers, 8)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(fetch, i, ws, tl, pj)
                   for i, (ws, tl, pj) in enumerate(tasks)]
        for f in futures:
            f.result()  # propagate FatalError / unexpected exceptions

    rows: list[Row] = []
    for i in range(total):
        rows.extend(results.get(i, []))
    return rows


def apply_filters(rows: list[Row], args: argparse.Namespace) -> list[Row]:
    def keep(r: Row) -> bool:
        if args.fixable_only and r.fixable != "yes":
            return False
        if args.min_cvss > 0 and r.cvss3 < args.min_cvss:
            return False
        if args.min_epss > 0 and r.epss_score < args.min_epss:
            return False
        if args.min_severity > 0 and r.severity < args.min_severity:
            return False
        if args.exploited_only and r.exploit_observed != "yes":
            return False
        if args.direct_only and r.direct != "direct":
            return False
        if args.transitive_only and r.direct != "transitive":
            return False
        return True
    return [r for r in rows if keep(r)]


def check_thresholds(rows: list[Row], args: argparse.Namespace) -> int:
    breached = []
    if args.fail_on_exploited and any(r.exploit_observed == "yes"
                                      for r in rows):
        breached.append("--fail-on-exploited")
    if args.fail_on_risk is not None and any(r.risk_score >= args.fail_on_risk
                                             for r in rows):
        breached.append(f"--fail-on-risk {args.fail_on_risk}")
    if args.fail_on_count is not None and len(rows) >= args.fail_on_count:
        breached.append(f"--fail-on-count {args.fail_on_count}")
    if breached:
        log.warning("CI gate breached: %s", ", ".join(breached))
        return EXIT_THRESHOLD
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args)

    weights = Weights(cvss=args.w_cvss, epss=args.w_epss,
                      exploit=args.w_exploit, method=args.w_method,
                      legacy=args.legacy_scoring)
    log.info("%s %s | region=%s | weights: cvss=%.1f epss=%.1f exploit=%.1f "
             "method=%.1f spread=%.1f%s",
             TOOL_NAME, TOOL_VERSION, args.region, weights.cvss, weights.epss,
             weights.exploit, weights.method, args.spread_weight,
             " [LEGACY SCORING]" if weights.legacy else "")

    client = ApiClient(REGION_HOSTS[args.region], retries=args.retries,
                       base_delay=args.retry_delay, read_timeout=args.timeout)

    scoped = resolve_scope(client, args)
    rows = fetch_all_rows(client, scoped, args, weights)
    if args.dry_run:
        return EXIT_OK

    rows, merged = dedup_rows(rows)
    if merged:
        log.info("Merged %d duplicate vulnerability/library record(s).",
                 merged)

    rows = apply_filters(rows, args)
    rows.sort(key=lambda r: r.risk_score, reverse=True)

    if not rows:
        print("No issues matched the filters.")
        return check_thresholds(rows, args)

    libs = library_rollup(rows, spread_weight=args.spread_weight,
                          legacy=args.legacy_scoring)

    row_dicts = [asdict(r) for r in rows]
    if args.format == "csv":
        write_csv(args.out, row_dicts, args.force)
        write_csv(args.exec_out, libs, args.force)
    elif args.format == "json":
        write_json(args.out, row_dicts, args.force)
        write_json(args.exec_out, libs, args.force)
    elif args.format == "jsonl":
        write_jsonl(args.out, row_dicts, args.force)
        write_csv(args.exec_out, libs, args.force)
    elif args.format == "sarif":
        write_json(args.out, build_sarif(rows), args.force)
        write_csv(args.exec_out, libs, args.force)

    if args.md_out:
        scope = (args.workspace or args.workspace_contains or args.team
                 or "ALL workspaces")
        md = build_markdown(rows, libs, scope, args.top, args.top_libs)
        atomic_write(args.md_out, args.force, lambda fh: fh.write(md),
                     newline=None)

    print_console(rows, libs, args, merged)

    print(f"\n{args.format.upper()}: {args.out}  (per-issue)")
    print(f"{'JSON' if args.format == 'json' else 'CSV'}: {args.exec_out}  "
          f"(library rollup)")
    if args.md_out:
        print(f"MD: {args.md_out}  (markdown report)")

    return check_thresholds(rows, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FatalError as exc:
        log.error("%s", exc)
        sys.exit(EXIT_ERROR)
    except requests.HTTPError as exc:
        log.error("%s", exc)
        sys.exit(EXIT_ERROR)
    except KeyboardInterrupt:
        sys.exit(EXIT_ERROR)

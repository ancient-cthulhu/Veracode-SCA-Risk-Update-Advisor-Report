#!/usr/bin/env python3
"""
Two outputs from one run:
  1. ACTIONABLE  - per-issue rows ranked by risk, with Update Advisor fix target
  2. EXECUTIVE   - top-N worst libraries rolled up across the whole scope

Scope is filterable by --workspace and/or --team.

Data sourced from the SCA Agent API (base: https://api.veracode.com/srcclr):
  getWorkspaces         GET /v3/workspaces
  getWorkspaceTeams     GET /v3/workspaces/{id}/teams
  getWorkspaceProjects  GET /v3/workspaces/{id}/projects
  getProjectIssues      GET /v3/workspaces/{id}/projects/{projectId}/issues

Fields used:
  IssueSummary.library_updated_version / library_updated_release_date  (Update Advisor)
  IssueSummary.severity / vulnerable_method
  VulnerabilitySummary.cve / cvss3_score / cvss2_score
  Exploitability.epss_score / epss_percentile / exploit_observed / exploit_source

AUTH
----
    pip install veracode-api-signing requests
    export VERACODE_API_KEY_ID=...     (or ~/.veracode/credentials)
    export VERACODE_API_KEY_SECRET=...
The SCA REST API requires a HUMAN user credential, not an API service account.

USAGE
-----
    python sca_risk_report.py
    python sca_risk_report.py --workspace "My Team WS"
    python sca_risk_report.py --team "Payments"
    python sca_risk_report.py --fixable-only --min-cvss 7 --min-epss 0.3
    python sca_risk_report.py --exploited-only
    python sca_risk_report.py --region eu --top-libs 10
"""

import argparse
import csv
import sys
import time
from dataclasses import dataclass, asdict

import requests

try:
    from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
except ImportError:
    sys.exit("Missing dependency. Run: pip install veracode-api-signing requests")

REGION_HOSTS = {
    "us": "https://api.veracode.com/srcclr",
    "eu": "https://api.veracode.eu/srcclr",
    "fed": "https://api.veracode.us/srcclr",
}

PAGE_SIZE = 500


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
def get_json(url, params=None, retries=3):
    auth = RequestsAuthPluginVeracodeHMAC()
    resp = None
    for attempt in range(retries):
        resp = requests.get(url, params=params, auth=auth, timeout=60)
        if resp.status_code == 429:
            time.sleep(2 ** attempt)
            continue
        resp.raise_for_status()
        return resp.json()
    resp.raise_for_status()


def embedded_list(payload):
    """SCA responses are HAL. Collections live under _embedded keyed by name."""
    emb = payload.get("_embedded") or {}
    if isinstance(emb, list):
        return emb
    for value in emb.values():
        if isinstance(value, list):
            return value
    return []


def paged(base_url, params=None):
    params = dict(params or {})
    params["size"] = PAGE_SIZE
    page = 0
    while True:
        params["page"] = page
        data = get_json(base_url, params=params)
        items = embedded_list(data)
        for it in items:
            yield it
        meta = data.get("page") or {}
        total_pages = meta.get("total_pages", 1)
        page += 1
        if page >= total_pages or not items:
            break


# --------------------------------------------------------------------------- #
# API wrappers
# --------------------------------------------------------------------------- #
def list_workspaces(host, name_filter=None):
    params = {}
    if name_filter:
        params["filter[workspace]"] = name_filter
    return list(paged(f"{host}/v3/workspaces", params))


def list_workspace_teams(host, workspace_id):
    try:
        return list(paged(f"{host}/v3/workspaces/{workspace_id}/teams"))
    except requests.HTTPError:
        return []


def list_projects(host, workspace_id):
    return list(paged(f"{host}/v3/workspaces/{workspace_id}/projects"))


def list_project_issues(host, workspace_id, project_id):
    url = f"{host}/v3/workspaces/{workspace_id}/projects/{project_id}/issues"
    params = {"status": "open", "type": ["vulnerability", "library"]}
    return list(paged(url, params))


# --------------------------------------------------------------------------- #
# Risk model
# --------------------------------------------------------------------------- #
@dataclass
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


def compute_risk(cvss3, epss, exploit_observed, vuln_method):
    """
    Explainable 0-100 prioritization score. Tune weights to taste.
      CVSS3 (0-10)  -> up to 50   likelihood-agnostic technical severity
      EPSS  (0-1)   -> up to 30   probability of exploitation in the wild
      observed exploit (KEV etc.) -> +15
      reachable vulnerable method -> +5
    """
    score = (cvss3 or 0) * 5.0
    score += (epss or 0) * 30.0
    if exploit_observed:
        score += 15.0
    if vuln_method:
        score += 5.0
    return round(min(score, 100.0), 2)


def build_row(ws_name, ws_team, proj, issue):
    lib = issue.get("library") or {}
    vuln = issue.get("vulnerability") or {}
    exp = vuln.get("exploitability") or {}

    safe_version = issue.get("library_updated_version") or ""
    exploit_observed = bool(exp.get("exploit_observed"))
    vuln_method = bool(issue.get("vulnerable_method"))
    cvss3 = vuln.get("cvss3_score") or 0.0
    epss = exp.get("epss_score") or 0.0

    return Row(
        workspace=ws_name,
        team=ws_team,
        project=proj.get("name", ""),
        project_id=proj.get("id", ""),
        languages=",".join(proj.get("languages") or []),
        issue_type=issue.get("issue_type", ""),
        library=lib.get("name", ""),
        version=lib.get("version", ""),
        direct="direct" if lib.get("direct") else "transitive",
        cve=vuln.get("cve", ""),
        cvss3=cvss3,
        cvss2=vuln.get("cvss2_score") or 0.0,
        epss_score=epss,
        epss_percentile=exp.get("epss_percentile") or 0.0,
        exploit_observed="yes" if exploit_observed else "",
        exploit_source=exp.get("exploit_source", "") or "",
        vulnerable_method="yes" if vuln_method else "",
        severity=issue.get("severity") or 0.0,
        fixable="yes" if safe_version else "no",
        safe_version=safe_version,
        safe_release_date=issue.get("library_updated_release_date", "") or "",
        risk_score=compute_risk(cvss3, epss, exploit_observed, vuln_method),
    )


# --------------------------------------------------------------------------- #
# Executive rollup: worst libraries across the whole scope
# --------------------------------------------------------------------------- #
def library_rollup(rows):
    """
    Aggregate by library name across every repo in scope.
    Ranked by an org-level exposure score:
        max single-issue risk  +  spread bonus (repos affected)
    """
    agg = {}
    for r in rows:
        if not r.library:
            continue
        b = agg.setdefault(r.library, {
            "library": r.library,
            "repos": set(),
            "versions": set(),
            "issues": 0,
            "vulns": set(),
            "max_cvss": 0.0,
            "max_epss": 0.0,
            "exploited": 0,
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
        if r.fixable == "yes":
            b["fixable_issues"] += 1
            if r.safe_version:
                b["safe_targets"].add(r.safe_version)
        b["max_risk"] = max(b["max_risk"], r.risk_score)

    out = []
    for b in agg.values():
        repo_n = len(b["repos"])
        # org exposure: worst issue risk plus a spread bonus, capped
        exposure = round(min(b["max_risk"] + (repo_n - 1) * 5.0, 100.0), 1)
        out.append({
            "library": b["library"],
            "repos_affected": repo_n,
            "issues": b["issues"],
            "distinct_cves": len(b["vulns"]),
            "max_cvss3": round(b["max_cvss"], 1),
            "max_epss": round(b["max_epss"], 4),
            "exploited_issues": b["exploited"],
            "fixable_issues": b["fixable_issues"],
            "fully_fixable": "yes" if b["fixable_issues"] == b["issues"] else "partial" if b["fixable_issues"] else "no",
            "safe_versions": ",".join(sorted(b["safe_targets"])[:5]),
            "versions_in_use": ",".join(sorted(b["versions"])[:5]),
            "exposure_score": exposure,
        })
    out.sort(key=lambda d: (d["exposure_score"], d["issues"]), reverse=True)
    return out


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Veracode SCA risk + Update Advisor report")
    ap.add_argument("--region", choices=REGION_HOSTS, default="us")
    ap.add_argument("--workspace", help="Filter to a single workspace by name")
    ap.add_argument("--team", help="Filter to workspaces belonging to this team name")
    ap.add_argument("--fixable-only", action="store_true",
                    help="Only issues Update Advisor can fix")
    ap.add_argument("--min-cvss", type=float, default=0.0)
    ap.add_argument("--min-epss", type=float, default=0.0)
    ap.add_argument("--exploited-only", action="store_true",
                    help="Only vulns with an observed exploit (KEV etc.)")
    ap.add_argument("--out", default="sca_actionable.csv",
                    help="Per-issue actionable CSV path")
    ap.add_argument("--exec-out", default="sca_executive_libraries.csv",
                    help="Executive library-rollup CSV path")
    ap.add_argument("--top", type=int, default=25, help="Top issues to print")
    ap.add_argument("--top-libs", type=int, default=10, help="Top libraries to print")
    args = ap.parse_args()

    host = REGION_HOSTS[args.region]
    need_teams = bool(args.team)
    rows = []

    workspaces = list_workspaces(host, args.workspace)
    if not workspaces:
        sys.exit("No workspaces returned. Check credentials, region, or --workspace name.")

    for ws in workspaces:
        ws_name = ws.get("name", "")
        ws_id = ws.get("id", "")

        # resolve teams for this workspace (needed for --team filter and labeling)
        team_names = []
        if need_teams or True:
            teams = list_workspace_teams(host, ws_id)
            team_names = [t.get("name", "") for t in teams if t.get("name")]

        if args.team and args.team not in team_names:
            continue

        ws_team_label = ";".join(team_names)
        print(f"[workspace] {ws_name}  teams=[{ws_team_label}]", file=sys.stderr)

        for proj in list_projects(host, ws_id):
            proj_name = proj.get("name", "")
            try:
                issues = list_project_issues(host, ws_id, proj["id"])
            except requests.HTTPError as e:
                print(f"  ! skip {proj_name}: {e}", file=sys.stderr)
                continue
            print(f"  [project] {proj_name}: {len(issues)} open issues", file=sys.stderr)
            for issue in issues:
                rows.append(build_row(ws_name, ws_team_label, proj, issue))

    # ---- filters (applied to the actionable set) ----
    def keep(r):
        if args.fixable_only and r.fixable != "yes":
            return False
        if args.min_cvss > 0 and r.cvss3 < args.min_cvss:
            return False
        if args.min_epss > 0 and r.epss_score < args.min_epss:
            return False
        if args.exploited_only and r.exploit_observed != "yes":
            return False
        return True

    rows = [r for r in rows if keep(r)]
    rows.sort(key=lambda r: r.risk_score, reverse=True)

    if not rows:
        print("No issues matched the filters.")
        return

    # ---- write actionable CSV ----
    with open(args.out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        for r in rows:
            writer.writerow(asdict(r))

    # ---- executive rollup ----
    libs = library_rollup(rows)
    with open(args.exec_out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(libs[0].keys()))
        writer.writeheader()
        writer.writerows(libs)

    # ======================= CONSOLE: EXECUTIVE ========================= #
    scope = args.workspace or args.team or "ALL workspaces"
    print("\n" + "=" * 78)
    print(f"EXECUTIVE SUMMARY  |  scope: {scope}")
    print("=" * 78)
    total_repos = len({r.project for r in rows})
    fixable_n = sum(1 for r in rows if r.fixable == "yes")
    exploited_n = sum(1 for r in rows if r.exploit_observed == "yes")
    print(f"Open issues: {len(rows)}   Repos affected: {total_repos}")
    print(f"Update Advisor fixable: {fixable_n} ({fixable_n * 100 // len(rows)}%)   "
          f"With observed exploit: {exploited_n}")

    print(f"\nTop {args.top_libs} highest-exposure libraries:")
    hdr = (f"{'EXPO':>5} {'LIBRARY':<30} {'REPOS':>5} {'ISS':>4} {'CVEs':>4} "
           f"{'CVSS':>4} {'EPSS':>6} {'EXPL':>4} {'FIX':<7} SAFE->")
    print(hdr)
    for d in libs[:args.top_libs]:
        print(f"{d['exposure_score']:>5.0f} {d['library'][:29]:<30} "
              f"{d['repos_affected']:>5} {d['issues']:>4} {d['distinct_cves']:>4} "
              f"{d['max_cvss3']:>4.1f} {d['max_epss']:>6.3f} {d['exploited_issues']:>4} "
              f"{d['fully_fixable']:<7} {d['safe_versions'][:20]}")

    # ======================= CONSOLE: PER-REPO ========================== #
    per_repo = {}
    for r in rows:
        b = per_repo.setdefault(r.project, {"total": 0, "fixable": 0, "max_risk": 0.0})
        b["total"] += 1
        b["fixable"] += 1 if r.fixable == "yes" else 0
        b["max_risk"] = max(b["max_risk"], r.risk_score)

    print("\nPer-repo risk (sorted by max risk):")
    print(f"{'REPO':<40} {'ISSUES':>7} {'FIXABLE':>8} {'MAXRISK':>8}")
    for repo, b in sorted(per_repo.items(), key=lambda kv: kv[1]["max_risk"], reverse=True):
        print(f"{repo[:39]:<40} {b['total']:>7} {b['fixable']:>8} {b['max_risk']:>8.1f}")

    # ======================= CONSOLE: ACTIONABLE ======================== #
    print(f"\nTop {args.top} highest-risk issues (actionable):")
    print(f"{'RISK':>5} {'CVSS3':>5} {'EPSS':>6} {'CVE':<16} {'LIB':<26} {'FIX->':<14} REPO")
    for r in rows[:args.top]:
        fix = r.safe_version if r.fixable == "yes" else "-"
        print(f"{r.risk_score:>5.0f} {r.cvss3:>5.1f} {r.epss_score:>6.3f} "
              f"{r.cve[:15]:<16} {r.library[:25]:<26} {fix[:13]:<14} {r.project[:30]}")

    print(f"\nCSV: {args.out}  (per-issue)")
    print(f"CSV: {args.exec_out}  (library rollup)")


if __name__ == "__main__":
    main()

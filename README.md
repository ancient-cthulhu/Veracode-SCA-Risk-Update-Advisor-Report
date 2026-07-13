# Veracode SCA Risk & Update Advisor Report

Pulls actionable SCA agent-based scan data across an entire Veracode tenant and produces two reports in a single run:

* A per-issue **actionable** report ranked by exploit-aware risk, including remediation guidance, fix age, and KEV context.
* An **executive** library rollup that identifies the highest-risk dependencies across the organization while separating ecosystems to avoid cross-language library collisions.

Scope can be filtered by workspace, team, severity, CVSS, EPSS, exploit status, dependency type, and Update Advisor availability. Supported output formats include CSV, JSON, JSONL, SARIF, and Markdown, with built-in CI/CD gating.

---

# How It Works

For each workspace in scope, the script:

1. Resolves workspace teams (used for `--team` filtering and report labeling; can be skipped with `--no-label-teams`).
2. Enumerates all projects in the workspace.
3. Retrieves open `vulnerability` and `library` issues concurrently (bounded by `--workers`).
4. Extracts CVE, CVSS, EPSS, exploit status, reachable vulnerable method, severity, and Update Advisor remediation information.
5. Deduplicates records where the same CVE on the same library/version/project appears as both a vulnerability and library issue.
6. Calculates an explainable risk score for every issue.
7. Produces an executive library exposure ranking aggregated by ecosystem and library name.

All operations use read-only `GET` requests against the SCA Agent API. The tool never modifies data, and unit tests verify that no non-GET requests exist.

> Update Advisor recommendations come directly from the issue feed using `IssueSummary.library_updated_version` and `library_updated_release_date`. No additional API calls are required.

---

# Prerequisites

* Veracode Platform **human user** API credentials (API service accounts are not supported by the SCA REST API).
* Access to the target workspaces.
* Network access to the appropriate regional SCA API endpoint.
* Python 3.10 or newer.

---

# Read-Only Operation

The tool is entirely read-only.

There is no apply mode and no confirmation prompt. Every execution reads scan results and writes reports locally. `--dry-run` validates scope without retrieving issue data.

---

# Quick Start

```bash
export VERACODE_API_KEY_ID="..."
export VERACODE_API_KEY_SECRET="..."

# Entire tenant
python script.py

# Single workspace
python script.py --workspace "acme-dev"

# Multiple teams, only fixable issues, higher risk
python script.py --team "Payments,Platform" --fixable-only --min-cvss 7 --min-epss 0.3

# Fail CI if exploited vulnerabilities exist
python script.py --exploited-only --fail-on-exploited --format sarif --out sca.sarif

# Preview scope only
python script.py --dry-run
```

By default, the tool creates:

* `sca_actionable.csv`
* `sca_executive_libraries.csv`

Both files are written with `0600` permissions and existing files are preserved unless `--force` is supplied.

---

# Installation

```bash
pip install -r requirements.txt
```

Python 3.10+ is required.

---

# Authentication

Uses Veracode HMAC authentication.

Credentials may be supplied via environment variables or `~/.veracode/credentials`.

| Variable                  | Purpose        |
| ------------------------- | -------------- |
| `VERACODE_API_KEY_ID`     | API key ID     |
| `VERACODE_API_KEY_SECRET` | API key secret |

Only **human user credentials** are supported.

Authentication failures immediately exit with status code **2**.

Signed URLs, query parameters, and authentication headers are never logged.

---

# Command Line Options

## Scope

| Flag                        | Description                             |
| --------------------------- | --------------------------------------- |
| `--region`                  | API region (`us`, `eu`, `fed`)          |
| `--workspace NAME`          | Exact workspace name (case-insensitive) |
| `--workspace-contains TEXT` | Workspace substring search              |
| `--team NAMES`              | Comma-separated team names              |
| `--no-label-teams`          | Skip team lookups                       |

## Filters

Applied to both actionable and executive reports.

| Flag                | Description                                 |
| ------------------- | ------------------------------------------- |
| `--fixable-only`    | Only issues with Update Advisor remediation |
| `--min-cvss`        | Minimum CVSS score                          |
| `--min-epss`        | Minimum EPSS probability                    |
| `--min-severity`    | Minimum Veracode severity                   |
| `--exploited-only`  | Only actively exploited vulnerabilities     |
| `--direct-only`     | Only direct dependencies                    |
| `--transitive-only` | Only transitive dependencies                |

## Output

| Flag              | Description                 |
| ----------------- | --------------------------- |
| `--out FILE`      | Actionable report output    |
| `--exec-out FILE` | Executive report output     |
| `--md-out FILE`   | Markdown report             |
| `--format`        | csv, json, jsonl, or sarif  |
| `--force`         | Overwrite existing files    |
| `--top`           | Console issue count         |
| `--top-libs`      | Console library count       |
| `--group-by`      | repo, team, cve, or library |

## Risk Scoring

| Flag               | Description                  |
| ------------------ | ---------------------------- |
| `--w-cvss`         | CVSS weight                  |
| `--w-epss`         | EPSS weight                  |
| `--w-exploit`      | Exploit bonus                |
| `--w-method`       | Reachable method bonus       |
| `--spread-weight`  | Executive spread weighting   |
| `--legacy-scoring` | Use previous scoring formula |

Active weights are displayed at runtime.

## CI/CD Gates

| Flag                  | Description                              |
| --------------------- | ---------------------------------------- |
| `--fail-on-exploited` | Exit if exploited vulnerabilities exist  |
| `--fail-on-risk N`    | Exit if any issue exceeds risk threshold |
| `--fail-on-count N`   | Exit if issue count exceeds threshold    |

Exit codes:

* **0** Success
* **1** Gate threshold exceeded
* **2** Runtime, configuration, or authentication error

## Runtime

| Flag                    | Description                |
| ----------------------- | -------------------------- |
| `--workers`             | Concurrent workers (max 8) |
| `--retries`             | Retry count                |
| `--retry-delay`         | Base retry delay           |
| `--timeout`             | HTTP timeout               |
| `--limit-projects`      | Limit projects processed   |
| `--dry-run`             | Enumerate scope only       |
| `--verbose` / `--quiet` | Logging controls           |

Filters are applied before both reports are generated, ensuring consistent reporting.

---

# Risk Scoring

Each issue receives an explainable 0–100 risk score.

```
risk =
    cvss3 * 5
  + sqrt(epss) * 30
  + 15 if exploited
  + 5 if reachable vulnerable method
  + 2 if direct dependency and reachable method
  + severity * 0.1
```

The score is capped at **100**.

The square root of EPSS gives greater weight to meaningful probability ranges while preserving the 0–1 scale.

All weights are configurable.

---

# Executive Library Ranking

Libraries are grouped by:

```
(language, library name)
```

to prevent collisions between ecosystems.

Exposure is calculated as:

```
exposure_score =
min(
    highest_issue_risk +
    spread_weight × log2(repositories_affected),
    100
)
```

Each library includes:

* repositories affected
* total issues
* distinct CVEs
* maximum CVSS
* maximum EPSS
* exploited issue count
* KEV issue count
* fixability (`yes`, `partial`, `no`)
* safe versions
* versions in use
* language

Console output includes:

1. Executive summary
2. Grouped rollup
3. Top actionable issues

---

# Regions

| Region  | Flag  |
| ------- | ----- |
| US      | `us`  |
| EU      | `eu`  |
| Federal | `fed` |

Only supported Veracode endpoints are allowed.

---

# Output Files

| File                          | Description                                 |
| ----------------------------- | ------------------------------------------- |
| `sca_actionable.csv`          | One row per issue ranked by risk            |
| `sca_executive_libraries.csv` | Library exposure summary                    |
| Markdown report               | Executive summary and remediation metrics   |
| SARIF                         | SARIF 2.1.0 output for GitHub code scanning |

Files are written atomically using temporary files and renamed only after successful completion.

Existing files require `--force`.

## Actionable Report Columns

```
workspace
team
project
project_id
languages
issue_type
library
version
direct
cve
cvss3
cvss2
epss_score
epss_percentile
exploit_observed
exploit_source
vulnerable_method
severity
fixable
safe_version
safe_release_date
risk_score
remediation
fix_age_days
kev
language
```

## Executive Report Columns

```
library
language
repos_affected
issues
distinct_cves
max_cvss3
max_epss
exploited_issues
kev_issues
fixable_issues
fully_fixable
safe_versions
versions_in_use
exposure_score
```

`fully_fixable` values:

* yes
* partial
* no

## CSV Injection Protection

Any value beginning with:

```
=
+
-
@
TAB
CR
```

is prefixed with a single quote before being written, preventing spreadsheet formula execution.

---

# API Endpoints

| Operation          | Endpoint                                              |
| ------------------ | ----------------------------------------------------- |
| List workspaces    | `GET /v3/workspaces`                                  |
| Workspace teams    | `GET /v3/workspaces/{id}/teams`                       |
| Workspace projects | `GET /v3/workspaces/{id}/projects`                    |
| Project issues     | `GET /v3/workspaces/{id}/projects/{projectId}/issues` |

All HAL pagination is handled automatically.

---

# Concurrency

Issue retrieval uses up to eight worker threads.

Each worker maintains its own pooled HTTP session and HMAC signer.

A shared throttling mechanism honors server rate limiting and `Retry-After` headers.

Output remains deterministic regardless of worker count.

Requests include a `veracode-sca-risk-report/<version>` User-Agent.

---

# Troubleshooting

| Problem                | Resolution                                                 |
| ---------------------- | ---------------------------------------------------------- |
| HTTP 401               | Use human user credentials instead of API service accounts |
| HTTP 403               | Verify workspace access                                    |
| No matching workspaces | Check region or workspace name                             |
| Empty reports          | Relax filters                                              |
| Existing file error    | Use `--force`                                              |
| Frequent rate limiting | Reduce `--workers` or increase retry delay                 |

---

# Notes

* Both `vulnerability` and `library` issue types are processed so Update Advisor recommendations are captured even when no CVE exists.
* Duplicate vulnerability/library records are merged while preserving the richest available information.
* Team filtering requires workspace team lookups because the workspace API does not expose team membership.
* Library language is determined from ecosystem metadata with project language as a fallback.

---

# Support

This is a community-maintained tool and is not officially supported by Veracode.

When reporting issues, include:

* command used
* region
* redacted API response

The tool never logs signed headers or query strings.

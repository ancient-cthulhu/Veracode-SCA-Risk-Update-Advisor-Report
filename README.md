# Veracode SCA Risk & Update Advisor Report

Pulls actionable SCA agent-based scan data across an entire Veracode tenant and produces two views in one run: 

- Per-issue **actionable** report ranked by exploit-aware risk.
-  An **executive** rollup of the worst libraries across the whole scope. Scope is filterable by workspace and team, with severity, EPSS, exploit, and Update Advisor filters.

-----

## How It Works

For each workspace in scope, the script:

1. Resolves the workspace's teams via the SCA Agent API (used for the `--team` filter and to label every row)
1. Enumerates all projects (repos) in the workspace
1. Pulls open `vulnerability` and `library` issues per project
1. Extracts CVE, CVSS, EPSS, observed-exploit, reachable-vulnerable-method, severity, and the Update Advisor safe-version target for each issue
1. Scores every issue with an explainable risk model and writes the ranked per-issue CSV
1. Aggregates issues by library name across all repos into an executive exposure ranking

All calls are read-only `GET`s against the SCA Agent API. The script never writes to the platform.

> **Update Advisor data comes straight from the issues feed.** The safe upgrade target is read from `IssueSummary.library_updated_version` and `library_updated_release_date`, populated only on `issue_type=library`. No separate Update Advisor call is needed.

-----

## Prerequisites

Confirm the following before a run.

- Veracode Platform: a **human user** API credential. The SCA REST API does not accept API service accounts.
- Veracode Platform: visibility into the workspaces you want to report on (workspace membership or team association).
- Network: outbound access to the SCA API host for your region (see [Regions](#regions)).

-----

## Modes

The script is **read-only**. There is no apply mode and no confirmation prompt. Every run only reads scan results and writes local CSV and console output.

-----

## Quickstart

```bash
export VERACODE_API_KEY_ID="..."
export VERACODE_API_KEY_SECRET="..."

# Whole tenant
python script.py

# One workspace
python script.py --workspace "acme-dev"

# One team, only what Update Advisor can fix, high severity and likelihood
python script.py --team "Payments" --fixable-only --min-cvss 7 --min-epss 0.3
```

Writes two files to the current directory:

- `sca_actionable.csv` - one row per issue, ranked by risk
- `sca_executive_libraries.csv` - library rollup, ranked by exposure

-----

## Requirements

```bash
pip install requests
pip install veracode-api-signing
```

Python 3.8+

-----

## Credentials

Uses Veracode HMAC signing. Supply credentials by environment variable or `~/.veracode/credentials`.

|Variable                    |Purpose                          |Account Type                 |
|----------------------------|---------------------------------|-----------------------------|
|`VERACODE_API_KEY_ID`       |Signs every SCA API request      |**Human user account**       |
|`VERACODE_API_KEY_SECRET`   |Signs every SCA API request      |Same as above                |

> **Human user only.** The SCA REST API rejects API service account credentials. Generate the key pair under **Veracode Platform > Account > API Credentials** on a human user with visibility into the target workspaces.

-----

## Command-Line Reference

### Scope

|Flag              |Default|Description                                                        |
|------------------|-------|-------------------------------------------------------------------|
|`--region`        |`us`   |SCA API region: `us`, `eu`, or `fed`. See [Regions](#regions).     |
|`--workspace NAME`|-      |Restrict to a single workspace by exact name.                      |
|`--team NAME`     |-      |Restrict to workspaces associated with this team name.             |

### Filters *(applied to both the actionable and executive views)*

|Flag               |Default|Description                                                       |
|-------------------|-------|------------------------------------------------------------------|
|`--fixable-only`   |off    |Only issues Update Advisor can fix (a safe version exists).       |
|`--min-cvss FLOAT` |`0`    |Drop issues below this CVSS v3 score.                             |
|`--min-epss FLOAT` |`0`    |Drop issues below this EPSS probability (0-1).                    |
|`--exploited-only` |off    |Only vulns with an observed exploit (KEV or equivalent source).   |

### Output

|Flag             |Default                         |Description                          |
|-----------------|--------------------------------|-------------------------------------|
|`--out FILE`     |`sca_actionable.csv`            |Per-issue actionable CSV path.       |
|`--exec-out FILE`|`sca_executive_libraries.csv`   |Executive library-rollup CSV path.   |
|`--top N`        |`25`                            |Top issues printed to console.       |
|`--top-libs N`   |`10`                            |Top libraries printed to console.    |

> **Filters shape both views.** The executive rollup is computed after filters run, so `--fixable-only` or `--min-cvss` narrows the top-libraries table as well as the per-issue CSV. Run with no filters for the full org-wide picture.

-----

## Risk Scoring

Each issue gets an explainable 0-100 `risk_score`. Weights are defined in `compute_risk()` and are meant to be tuned.

|Signal                              |Contribution           |
|------------------------------------|-----------------------|
|CVSS v3 score (0-10)                |up to 50 (`score x 5`) |
|EPSS probability (0-1)              |up to 30 (`score x 30`)|
|Observed exploit (KEV etc.)         |flat +15               |
|Reachable vulnerable method         |flat +5                |

The actionable CSV and the top-issues console table are sorted by this score descending.

-----

## Executive Summary

The executive rollup aggregates issues by **library name** across every repo in scope and ranks by an `exposure_score`:

```
exposure_score = min( worst single-issue risk + (repos_affected - 1) x 5, 100 )
```

This surfaces libraries that are both high-risk and widespread. Each row reports repos affected, total issues, distinct CVEs, max CVSS3, max EPSS, count of exploited issues, Update Advisor fixability (`yes` / `partial` / `no`), the safe version targets, and the versions currently in use.

The console prints, in order: the executive block, a per-repo risk rollup, and the top actionable issues.

-----

## Regions

|Region|Flag value|SCA API base                       |
|------|----------|-----------------------------------|
|US    |`us`      |`https://api.veracode.com/srcclr`  |
|EU    |`eu`      |`https://api.veracode.eu/srcclr`   |
|Fed   |`fed`     |`https://api.veracode.us/srcclr`   |

-----

## Output Files

|File                            |Description                                                            |
|--------------------------------|----------------------------------------------------------------------|
|`sca_actionable.csv`            |One row per open issue, ranked by `risk_score`, with the Update Advisor safe version.|
|`sca_executive_libraries.csv`   |Libraries aggregated across scope, ranked by `exposure_score`.        |

### Actionable Columns

`workspace`, `team`, `project`, `project_id`, `languages`, `issue_type`, `library`, `version`, `direct`, `cve`, `cvss3`, `cvss2`, `epss_score`, `epss_percentile`, `exploit_observed`, `exploit_source`, `vulnerable_method`, `severity`, `fixable`, `safe_version`, `safe_release_date`, `risk_score`

### Executive Columns

`library`, `repos_affected`, `issues`, `distinct_cves`, `max_cvss3`, `max_epss`, `exploited_issues`, `fixable_issues`, `fully_fixable`, `safe_versions`, `versions_in_use`, `exposure_score`

`fully_fixable` values: `yes` (every issue has a safe version), `partial` (some do), `no` (none).

-----

## API Endpoints Used

|Operation           |Method and path                                                  |
|--------------------|-----------------------------------------------------------------|
|List workspaces     |`GET /v3/workspaces`                                             |
|List workspace teams|`GET /v3/workspaces/{id}/teams`                                 |
|List projects       |`GET /v3/workspaces/{id}/projects`                             |
|List project issues |`GET /v3/workspaces/{id}/projects/{projectId}/issues`         |

All responses are HAL-paginated; the script walks every page and extracts the embedded collection regardless of its key name.

-----

## Notes

- Both `vulnerability` and `library` issue types are pulled, so Update Advisor bumps are captured even where there is no active CVE.
- The executive rollup keys on library name, not name plus version. It answers "which components are our biggest org-wide problem." Versions in use are shown as a column.
- Team filtering resolves teams per workspace because the workspaces endpoint has no team filter and the Workspace object does not embed teams.
- `429` responses are retried with backoff.

-----

## Support

Supplied as a community tool. Not officially supported by Veracode. For issues, provide the command used, the region, and a redacted sample of the failing API response.

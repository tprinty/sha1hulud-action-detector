# Shai-Hulud Security Scanner

A comprehensive GitHub Action suite that detects the **Shai-Hulud** supply chain attack (November 24, 2025) in your organization:

1. **Package Scanner** - Scans org repos for compromised npm packages
2. **Exfiltration Scanner** - Finds malware-created repos containing stolen credentials

## Background

On November 24, 2025, over 1,000 npm packages were poisoned in a supply chain attack known as "Shai-Hulud: The Second Coming." The malicious packages:

- Inject a fake Bun runtime via `preinstall` script
- Steal NPM tokens, AWS/GCP/Azure credentials, and environment variables
- Use TruffleHog to scan for secrets
- Create GitHub Action runners named "SHA1HULUD"
- Can propagate to other packages using stolen npm tokens

**Reference:** [HelixGuard Advisory](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)

## Quick Start

### 1. Create a GitHub Token

Create a Personal Access Token (classic) with:
- `repo` scope (to read repositories and create issues)
- `read:org` scope (to list organization repositories and members)

> **Note:** The token needs write access to create issues on affected repositories and notify users.

### 2. Add the Token as a Secret

In your repository, go to **Settings → Secrets and variables → Actions** and add:
- `ORG_SCAN_TOKEN`: Your GitHub token with org read/write access

### 3. Set Up the Workflows

Copy both workflow files to your repository:
- `.github/workflows/scan-org-repos.yml` - Package scanner
- `.github/workflows/scan-exfil-repos.yml` - Exfiltration repo scanner

For scheduled scans, also set the repository variable:
- `GITHUB_ORG_NAME`: Your organization name

### 4. Run the Scans

#### Manual Trigger
Go to **Actions** and choose either:
- **Scan Organization for Shai-Hulud Compromised Packages** - Check repos for malicious packages
- **Scan for Shai-Hulud Exfiltration Repositories** - Find repos created by the malware

Enter your organization name and click "Run workflow".

#### Scheduled Scans
- Package scan runs daily at 6 AM UTC
- Exfiltration scan runs daily at 7 AM UTC

## What Gets Scanned

### Package Scanner (`scan-org-repos.yml`)

Scans organization repositories for compromised npm packages:
- All `package.json` files (including monorepo workspaces)
- `package-lock.json` for transitive dependencies
- Both public and private repositories (configurable)
- Only active (non-archived) repositories

### Exfiltration Scanner (`scan-exfil-repos.yml`)

Scans for repositories created by the malware to exfiltrate stolen credentials:
- **GitHub search** for repos with "Sha1-Hulud: The Second Coming" description
- **Organization members' public repos** for malware signatures
- **Malicious workflow files** (formatter_*.yml, discussion.yaml)
- **Rogue self-hosted runners** named "SHA1HULUD"
- **Exfiltrated secrets files** (actionsSecrets.json, etc.)

## Output

### Artifacts

**Package Scanner:**
- `scan-results.json` - Machine-readable results
- `scan-results.md` - Human-readable markdown report

**Exfiltration Scanner:**
- `exfil-scan-results.json` - Machine-readable results
- `exfil-scan-results.md` - Human-readable markdown report

### Issues Created

#### Package Scanner
If compromised packages are found, issues are created:

1. **On each affected repository** - Detailed issue with:
   - List of compromised packages found
   - Remediation steps specific to that repo
   - Links to security advisories

2. **On the scanner repository** (tracking issue) - Summary with:
   - Links to all created issues
   - Overview of affected repositories
   - Full scan report

#### Exfiltration Scanner
If malware repos are found, issues are created:

1. **On affected users' repos** - Alert notifying them that:
   - Their credentials may have been stolen
   - Suspicious repos were found on their account
   - Steps to remediate and secure their account

2. **On the scanner repository** (tracking issue) - Summary with:
   - List of all malware repos found
   - Affected organization members
   - Links to user notification issues

### Exit Code
Both workflows fail (exit code 1) if any issues are detected.

## Local Usage

You can run the scanners locally:

```bash
# Clone this repository
git clone <this-repo>
cd sha1hulud-action-detector

# Set environment variables
export GITHUB_TOKEN="your-token"
export ORG_NAME="your-org-name"

# Run the package scanner
export SCAN_PRIVATE="true"  # optional, default true
node scan-org.js

# Run the exfiltration scanner
export SCAN_MEMBERS="true"  # optional, default true
node scan-exfil-repos.js
```

## Configuration

### Package Scanner Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `org_name` | GitHub organization to scan | Required |
| `scan_private_repos` | Include private repositories | `true` |
| `max_repos` | Maximum repos to scan (0 = unlimited) | `0` |

### Exfiltration Scanner Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `org_name` | GitHub organization to scan | Required |
| `scan_members` | Scan org member public repos | `true` |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` / `ORG_SCAN_TOKEN` | GitHub token with repo and org access |
| `ORG_NAME` | Organization name |
| `SCAN_PRIVATE` | Set to "false" to skip private repos (package scanner) |
| `SCAN_MEMBERS` | Set to "false" to skip member repos (exfil scanner) |
| `MAX_REPOS` | Limit number of repos scanned (package scanner) |

## Updating the Package List

The compromised packages list is in `compromised-packages.json`. To update it:

1. Check the [HelixGuard advisory](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24) for updates
2. Edit `compromised-packages.json`
3. Commit and push

## Remediation

If compromised packages are found:

1. **Immediately update or remove** affected packages
2. **Rotate ALL credentials** that may have been exposed:
   - NPM tokens
   - GitHub Personal Access Tokens
   - AWS/GCP/Azure credentials
   - CI/CD secrets
3. **Audit GitHub Actions** for suspicious workflows:
   - Look for `.github/workflows/formatter_*.yml`
   - Check for unexpected workflow files
4. **Check for rogue runners** named "SHA1HULUD"
5. **Review git history** for unauthorized commits
6. **Revert to safe versions** - anything before November 21, 2025

## License

MIT

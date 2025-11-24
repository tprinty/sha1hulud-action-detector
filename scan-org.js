#!/usr/bin/env node

/**
 * Shai-Hulud Compromised Package Scanner
 *
 * Scans all repositories in a GitHub organization for npm packages
 * that have been compromised in the Shai-Hulud supply chain attack.
 *
 * Reference: https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

// Load compromised packages database
const compromisedData = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'compromised-packages.json'), 'utf8')
);
const COMPROMISED_PACKAGES = compromisedData.packages;

// Configuration from environment
const ORG_NAME = process.env.ORG_NAME;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const SCAN_PRIVATE = process.env.SCAN_PRIVATE !== 'false';
const MAX_REPOS = parseInt(process.env.MAX_REPOS || '0', 10);

if (!ORG_NAME) {
  console.error('Error: ORG_NAME environment variable is required');
  process.exit(1);
}

if (!GITHUB_TOKEN) {
  console.error('Error: GITHUB_TOKEN environment variable is required');
  console.error('Create a token with repo and read:org scopes');
  process.exit(1);
}

/**
 * Make a GitHub API request
 */
function githubRequest(endpoint, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, 'https://api.github.com');

    const reqOptions = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: options.method || 'GET',
      headers: {
        'User-Agent': 'shai-hulud-scanner',
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        ...options.headers
      }
    };

    const req = https.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve({ data: JSON.parse(data), headers: res.headers });
          } catch {
            resolve({ data, headers: res.headers });
          }
        } else {
          reject(new Error(`GitHub API error: ${res.statusCode} - ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
}

/**
 * Fetch all repositories in the organization with pagination
 */
async function fetchOrgRepos() {
  const repos = [];
  let page = 1;
  const perPage = 100;

  console.log(`Fetching repositories for organization: ${ORG_NAME}`);

  while (true) {
    const visibility = SCAN_PRIVATE ? 'all' : 'public';
    const { data, headers } = await githubRequest(
      `/orgs/${ORG_NAME}/repos?type=${visibility}&per_page=${perPage}&page=${page}`
    );

    if (!Array.isArray(data) || data.length === 0) break;

    // Filter for active repos (not archived)
    const activeRepos = data.filter(repo => !repo.archived);
    repos.push(...activeRepos);

    console.log(`  Fetched page ${page}: ${activeRepos.length} active repos (${data.length - activeRepos.length} archived skipped)`);

    if (MAX_REPOS > 0 && repos.length >= MAX_REPOS) {
      repos.length = MAX_REPOS;
      break;
    }

    // Check for next page
    const linkHeader = headers.link || '';
    if (!linkHeader.includes('rel="next"')) break;
    page++;
  }

  console.log(`Total active repositories to scan: ${repos.length}\n`);
  return repos;
}

/**
 * Fetch package.json content from a repository
 */
async function fetchPackageJson(repo, filePath = 'package.json') {
  try {
    const { data } = await githubRequest(
      `/repos/${ORG_NAME}/${repo.name}/contents/${filePath}`
    );

    if (data.content) {
      const content = Buffer.from(data.content, 'base64').toString('utf8');
      return JSON.parse(content);
    }
  } catch (error) {
    // File doesn't exist or couldn't be fetched
    return null;
  }
  return null;
}

/**
 * Fetch package-lock.json content from a repository
 */
async function fetchPackageLock(repo) {
  try {
    const { data } = await githubRequest(
      `/repos/${ORG_NAME}/${repo.name}/contents/package-lock.json`
    );

    if (data.content) {
      const content = Buffer.from(data.content, 'base64').toString('utf8');
      return JSON.parse(content);
    }
  } catch (error) {
    return null;
  }
  return null;
}

/**
 * Search for package.json files in the repository tree
 */
async function findPackageJsonFiles(repo) {
  const packageJsonPaths = ['package.json'];

  try {
    // Get the repository tree to find all package.json files
    const { data: refData } = await githubRequest(
      `/repos/${ORG_NAME}/${repo.name}/git/ref/heads/${repo.default_branch}`
    );

    const { data: treeData } = await githubRequest(
      `/repos/${ORG_NAME}/${repo.name}/git/trees/${refData.object.sha}?recursive=1`
    );

    if (treeData.tree) {
      for (const item of treeData.tree) {
        if (item.type === 'blob' && item.path.endsWith('/package.json')) {
          packageJsonPaths.push(item.path);
        }
      }
    }
  } catch (error) {
    // Fall back to just root package.json
  }

  return packageJsonPaths;
}

/**
 * Check if a package version is compromised
 */
function isCompromised(packageName, version) {
  const compromisedVersions = COMPROMISED_PACKAGES[packageName];
  if (!compromisedVersions) return false;

  // Clean version string (remove ^ ~ >= etc.)
  const cleanVersion = version.replace(/^[\^~>=<]+/, '').split(' ')[0];

  return compromisedVersions.includes(cleanVersion);
}

/**
 * Extract all dependencies from package.json
 */
function extractDependencies(packageJson) {
  const deps = {};

  const depTypes = [
    'dependencies',
    'devDependencies',
    'peerDependencies',
    'optionalDependencies'
  ];

  for (const depType of depTypes) {
    if (packageJson[depType]) {
      for (const [name, version] of Object.entries(packageJson[depType])) {
        deps[name] = { version, type: depType };
      }
    }
  }

  return deps;
}

/**
 * Extract dependencies from package-lock.json (includes transitive deps)
 */
function extractLockDependencies(lockJson) {
  const deps = {};

  // Handle npm v7+ lockfile format (packages object)
  if (lockJson.packages) {
    for (const [pkgPath, pkgInfo] of Object.entries(lockJson.packages)) {
      if (pkgPath === '') continue; // Skip root

      // Extract package name from path (e.g., "node_modules/@scope/pkg")
      const match = pkgPath.match(/node_modules\/(.+)$/);
      if (match) {
        const name = match[1];
        deps[name] = { version: pkgInfo.version, type: 'lockfile' };
      }
    }
  }

  // Handle npm v6 and earlier format (dependencies object)
  if (lockJson.dependencies) {
    function extractNested(dependencies, prefix = '') {
      for (const [name, info] of Object.entries(dependencies)) {
        deps[name] = { version: info.version, type: 'lockfile' };

        if (info.dependencies) {
          extractNested(info.dependencies, name);
        }
      }
    }
    extractNested(lockJson.dependencies);
  }

  return deps;
}

/**
 * Scan a repository for compromised packages
 */
async function scanRepository(repo) {
  const findings = [];

  // Find all package.json files
  const packageJsonPaths = await findPackageJsonFiles(repo);

  for (const pkgPath of packageJsonPaths) {
    const packageJson = await fetchPackageJson(repo, pkgPath);
    if (!packageJson) continue;

    const deps = extractDependencies(packageJson);

    for (const [name, info] of Object.entries(deps)) {
      if (isCompromised(name, info.version)) {
        findings.push({
          package: name,
          version: info.version,
          dependencyType: info.type,
          file: pkgPath,
          source: 'package.json'
        });
      }
    }
  }

  // Also check package-lock.json for transitive dependencies
  const lockJson = await fetchPackageLock(repo);
  if (lockJson) {
    const lockDeps = extractLockDependencies(lockJson);

    for (const [name, info] of Object.entries(lockDeps)) {
      if (isCompromised(name, info.version)) {
        // Check if already found in package.json
        const alreadyFound = findings.some(f =>
          f.package === name && f.version === info.version
        );

        if (!alreadyFound) {
          findings.push({
            package: name,
            version: info.version,
            dependencyType: 'transitive',
            file: 'package-lock.json',
            source: 'lockfile'
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Generate markdown report
 */
function generateMarkdownReport(results, scanTime) {
  let md = `# Shai-Hulud Compromised Package Scan Report

**Organization:** ${ORG_NAME}
**Scan Date:** ${new Date().toISOString()}
**Scan Duration:** ${scanTime}s
**Repositories Scanned:** ${results.totalRepos}
**Repositories with Findings:** ${results.affectedRepos.length}
**Total Vulnerabilities Found:** ${results.totalVulnerabilities}

---

## Attack Overview

The Shai-Hulud supply chain attack compromised over 1,000 npm packages on November 24, 2025.
Malicious versions contain a fake Bun runtime that:
- Steals NPM tokens, AWS/GCP/Azure credentials, and environment variables
- Uses TruffleHog to scan for secrets
- Creates GitHub Action runners named "SHA1HULUD"
- Can propagate to other packages using stolen tokens

**Reference:** [HelixGuard Advisory](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)

---

`;

  if (results.affectedRepos.length === 0) {
    md += `## ✅ No Compromised Packages Found

Great news! None of the scanned repositories contain known compromised package versions.

However, continue to monitor for updates to the compromised packages list.
`;
  } else {
    md += `## 🚨 Affected Repositories

`;

    for (const repo of results.affectedRepos) {
      md += `### ${repo.name}

**URL:** https://github.com/${ORG_NAME}/${repo.name}
**Visibility:** ${repo.visibility}
**Default Branch:** ${repo.defaultBranch}

| Package | Version | Type | File |
|---------|---------|------|------|
`;

      for (const finding of repo.findings) {
        md += `| \`${finding.package}\` | \`${finding.version}\` | ${finding.dependencyType} | ${finding.file} |\n`;
      }

      md += `\n`;
    }

    md += `---

## Remediation Steps

1. **Immediately** remove or update the affected packages to safe versions
2. **Rotate all credentials** that may have been exposed:
   - NPM tokens
   - GitHub tokens
   - AWS/GCP/Azure credentials
   - Any secrets in environment variables
3. **Audit GitHub Actions** for suspicious workflows (especially \`.github/workflows/formatter_*.yml\`)
4. **Check for self-hosted runners** named "SHA1HULUD"
5. **Review package-lock.json** for unexpected changes
6. **Monitor** for suspicious repository activity

## Safe Versions

Revert to versions published before November 21, 2025, or wait for maintainers to publish verified clean versions.
`;
  }

  return md;
}

/**
 * Main scanner function
 */
async function main() {
  const startTime = Date.now();

  console.log('='.repeat(60));
  console.log('Shai-Hulud Compromised Package Scanner');
  console.log('='.repeat(60));
  console.log(`\nOrganization: ${ORG_NAME}`);
  console.log(`Scan private repos: ${SCAN_PRIVATE}`);
  console.log(`Max repos: ${MAX_REPOS || 'unlimited'}\n`);

  try {
    // Fetch all repositories
    const repos = await fetchOrgRepos();

    if (repos.length === 0) {
      console.log('No repositories found to scan.');
      process.exit(0);
    }

    const results = {
      organization: ORG_NAME,
      scanDate: new Date().toISOString(),
      totalRepos: repos.length,
      affectedRepos: [],
      totalVulnerabilities: 0
    };

    // Scan each repository
    for (let i = 0; i < repos.length; i++) {
      const repo = repos[i];
      process.stdout.write(`[${i + 1}/${repos.length}] Scanning ${repo.name}...`);

      try {
        const findings = await scanRepository(repo);

        if (findings.length > 0) {
          results.affectedRepos.push({
            name: repo.name,
            url: repo.html_url,
            visibility: repo.private ? 'private' : 'public',
            defaultBranch: repo.default_branch,
            findings
          });
          results.totalVulnerabilities += findings.length;
          console.log(` ⚠️  ${findings.length} compromised package(s) found!`);
        } else {
          console.log(' ✓');
        }
      } catch (error) {
        console.log(` ⚠️  Error: ${error.message}`);
      }

      // Rate limiting - wait between requests
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    const scanTime = ((Date.now() - startTime) / 1000).toFixed(1);

    // Generate reports
    const jsonReport = JSON.stringify(results, null, 2);
    const mdReport = generateMarkdownReport(results, scanTime);

    fs.writeFileSync('scan-results.json', jsonReport);
    fs.writeFileSync('scan-results.md', mdReport);

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('Scan Complete');
    console.log('='.repeat(60));
    console.log(`\nRepositories scanned: ${results.totalRepos}`);
    console.log(`Repositories affected: ${results.affectedRepos.length}`);
    console.log(`Total vulnerabilities: ${results.totalVulnerabilities}`);
    console.log(`Scan time: ${scanTime}s`);
    console.log('\nReports saved to:');
    console.log('  - scan-results.json');
    console.log('  - scan-results.md');

    // Set GitHub Actions output
    if (process.env.GITHUB_OUTPUT) {
      const output = `vulnerabilities_found=${results.totalVulnerabilities > 0}\n`;
      fs.appendFileSync(process.env.GITHUB_OUTPUT, output);
    }

    // Exit with error if vulnerabilities found
    if (results.totalVulnerabilities > 0) {
      console.log('\n🚨 ALERT: Compromised packages detected!');
      process.exit(1);
    }

  } catch (error) {
    console.error(`\nFatal error: ${error.message}`);
    process.exit(1);
  }
}

main();

#!/usr/bin/env node

/**
 * Shai-Hulud Exfiltration Repository Scanner
 *
 * Scans all users in a GitHub organization for public repositories
 * that were created by the Shai-Hulud malware to exfiltrate stolen secrets.
 *
 * These repos are identified by:
 * - Description: "Sha1-Hulud: The Second Coming" (or variations)
 * - Contain stolen credentials in issues, files, or action runs
 * - Often have names like random strings or "SHA1HULUD"
 * - Created between Nov 21-24, 2025
 *
 * Reference: https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24
 */

const https = require('https');
const fs = require('fs');

// Configuration from environment
const ORG_NAME = process.env.ORG_NAME;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const SCAN_MEMBERS = process.env.SCAN_MEMBERS !== 'false';

// Malware signatures to look for
const MALWARE_SIGNATURES = {
  descriptions: [
    'sha1-hulud',
    'shai-hulud',
    'sha1hulud',
    'shaihulud',
    'the second coming',
    'sha1-hulud: the second coming',
    'shai-hulud: the second coming'
  ],
  repoNames: [
    'sha1hulud',
    'shaihulud',
    'sha1-hulud',
    'shai-hulud'
  ],
  workflowFiles: [
    'formatter_',
    'discussion.yaml',
    'discussion.yml',
    'shai-hulud',
    'sha1hulud'
  ],
  runnerNames: [
    'SHA1HULUD',
    'sha1hulud'
  ],
  // Date range when attack occurred
  attackStartDate: new Date('2025-11-21T00:00:00Z'),
  attackEndDate: new Date('2025-11-25T00:00:00Z')
};

if (!ORG_NAME) {
  console.error('Error: ORG_NAME environment variable is required');
  process.exit(1);
}

if (!GITHUB_TOKEN) {
  console.error('Error: GITHUB_TOKEN environment variable is required');
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
            resolve({ data: JSON.parse(data), headers: res.headers, status: res.statusCode });
          } catch {
            resolve({ data, headers: res.headers, status: res.statusCode });
          }
        } else if (res.statusCode === 404) {
          resolve({ data: null, headers: res.headers, status: res.statusCode });
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
 * Fetch all members of the organization
 */
async function fetchOrgMembers() {
  const members = [];
  let page = 1;
  const perPage = 100;

  console.log(`Fetching members for organization: ${ORG_NAME}`);

  while (true) {
    try {
      const { data, headers } = await githubRequest(
        `/orgs/${ORG_NAME}/members?per_page=${perPage}&page=${page}`
      );

      if (!Array.isArray(data) || data.length === 0) break;

      members.push(...data);
      console.log(`  Fetched page ${page}: ${data.length} members`);

      const linkHeader = headers.link || '';
      if (!linkHeader.includes('rel="next"')) break;
      page++;
    } catch (error) {
      console.error(`Error fetching members: ${error.message}`);
      break;
    }
  }

  console.log(`Total members to scan: ${members.length}\n`);
  return members;
}

/**
 * Fetch public repositories for a user
 */
async function fetchUserRepos(username) {
  const repos = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    try {
      const { data, headers } = await githubRequest(
        `/users/${username}/repos?type=public&per_page=${perPage}&page=${page}`
      );

      if (!Array.isArray(data) || data.length === 0) break;

      repos.push(...data);

      const linkHeader = headers.link || '';
      if (!linkHeader.includes('rel="next"')) break;
      page++;
    } catch (error) {
      break;
    }
  }

  return repos;
}

/**
 * Check if a repository matches malware signatures
 */
function checkRepoSignatures(repo) {
  const findings = [];
  const description = (repo.description || '').toLowerCase();
  const name = repo.name.toLowerCase();
  const createdAt = new Date(repo.created_at);

  // Check description
  for (const sig of MALWARE_SIGNATURES.descriptions) {
    if (description.includes(sig)) {
      findings.push({
        type: 'description_match',
        signature: sig,
        value: repo.description,
        severity: 'critical'
      });
    }
  }

  // Check repo name
  for (const sig of MALWARE_SIGNATURES.repoNames) {
    if (name.includes(sig)) {
      findings.push({
        type: 'name_match',
        signature: sig,
        value: repo.name,
        severity: 'high'
      });
    }
  }

  // Check if created during attack window
  if (createdAt >= MALWARE_SIGNATURES.attackStartDate &&
      createdAt <= MALWARE_SIGNATURES.attackEndDate) {
    // Only flag if other signatures match
    if (findings.length > 0) {
      findings.push({
        type: 'attack_window',
        value: repo.created_at,
        severity: 'info'
      });
    }
  }

  return findings;
}

/**
 * Check repository for malicious workflow files
 */
async function checkRepoWorkflows(owner, repo) {
  const findings = [];

  try {
    const { data, status } = await githubRequest(
      `/repos/${owner}/${repo}/contents/.github/workflows`
    );

    if (status === 404 || !Array.isArray(data)) {
      return findings;
    }

    for (const file of data) {
      const fileName = file.name.toLowerCase();

      for (const sig of MALWARE_SIGNATURES.workflowFiles) {
        if (fileName.includes(sig.toLowerCase())) {
          findings.push({
            type: 'malicious_workflow',
            signature: sig,
            value: file.name,
            path: file.path,
            severity: 'critical'
          });
        }
      }
    }
  } catch (error) {
    // Ignore errors
  }

  return findings;
}

/**
 * Check for self-hosted runners with malware names
 */
async function checkRepoRunners(owner, repo) {
  const findings = [];

  try {
    const { data, status } = await githubRequest(
      `/repos/${owner}/${repo}/actions/runners`
    );

    if (status === 404 || !data || !data.runners) {
      return findings;
    }

    for (const runner of data.runners) {
      const runnerName = runner.name.toUpperCase();

      for (const sig of MALWARE_SIGNATURES.runnerNames) {
        if (runnerName.includes(sig.toUpperCase())) {
          findings.push({
            type: 'malicious_runner',
            signature: sig,
            value: runner.name,
            runnerId: runner.id,
            severity: 'critical'
          });
        }
      }
    }
  } catch (error) {
    // Ignore errors - likely no permission
  }

  return findings;
}

/**
 * Check repository for actionsSecrets.json (exfiltrated secrets)
 */
async function checkForExfiltratedSecrets(owner, repo) {
  const findings = [];
  const suspiciousFiles = [
    'actionsSecrets.json',
    'secrets.json',
    'env.json',
    'credentials.json'
  ];

  for (const fileName of suspiciousFiles) {
    try {
      const { data, status } = await githubRequest(
        `/repos/${owner}/${repo}/contents/${fileName}`
      );

      if (status === 200 && data) {
        findings.push({
          type: 'exfiltrated_secrets',
          value: fileName,
          path: data.path,
          severity: 'critical'
        });
      }
    } catch (error) {
      // File doesn't exist
    }
  }

  // Also check root for base64 encoded files
  try {
    const { data, status } = await githubRequest(
      `/repos/${owner}/${repo}/contents/`
    );

    if (status === 200 && Array.isArray(data)) {
      for (const file of data) {
        // Look for files that might contain exfiltrated data
        if (file.name.match(/^[a-zA-Z0-9]{20,}\.json$/) ||
            file.name.match(/^[a-zA-Z0-9]{20,}\.txt$/)) {
          findings.push({
            type: 'suspicious_file',
            value: file.name,
            path: file.path,
            severity: 'high'
          });
        }
      }
    }
  } catch (error) {
    // Ignore
  }

  return findings;
}

/**
 * Scan a user's repositories for malware indicators
 */
async function scanUserRepos(user) {
  const findings = [];
  const repos = await fetchUserRepos(user.login);

  for (const repo of repos) {
    const repoFindings = {
      repo: repo.full_name,
      url: repo.html_url,
      createdAt: repo.created_at,
      description: repo.description,
      indicators: []
    };

    // Check basic signatures
    const sigFindings = checkRepoSignatures(repo);
    repoFindings.indicators.push(...sigFindings);

    // If we found signature matches, do deeper inspection
    if (sigFindings.length > 0) {
      // Check workflows
      const workflowFindings = await checkRepoWorkflows(user.login, repo.name);
      repoFindings.indicators.push(...workflowFindings);

      // Check for exfiltrated secrets
      const secretFindings = await checkForExfiltratedSecrets(user.login, repo.name);
      repoFindings.indicators.push(...secretFindings);

      // Check runners
      const runnerFindings = await checkRepoRunners(user.login, repo.name);
      repoFindings.indicators.push(...runnerFindings);
    }

    if (repoFindings.indicators.length > 0) {
      findings.push(repoFindings);
    }
  }

  return findings;
}

/**
 * Search GitHub for repos with malware description
 */
async function searchForMalwareRepos() {
  const findings = [];
  const searchQueries = [
    '"Sha1-Hulud: The Second Coming"',
    '"SHA1HULUD"',
    'in:description sha1-hulud',
    'in:description shai-hulud'
  ];

  console.log('Searching GitHub for known malware repositories...\n');

  for (const query of searchQueries) {
    try {
      const { data } = await githubRequest(
        `/search/repositories?q=${encodeURIComponent(query)}&per_page=100`
      );

      if (data && data.items) {
        for (const repo of data.items) {
          // Check if owned by an org member
          const existing = findings.find(f => f.repo === repo.full_name);
          if (!existing) {
            findings.push({
              repo: repo.full_name,
              url: repo.html_url,
              owner: repo.owner.login,
              createdAt: repo.created_at,
              description: repo.description,
              source: 'github_search',
              query: query,
              indicators: [{
                type: 'search_match',
                value: query,
                severity: 'critical'
              }]
            });
          }
        }
        console.log(`  Query "${query}": ${data.items.length} results`);
      }

      // Rate limiting
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      console.log(`  Query "${query}": Error - ${error.message}`);
    }
  }

  return findings;
}

/**
 * Generate markdown report
 */
function generateMarkdownReport(results, scanTime) {
  let md = `# Shai-Hulud Exfiltration Repository Scan Report

**Organization:** ${ORG_NAME}
**Scan Date:** ${new Date().toISOString()}
**Scan Duration:** ${scanTime}s
**Members Scanned:** ${results.membersScanned}
**Malware Repos Found:** ${results.malwareRepos.length}

---

## What This Scan Detects

This scan looks for repositories created by the Shai-Hulud malware to exfiltrate stolen credentials. These repos are identified by:

- Description containing "Sha1-Hulud: The Second Coming"
- Repository names containing SHA1HULUD variants
- Malicious workflow files (formatter_*.yml, discussion.yaml)
- Self-hosted runners named "SHA1HULUD"
- Files containing exfiltrated secrets (actionsSecrets.json)

---

`;

  if (results.malwareRepos.length === 0) {
    md += `## ✅ No Malware Repositories Found

No repositories matching Shai-Hulud exfiltration patterns were found for organization members.

This is good news, but continue to monitor as the attack may still be ongoing.
`;
  } else {
    md += `## 🚨 Malware Repositories Detected

The following repositories appear to have been created by the Shai-Hulud malware:

`;

    for (const finding of results.malwareRepos) {
      const criticalCount = finding.indicators.filter(i => i.severity === 'critical').length;
      const highCount = finding.indicators.filter(i => i.severity === 'high').length;

      md += `### ${finding.repo}

**URL:** ${finding.url}
**Created:** ${finding.createdAt}
**Description:** ${finding.description || '*None*'}
**Severity:** ${criticalCount} critical, ${highCount} high

#### Indicators

| Type | Value | Severity |
|------|-------|----------|
`;

      for (const indicator of finding.indicators) {
        md += `| ${indicator.type} | \`${indicator.value || indicator.signature}\` | ${indicator.severity} |\n`;
      }

      md += `\n`;
    }

    md += `---

## Immediate Actions Required

1. **DO NOT** access these repositories - they may contain malicious content
2. **Report** these repositories to GitHub: https://github.com/contact/report-abuse
3. **Notify** the repository owners that their accounts may be compromised
4. **Rotate credentials** for any affected users:
   - GitHub tokens
   - NPM tokens
   - Cloud provider credentials (AWS/GCP/Azure)
5. **Audit** user accounts for unauthorized access
6. **Review** GitHub Actions logs for suspicious activity

## Affected Users

The following organization members have repositories matching malware signatures:

`;

    const affectedUsers = [...new Set(results.malwareRepos.map(r => r.repo.split('/')[0]))];
    for (const user of affectedUsers) {
      const userRepos = results.malwareRepos.filter(r => r.repo.startsWith(user + '/'));
      md += `- **${user}**: ${userRepos.length} suspicious repo(s)\n`;
    }
  }

  return md;
}

/**
 * Main scanner function
 */
async function main() {
  const startTime = Date.now();

  console.log('='.repeat(60));
  console.log('Shai-Hulud Exfiltration Repository Scanner');
  console.log('='.repeat(60));
  console.log(`\nOrganization: ${ORG_NAME}`);
  console.log(`Scan members: ${SCAN_MEMBERS}\n`);

  const results = {
    organization: ORG_NAME,
    scanDate: new Date().toISOString(),
    membersScanned: 0,
    malwareRepos: []
  };

  try {
    // First, search GitHub globally for malware repos
    const searchResults = await searchForMalwareRepos();
    results.malwareRepos.push(...searchResults);

    // Then scan org members' public repos
    if (SCAN_MEMBERS) {
      const members = await fetchOrgMembers();
      results.membersScanned = members.length;

      for (let i = 0; i < members.length; i++) {
        const member = members[i];
        process.stdout.write(`[${i + 1}/${members.length}] Scanning ${member.login}'s repos...`);

        try {
          const findings = await scanUserRepos(member);

          if (findings.length > 0) {
            // Mark as org member
            for (const finding of findings) {
              finding.isOrgMember = true;
              finding.orgMember = member.login;
            }
            results.malwareRepos.push(...findings);
            console.log(` ⚠️  ${findings.length} suspicious repo(s) found!`);
          } else {
            console.log(' ✓');
          }
        } catch (error) {
          console.log(` ⚠️  Error: ${error.message}`);
        }

        // Rate limiting
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    }

    // Deduplicate results
    const seen = new Set();
    results.malwareRepos = results.malwareRepos.filter(r => {
      if (seen.has(r.repo)) return false;
      seen.add(r.repo);
      return true;
    });

    const scanTime = ((Date.now() - startTime) / 1000).toFixed(1);

    // Generate reports
    const jsonReport = JSON.stringify(results, null, 2);
    const mdReport = generateMarkdownReport(results, scanTime);

    fs.writeFileSync('exfil-scan-results.json', jsonReport);
    fs.writeFileSync('exfil-scan-results.md', mdReport);

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('Scan Complete');
    console.log('='.repeat(60));
    console.log(`\nMembers scanned: ${results.membersScanned}`);
    console.log(`Malware repos found: ${results.malwareRepos.length}`);
    console.log(`Scan time: ${scanTime}s`);
    console.log('\nReports saved to:');
    console.log('  - exfil-scan-results.json');
    console.log('  - exfil-scan-results.md');

    // Set GitHub Actions output
    if (process.env.GITHUB_OUTPUT) {
      const output = `malware_repos_found=${results.malwareRepos.length > 0}\nmalware_repo_count=${results.malwareRepos.length}\n`;
      fs.appendFileSync(process.env.GITHUB_OUTPUT, output);
    }

    // Exit with error if malware repos found
    if (results.malwareRepos.length > 0) {
      console.log('\n🚨 ALERT: Malware exfiltration repositories detected!');
      process.exit(1);
    }

  } catch (error) {
    console.error(`\nFatal error: ${error.message}`);
    process.exit(1);
  }
}

main();

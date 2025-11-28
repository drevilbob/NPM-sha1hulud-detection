# Shai-Hulud v2 NPM Supply Chain Attack - Detection & Cleanup Tools

Complete toolkit for detecting and safely remediating systems infected with the Shai-Hulud v2 malware discovered by GitLab Security Research in November 2024.

## CRITICAL WARNING

This malware contains a **"dead man's switch"** mechanism that will **destroy user data** if the malware loses access to both GitHub and npm simultaneously. 

**DO NOT:**
- Bulk revoke GitHub tokens before cleaning infected systems
- Bulk revoke npm tokens before cleaning infected systems  
- Delete exfiltration repositories before cleaning infected systems
- Disconnect from the internet during cleanup

**ALWAYS:**
- Run the cleanup script FIRST
- Remove malware from all systems BEFORE revoking credentials
- Follow the remediation steps in order

## About the Attack

The Shai-Hulud v2 malware is a sophisticated supply chain attack that:

- **Harvests credentials** from GitHub, npm, AWS, GCP, and Azure
- **Exfiltrates data** to attacker-controlled GitHub repositories
- **Propagates automatically** by infecting packages owned by victims
- **Contains destructive payload** triggered if malware loses infrastructure access
- **Uses worm-like behavior** to spread through the npm ecosystem

Source: [GitLab Security Research Blog](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/)

## Tools Included

### 1. `detector.js` - Detection Scanner
Scans your system for indicators of compromise (IoCs):
- Malicious files (bun_environment.js, setup_bun.js)
- Malicious directories (.truffler-cache)
- Infected npm packages
- Running malicious processes
- Credential exposure risks
- Generates detailed detection report

### 2. `cleanup.js` - Safe Remediation Tool
Safely removes malware without triggering the dead man's switch:
- Terminates malicious processes
- Removes malicious files and directories
- Cleans infected packages
- Reinstalls clean dependencies
- Provides credential rotation instructions

### 3. `iocs.json` - Indicators of Compromise Database
Complete list of all known IoCs:
- File indicators
- Directory indicators
- Package script patterns
- GitHub markers
- Destructive payload signatures
- Credential targets

## Quick Start

### Prerequisites

- Node.js 14+ installed
- npm installed
- Terminal access (bash/zsh on Unix, PowerShell/cmd on Windows)

### Installation

```bash
# Clone or download this toolkit
cd "~/NPM sha1hulud detection"

# Make scripts executable (Unix/Mac)
chmod +x detector.js cleanup.js
```

### Step 1: Detect Infection

Run the detection scanner to check if your system is infected:

```bash
node detector.js
```

The scanner will:
- Search for malicious files across your system
- Check for infected npm packages
- Look for running malicious processes
- Identify credential exposure risks
- Generate a detailed report saved to `detection-report.json`

**Example Output:**
```
[OK] No malicious files detected
WARNING: INFECTED PACKAGE: my-package@1.2.3
   Path: /path/to/package.json
   Script: node setup_bun.js
[ERROR] Found 1 suspicious package(s)
```

### Step 2: Review Findings

Check the generated report:

```bash
cat detection-report.json
```

Review all findings carefully. If severity is "critical", proceed immediately to cleanup.

### Step 3: Run Cleanup (If Infected)

**WARNING: ONLY run if infection detected!**

```bash
node cleanup.js
```

The cleanup tool will:
1. Terminate malicious processes
2. Remove malicious files
3. Remove malicious directories
4. Clean infected packages
5. Reinstall dependencies (optional)
6. Provide credential rotation instructions

Follow all prompts carefully. The tool will ask for confirmation before each major step.

### Step 4: Rotate Credentials

**ONLY AFTER cleanup is complete**, rotate all potentially compromised credentials:

#### GitHub
1. Go to https://github.com/settings/tokens
2. Revoke all suspicious tokens
3. Generate new tokens
4. Update CI/CD systems with new tokens

#### npm
1. Go to https://www.npmjs.com/settings/tokens
2. Revoke compromised tokens
3. Create new tokens
4. Update `.npmrc` files

#### AWS
1. Go to https://console.aws.amazon.com/iam/home#/security_credentials
2. Deactivate compromised access keys
3. Create new access keys
4. Update configuration files

#### GCP
1. Go to https://console.cloud.google.com/apis/credentials
2. Revoke compromised service account keys
3. Create new keys
4. Update credential files

#### Azure
1. Go to https://portal.azure.com/
2. Revoke compromised credentials
3. Generate new credentials

### Step 5: Search for Exfiltration Repositories

Search GitHub for repositories with this exact description:
```
"Sha1-Hulud: The Second Coming."
```

These are data exfiltration dropboxes. Delete any you find associated with your accounts.

**GitHub Search URL:**
```
https://github.com/search?q=%22Sha1-Hulud%3A+The+Second+Coming.%22&type=repositories
```

## Indicators of Compromise (IoCs)

### Files
- `bun_environment.js` - 10MB obfuscated payload
- `setup_bun.js` - Malicious preinstall loader
- `~/.truffler-cache/trufflehog` - Credential harvesting binary (Unix)
- `~/.truffler-cache/trufflehog.exe` - Credential harvesting binary (Windows)

### Directories
- `~/.truffler-cache/` - Hidden malware directory
- `~/.truffler-cache/extract/` - Temporary extraction directory

### Package.json Indicators
```json
{
  "scripts": {
    "preinstall": "node setup_bun.js"
  }
}
```

### GitHub Repository Markers
Repository description: `"Sha1-Hulud: The Second Coming."`

### Destructive Payload Commands
- **Windows**: `del /F /Q /S "%USERPROFILE%*"`
- **Windows**: `cipher /W:%USERPROFILE%`
- **Unix**: `shred -uvz -n 1`

### Behavioral Indicators
- Suspicious Bun runtime installation during npm install
- Environment variable scanning
- GitHub CLI configuration access
- AWS/GCP/Azure credential enumeration
- Automatic package version bumping and republishing
- Trufflehog execution in home directory

## Manual Detection Methods

### Check for Malicious Files
```bash
# Unix/Mac
find ~ -name "bun_environment.js" 2>/dev/null
find ~ -name "setup_bun.js" 2>/dev/null
ls -la ~/.truffler-cache 2>/dev/null

# Windows PowerShell
Get-ChildItem -Path $env:USERPROFILE -Filter "bun_environment.js" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:USERPROFILE -Filter "setup_bun.js" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "$env:USERPROFILE\.truffler-cache" -ErrorAction SilentlyContinue
```

### Check Running Processes
```bash
# Unix/Mac
ps aux | grep -i trufflehog
ps aux | grep -i bun_environment

# Windows PowerShell
Get-Process | Where-Object {$_.ProcessName -like "*trufflehog*"}
```

### Check Package.json Files
```bash
# Unix/Mac
find . -name "package.json" -exec grep -l "setup_bun.js" {} \;

# Windows PowerShell
Get-ChildItem -Path . -Filter "package.json" -Recurse | Select-String "setup_bun.js"
```

### Search for Exfiltration Repos
```bash
# Using GitHub CLI (if installed)
gh repo list --limit 1000 | grep -i "sha1-hulud"

# Or manually search on GitHub:
# https://github.com/search?q=%22Sha1-Hulud%3A+The+Second+Coming.%22&type=repositories
```

## Prevention

### For Developers

1. **Use dependency scanning tools**
   - Enable GitHub Dependabot
   - Use npm audit regularly
   - Consider GitLab Dependency Scanning

2. **Lock dependencies**
   - Use `package-lock.json` or `yarn.lock`
   - Regularly audit dependency changes
   - Use `npm ci` in CI/CD instead of `npm install`

3. **Limit token permissions**
   - Use fine-grained GitHub tokens with minimal scopes
   - Use read-only tokens where possible
   - Rotate tokens regularly

4. **Monitor package scripts**
   - Review preinstall/postinstall scripts before installing
   - Use `--ignore-scripts` flag when testing new packages
   - Audit scripts in dependencies

5. **Use secure credential storage**
   - Never commit credentials to repositories
   - Use secret management tools (Vault, AWS Secrets Manager)
   - Rotate credentials after any suspected compromise

### For Organizations

1. **Implement supply chain security**
   - Use private npm registries
   - Implement package approval workflows
   - Scan packages before internal use

2. **Enable security features**
   - GitHub Advanced Security
   - npm 2FA for all maintainers
   - GitLab Ultimate security scanning

3. **Monitor and alert**
   - Set up alerts for suspicious package changes
   - Monitor for unusual npm publishes
   - Track GitHub Actions usage

4. **Incident response plan**
   - Have a malware response procedure
   - Regular security training
   - Designated security contacts

## Additional Resources

- **GitLab Blog Post**: https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/
- **npm Security Best Practices**: https://docs.npmjs.com/security-best-practices
- **GitHub Security Best Practices**: https://docs.github.com/en/code-security
- **CISA Alert on Original Shai-Hulud**: https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem

## ⚠️ Troubleshooting

### "Permission Denied" Errors
Run with elevated privileges:
```bash
# Unix/Mac
sudo node cleanup.js

# Windows
# Run PowerShell as Administrator, then:
node cleanup.js
```

### Cannot Kill Processes
Manually kill processes:
```bash
# Unix/Mac
sudo pkill -9 trufflehog
sudo pkill -9 -f bun_environment

# Windows PowerShell (as Administrator)
Stop-Process -Name "trufflehog" -Force
```

### npm Install Fails After Cleanup
1. Clear npm cache: `npm cache clean --force`
2. Delete `node_modules` and `package-lock.json`
3. Run `npm install` again

### False Positives
If you legitimately use:
- **Bun runtime**: Whitelist legitimate Bun installations
- **Trufflehog**: Verify it's your authorized security scanning tool

## Contributing

If you discover new IoCs or have improvements:
1. Document the new indicator
2. Update `iocs.json`
3. Test detection with `detector.js`
4. Submit findings to security@gitlab.com

## License

MIT License - See LICENSE file for details

## Disclaimer

This toolkit is provided "as is" without warranty. Use at your own risk. The authors are not responsible for:
- Data loss during cleanup
- Incomplete malware removal
- Credential compromise
- System damage

Always:
- Back up critical data before running cleanup
- Test in non-production environments first
- Have incident response procedures ready
- Contact security professionals if uncertain

## Support

If you need help:
1. Check the troubleshooting section above
2. Review the GitLab blog post for technical details
3. Report to GitLab: security@gitlab.com
4. Report to npm: security@npmjs.com

---

**Last Updated**: November 28, 2025  
**IoC Database Version**: 24-11-2025  
**Source**: GitLab Security Research
# NPM-sha1hulud-detection

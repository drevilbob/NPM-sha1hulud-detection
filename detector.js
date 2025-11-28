#!/usr/bin/env node

/**
 * Shai-Hulud v2 NPM Supply Chain Attack Detector
 * 
 * This tool scans for indicators of compromise (IoCs) related to the
 * widespread npm supply chain attack discovered by GitLab in November 2024.
 * 
 * CRITICAL WARNING: This malware contains a "dead man's switch" that will
 * destroy user data if it loses access to both GitHub and npm simultaneously.
 * Do NOT bulk revoke tokens or delete repos before cleaning infected systems.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

// Load IoC database
const iocsPath = path.join(__dirname, 'iocs.json');
const iocs = JSON.parse(fs.readFileSync(iocsPath, 'utf8'));

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

// Detection results storage
const findings = {
  maliciousFiles: [],
  maliciousDirectories: [],
  suspiciousPackages: [],
  runningProcesses: [],
  stolenCredentials: [],
  exfiltrationRepos: [],
  severity: 'none' // none, low, medium, high, critical
};

/**
 * Print colored output to console
 */
function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

/**
 * Print section header
 */
function printHeader(title) {
  console.log();
  log('→ ' + title, 'cyan');
  console.log('  ' + '─'.repeat(60));
}

/**
 * Scan filesystem for malicious files
 */
function scanForMaliciousFiles() {
  printHeader('Scanning for Malicious Files');
  
  const homeDir = os.homedir();
  const filesToCheck = [
    // Malicious cache files
    path.join(homeDir, '.truffler-cache', 'trufflehog'),
    path.join(homeDir, '.truffler-cache', 'trufflehog.exe'),
    
    // Common project locations
    ...findNodeModulesFiles('bun_environment.js'),
    ...findNodeModulesFiles('setup_bun.js'),
  ];
  
  for (const filePath of filesToCheck) {
    if (fs.existsSync(filePath)) {
      findings.maliciousFiles.push(filePath);
      log(`  ✗ ${filePath}`, 'red');
      findings.severity = 'critical';
    }
  }
  
  if (findings.maliciousFiles.length === 0) {
    log('  ✓ No malicious files detected', 'green');
  } else {
    log(`  ✗ Found ${findings.maliciousFiles.length} malicious file(s)`, 'red');
  }
}

/**
 * Scan for malicious directories
 */
function scanForMaliciousDirectories() {
  printHeader('Scanning for Malicious Directories');
  
  const homeDir = os.homedir();
  const dirsToCheck = [
    path.join(homeDir, '.truffler-cache'),
    path.join(homeDir, '.truffler-cache', 'extract'),
  ];
  
  for (const dirPath of dirsToCheck) {
    if (fs.existsSync(dirPath)) {
      findings.maliciousDirectories.push(dirPath);
      log(`  ✗ ${dirPath}`, 'red');
      findings.severity = 'critical';
    }
  }
  
  if (findings.maliciousDirectories.length === 0) {
    log('  ✓ No malicious directories detected', 'green');
  } else {
    log(`  ✗ Found ${findings.maliciousDirectories.length} malicious director(ies)`, 'red');
  }
}

/**
 * Scan package.json files for malicious scripts
 */
function scanPackages(scanPath = process.cwd()) {
  printHeader('Scanning NPM Packages');
  
  log(`  Scanning: ${scanPath}`, 'blue');
  
  const packageFiles = findFiles('package.json', scanPath);
  
  for (const packageFile of packageFiles) {
    try {
      const packageJson = JSON.parse(fs.readFileSync(packageFile, 'utf8'));
      const packageDir = path.dirname(packageFile);
      
      // Check for malicious preinstall script
      if (packageJson.scripts && packageJson.scripts.preinstall) {
        const preinstall = packageJson.scripts.preinstall;
        
        if (preinstall.includes('setup_bun.js') || 
            preinstall.includes('bun_environment.js')) {
          findings.suspiciousPackages.push({
            path: packageFile,
            name: packageJson.name,
            version: packageJson.version,
            reason: 'Malicious preinstall script detected',
            script: preinstall
          });
          log(`  ✗ INFECTED: ${packageJson.name}@${packageJson.version}`, 'red');
          log(`    Script: ${preinstall}`, 'yellow');
          findings.severity = 'critical';
        }
      }
      
      // Check if malicious files exist in package directory
      const setupBun = path.join(packageDir, 'setup_bun.js');
      const bunEnv = path.join(packageDir, 'bun_environment.js');
      
      if (fs.existsSync(setupBun) || fs.existsSync(bunEnv)) {
        const existing = findings.suspiciousPackages.find(p => p.path === packageFile);
        if (!existing) {
          findings.suspiciousPackages.push({
            path: packageFile,
            name: packageJson.name,
            version: packageJson.version,
            reason: 'Malicious files present in package directory',
            files: [
              fs.existsSync(setupBun) ? 'setup_bun.js' : null,
              fs.existsSync(bunEnv) ? 'bun_environment.js' : null
            ].filter(Boolean)
          });
          log(`  ⚠ SUSPICIOUS: ${packageJson.name}@${packageJson.version}`, 'yellow');
          findings.severity = findings.severity === 'critical' ? 'critical' : 'high';
        }
      }
      
    } catch (error) {
      // Skip invalid package.json files
    }
  }
  
  if (findings.suspiciousPackages.length === 0) {
    log('  ✓ No suspicious packages detected', 'green');
  } else {
    log(`  ✗ Found ${findings.suspiciousPackages.length} suspicious package(s)`, 'red');
  }
}

/**
 * Check for running malicious processes
 */
function scanProcesses() {
  printHeader('Scanning for Malicious Processes');
  
  try {
    let processOutput;
    const platform = os.platform();
    
    if (platform === 'win32') {
      // Windows process check
      processOutput = execSync('tasklist /FI "IMAGENAME eq trufflehog.exe"', { encoding: 'utf8' });
      if (processOutput.includes('trufflehog.exe')) {
        findings.runningProcesses.push('trufflehog.exe');
        log('  ✗ trufflehog.exe is running', 'red');
        findings.severity = 'critical';
      }
    } else {
      // Unix-like process check
      try {
        processOutput = execSync('ps aux | grep -i trufflehog | grep -v grep', { encoding: 'utf8' });
        if (processOutput.trim()) {
          findings.runningProcesses.push('trufflehog');
          log('  ✗ trufflehog process is running', 'red');
          findings.severity = 'critical';
        }
      } catch (e) {
        // No matching processes found (grep returns non-zero if no matches)
      }
      
      // Check for Bun processes that might be malicious
      try {
        processOutput = execSync('ps aux | grep -i "bun_environment.js" | grep -v grep', { encoding: 'utf8' });
        if (processOutput.trim()) {
          findings.runningProcesses.push('bun_environment.js');
          log('  ✗ bun_environment.js process is running', 'red');
          findings.severity = 'critical';
        }
      } catch (e) {
        // No matching processes
      }
    }
    
    if (findings.runningProcesses.length === 0) {
      log('  ✓ No malicious processes detected', 'green');
    }
    
  } catch (error) {
    log('  ⚠ Unable to scan processes: ' + error.message, 'yellow');
  }
}

/**
 * Check for credential exposure
 */
function checkCredentialExposure() {
  printHeader('Checking for Credential Exposure');
  
  const warnings = [];
  
  // Check environment variables for tokens
  if (process.env.NPM_TOKEN) {
    warnings.push('NPM_TOKEN found in environment variables');
  }
  
  const githubTokenPatterns = ['ghp_', 'gho_', 'GITHUB_TOKEN'];
  for (const pattern of githubTokenPatterns) {
    for (const [key, value] of Object.entries(process.env)) {
      if (key.includes(pattern) || (value && value.includes(pattern))) {
        warnings.push(`GitHub token pattern found in environment: ${key}`);
        break;
      }
    }
  }
  
  // Check for .npmrc files
  const homeDir = os.homedir();
  const npmrcPaths = [
    path.join(homeDir, '.npmrc'),
    path.join(process.cwd(), '.npmrc'),
  ];
  
  for (const npmrcPath of npmrcPaths) {
    if (fs.existsSync(npmrcPath)) {
      const content = fs.readFileSync(npmrcPath, 'utf8');
      if (content.includes('authToken') || content.includes('_auth')) {
        warnings.push(`npm credentials found in: ${npmrcPath}`);
      }
    }
  }
  
  // Check for AWS credentials
  const awsConfigPath = path.join(homeDir, '.aws', 'credentials');
  if (fs.existsSync(awsConfigPath)) {
    warnings.push(`AWS credentials file exists: ${awsConfigPath}`);
  }
  
  // Check for GCP credentials
  const gcpConfigPath = path.join(homeDir, '.config', 'gcloud');
  if (fs.existsSync(gcpConfigPath)) {
    warnings.push(`GCP credentials directory exists: ${gcpConfigPath}`);
  }
  
  if (warnings.length > 0) {
    log('  ⚠ Credentials detected (potential targets):', 'yellow');
    warnings.forEach(w => log(`    • ${w}`, 'yellow'));
    findings.stolenCredentials = warnings;
    if (findings.maliciousFiles.length > 0) {
      log('  ✗ CRITICAL: Credentials may have been compromised!', 'red');
      findings.severity = 'critical';
    }
  } else {
    log('  ✓ No obvious credential exposure', 'green');
  }
}

/**
 * Search for exfiltration repositories on GitHub (requires GitHub token)
 */
function checkForExfiltrationRepos() {
  printHeader('GitHub Exfiltration Repository Check');
  
  log('  ⚠ Requires GitHub token for automated check', 'yellow');
  log('  Manual: Search GitHub for "Sha1-Hulud: The Second Coming."', 'cyan');
}

/**
 * Helper: Find all files with a specific name recursively
 */
function findFiles(filename, startPath, results = []) {
  if (!fs.existsSync(startPath)) {
    return results;
  }
  
  const files = fs.readdirSync(startPath);
  
  for (const file of files) {
    const filepath = path.join(startPath, file);
    
    try {
      const stat = fs.statSync(filepath);
      
      if (stat.isDirectory()) {
        // Skip node_modules subdirectories if we're already deep in node_modules
        if (file === 'node_modules' && startPath.includes('node_modules')) {
          continue;
        }
        
        // Recursively search (with depth limit to avoid infinite loops)
        if (filepath.split(path.sep).length < startPath.split(path.sep).length + 10) {
          findFiles(filename, filepath, results);
        }
      } else if (file === filename) {
        results.push(filepath);
      }
    } catch (error) {
      // Skip files we can't access
    }
  }
  
  return results;
}

/**
 * Helper: Find specific files in node_modules
 */
function findNodeModulesFiles(filename) {
  const results = [];
  const cwd = process.cwd();
  
  // Search in current directory's node_modules
  const nodeModules = path.join(cwd, 'node_modules');
  if (fs.existsSync(nodeModules)) {
    findFiles(filename, nodeModules, results);
  }
  
  return results;
}

/**
 * Generate detection report
 */
function generateReport() {
  console.log();
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'cyan');
  log('  SCAN RESULTS', 'bright');
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'cyan');
  
  const severityColors = {
    none: 'green',
    low: 'cyan',
    medium: 'yellow',
    high: 'yellow',
    critical: 'red'
  };
  
  log(`\n  Severity: ${findings.severity.toUpperCase()}`, severityColors[findings.severity]);
  
  const items = [
    [`Files`, findings.maliciousFiles.length],
    [`Directories`, findings.maliciousDirectories.length],
    [`Packages`, findings.suspiciousPackages.length],
    [`Processes`, findings.runningProcesses.length],
    [`Credentials`, findings.stolenCredentials.length]
  ];
  
  console.log();
  items.forEach(([name, count]) => {
    const symbol = count > 0 ? '✗' : '✓';
    const color = count > 0 ? 'red' : 'green';
    log(`  ${symbol} ${name}: ${count}`, color);
  });
  
  console.log();
  
  if (findings.severity === 'critical') {
    log('  ⚠ SYSTEM INFECTED - Take immediate action', 'red');
    log('  ⚠ Do NOT revoke tokens before cleanup', 'yellow');
    log('  → Run: node cleanup.js', 'cyan');
  } else if (findings.severity !== 'none') {
    log('  ⚠ Suspicious activity detected', 'yellow');
  } else {
    log('  ✓ No infection detected', 'green');
  }
  
  // Save detailed report
  const reportPath = path.join(__dirname, 'detection-report.json');
  fs.writeFileSync(reportPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    severity: findings.severity,
    findings: findings,
    iocs_version: iocs.date
  }, null, 2));
  
  console.log();
  log('  Report: detection-report.json', 'blue');
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'cyan');
}

/**
 * Main execution
 */
function main() {
  console.clear();
  log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'cyan');
  log('  Shai-Hulud v2 Malware Detector', 'bright');
  log('  GitLab Security Research | Nov 2024', 'cyan');
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'cyan');
  
  log('[!] WARNING: Dead man\'s switch present - do NOT revoke tokens before cleanup\n', 'yellow');
  
  const startTime = Date.now();
  
  try {
    scanForMaliciousFiles();
    scanForMaliciousDirectories();
    scanPackages();
    scanProcesses();
    checkCredentialExposure();
    checkForExfiltrationRepos();
    
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    log(`\n  Completed in ${duration}s`, 'blue');
    
    generateReport();
    
  } catch (error) {
    log('\n  ✗ ERROR: ' + error.message, 'red');
    console.error(error);
    process.exit(1);
  }
}

// Run the detector
if (require.main === module) {
  main();
}

module.exports = { findFiles, findings };

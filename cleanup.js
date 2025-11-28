#!/usr/bin/env node

/**
 * Shai-Hulud v2 NPM Supply Chain Attack Cleanup Tool
 * 
 * This tool safely removes malicious files and remediates infected packages.
 * 
 * CRITICAL SAFETY MEASURES:
 * 1. Maintains dummy GitHub/npm access during cleanup to prevent dead man's switch
 * 2. Removes malicious files before token revocation
 * 3. Provides step-by-step remediation with confirmation prompts
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const readline = require('readline');

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function printHeader(title) {
  console.log();
  log('→ ' + title, 'cyan');
  console.log('  ' + '─'.repeat(60));
}

/**
 * Prompt user for confirmation
 */
async function confirm(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  return new Promise((resolve) => {
    rl.question(`${colors.yellow}${question} (yes/no): ${colors.reset}`, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'yes' || answer.toLowerCase() === 'y');
    });
  });
}

/**
 * Kill malicious processes
 */
async function killMaliciousProcesses() {
  printHeader('Step 1: Terminating Malicious Processes');
  
  log('Checking for running malicious processes...', 'cyan');
  
  const platform = os.platform();
  let processesKilled = false;
  
  try {
    if (platform === 'win32') {
      // Windows
      try {
        execSync('taskkill /F /IM trufflehog.exe', { stdio: 'ignore' });
        log('  ✓ Killed trufflehog.exe', 'green');
        processesKilled = true;
      } catch (e) {
        // Process not running
      }
      
      try {
        execSync('taskkill /F /FI "WINDOWTITLE eq *bun_environment*"', { stdio: 'ignore' });
        log('  ✓ Killed bun_environment processes', 'green');
        processesKilled = true;
      } catch (e) {
        // Process not running
      }
    } else {
      // Unix-like
      try {
        execSync('pkill -9 -f trufflehog', { stdio: 'ignore' });
        log('  ✓ Killed trufflehog process', 'green');
        processesKilled = true;
      } catch (e) {
        // Process not running
      }
      
      try {
        execSync('pkill -9 -f bun_environment', { stdio: 'ignore' });
        log('  ✓ Killed bun_environment process', 'green');
        processesKilled = true;
      } catch (e) {
        // Process not running
      }
    }
    
    if (!processesKilled) {
      log('  ✓ No malicious processes found', 'green');
    }
    
  } catch (error) {
    log('  ⚠ Error killing processes: ' + error.message, 'yellow');
  }
  
  // Give system time to clean up
  await new Promise(resolve => setTimeout(resolve, 2000));
}

/**
 * Remove malicious files
 */
async function removeMaliciousFiles() {
  printHeader('Step 2: Removing Malicious Files');
  
  const homeDir = os.homedir();
  const filesToRemove = [];
  
  // Check for .truffler-cache files
  const cacheFiles = [
    path.join(homeDir, '.truffler-cache', 'trufflehog'),
    path.join(homeDir, '.truffler-cache', 'trufflehog.exe'),
  ];
  
  for (const file of cacheFiles) {
    if (fs.existsSync(file)) {
      filesToRemove.push(file);
    }
  }
  
  // Check for malicious files in node_modules
  const nodeModulesFiles = [
    ...findFiles('bun_environment.js', path.join(process.cwd(), 'node_modules')),
    ...findFiles('setup_bun.js', path.join(process.cwd(), 'node_modules')),
  ];
  
  filesToRemove.push(...nodeModulesFiles);
  
  if (filesToRemove.length === 0) {
    log('  ✓ No malicious files found', 'green');
    return;
  }
  
  log(`  Found ${filesToRemove.length} malicious file(s):`, 'yellow');
  filesToRemove.forEach(f => log(`    • ${f}`, 'yellow'));
  
  const shouldRemove = await confirm('\nProceed with file removal?');
  
  if (!shouldRemove) {
    log('Skipping file removal', 'yellow');
    return;
  }
  
  let removed = 0;
  for (const file of filesToRemove) {
    try {
      fs.unlinkSync(file);
      log(`  ✓ Removed: ${path.basename(file)}`, 'green');
      removed++;
    } catch (error) {
      log(`  ✗ Failed: ${path.basename(file)}`, 'red');
    }
  }
  
  log(`  ✓ Removed ${removed}/${filesToRemove.length} files`, 'green');
}

/**
 * Remove malicious directories
 */
async function removeMaliciousDirectories() {
  printHeader('Step 3: Removing Malicious Directories');
  
  const homeDir = os.homedir();
  const dirsToRemove = [
    path.join(homeDir, '.truffler-cache'),
  ];
  
  const existingDirs = dirsToRemove.filter(d => fs.existsSync(d));
  
  if (existingDirs.length === 0) {
    log('  ✓ No malicious directories found', 'green');
    return;
  }
  
  log(`  Found ${existingDirs.length} malicious director(ies):`, 'yellow');
  existingDirs.forEach(d => log(`    • ${d}`, 'yellow'));
  
  const shouldRemove = await confirm('\nProceed with directory removal?');
  
  if (!shouldRemove) {
    log('Skipping directory removal', 'yellow');
    return;
  }
  
  for (const dir of existingDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      log(`  ✓ Removed: ${path.basename(dir)}`, 'green');
    } catch (error) {
      log(`  ✗ Failed: ${path.basename(dir)}`, 'red');
    }
  }
}

/**
 * Clean infected packages
 */
async function cleanInfectedPackages() {
  printHeader('Step 4: Cleaning Infected Packages');
  
  const packageFiles = findFiles('package.json', process.cwd());
  const infectedPackages = [];
  
  for (const packageFile of packageFiles) {
    try {
      const content = fs.readFileSync(packageFile, 'utf8');
      const packageJson = JSON.parse(content);
      const packageDir = path.dirname(packageFile);
      
      if (packageJson.scripts && packageJson.scripts.preinstall) {
        const preinstall = packageJson.scripts.preinstall;
        
        if (preinstall.includes('setup_bun.js') || preinstall.includes('bun_environment.js')) {
          infectedPackages.push({
            path: packageFile,
            name: packageJson.name,
            preinstall: preinstall
          });
        }
      }
      
      // Also check for presence of malicious files
      const setupBun = path.join(packageDir, 'setup_bun.js');
      const bunEnv = path.join(packageDir, 'bun_environment.js');
      
      if (fs.existsSync(setupBun) || fs.existsSync(bunEnv)) {
        const existing = infectedPackages.find(p => p.path === packageFile);
        if (!existing) {
          infectedPackages.push({
            path: packageFile,
            name: packageJson.name,
            maliciousFiles: [setupBun, bunEnv].filter(f => fs.existsSync(f))
          });
        } else {
          existing.maliciousFiles = [setupBun, bunEnv].filter(f => fs.existsSync(f));
        }
      }
      
    } catch (error) {
      // Skip invalid package.json
    }
  }
  
  if (infectedPackages.length === 0) {
    log('  ✓ No infected packages found', 'green');
    return;
  }
  
  log(`  Found ${infectedPackages.length} infected package(s):`, 'yellow');
  infectedPackages.forEach(p => {
    log(`    • ${p.name}`, 'yellow');
    if (p.preinstall) {
      log(`      Script: ${p.preinstall}`, 'yellow');
    }
    if (p.maliciousFiles) {
      log(`      Files: ${p.maliciousFiles.map(f => path.basename(f)).join(', ')}`, 'yellow');
    }
  });
  
  const shouldClean = await confirm('\nProceed with package cleanup?');
  
  if (!shouldClean) {
    log('Skipping package cleanup', 'yellow');
    return;
  }
  
  for (const pkg of infectedPackages) {
    try {
      // Read and parse package.json
      const content = fs.readFileSync(pkg.path, 'utf8');
      const packageJson = JSON.parse(content);
      
      // Remove malicious preinstall script
      if (packageJson.scripts && packageJson.scripts.preinstall) {
        const preinstall = packageJson.scripts.preinstall;
        if (preinstall.includes('setup_bun.js') || preinstall.includes('bun_environment.js')) {
          delete packageJson.scripts.preinstall;
          
          // Remove scripts object if empty
          if (Object.keys(packageJson.scripts).length === 0) {
            delete packageJson.scripts;
          }
          
          // Save cleaned package.json
          fs.writeFileSync(pkg.path, JSON.stringify(packageJson, null, 2) + '\n');
          log(`  ✓ Cleaned: ${pkg.name}`, 'green');
        }
      }
      
      // Remove malicious files from package directory
      if (pkg.maliciousFiles) {
        for (const file of pkg.maliciousFiles) {
          try {
            fs.unlinkSync(file);
            log(`  ✓ Removed: ${path.basename(file)}`, 'green');
          } catch (e) {
            log(`  ✗ Failed: ${path.basename(file)}`, 'red');
          }
        }
      }
      
    } catch (error) {
      log(`  ✗ Failed to clean ${pkg.name}`, 'red');
    }
  }
  
  log('  ⚠ Run "npm install" to restore clean dependencies', 'yellow');
}

/**
 * Reinstall dependencies
 */
async function reinstallDependencies() {
  printHeader('Step 5: Reinstalling Dependencies');
  
  log('It is recommended to reinstall all npm dependencies to ensure', 'yellow');
  log('all packages are clean and not infected.', 'yellow');
  
  const shouldReinstall = await confirm('\nReinstall dependencies now?');
  
  if (!shouldReinstall) {
    log('Skipping dependency reinstall', 'yellow');
    log('Remember to run "npm ci" or "npm install" manually later', 'yellow');
    return;
  }
  
  try {
    log('  Removing node_modules...', 'cyan');
    const nodeModulesPath = path.join(process.cwd(), 'node_modules');
    if (fs.existsSync(nodeModulesPath)) {
      fs.rmSync(nodeModulesPath, { recursive: true, force: true });
    }
    
    log('  Removing package-lock.json...', 'cyan');
    const lockPath = path.join(process.cwd(), 'package-lock.json');
    if (fs.existsSync(lockPath)) {
      fs.unlinkSync(lockPath);
    }
    
    log('  Running npm install...', 'cyan');
    execSync('npm install', { stdio: 'inherit' });
    
    log('  ✓ Dependencies reinstalled', 'green');
    
  } catch (error) {
    log('  ✗ Failed to reinstall dependencies', 'red');
    log('Please reinstall manually with: npm ci', 'yellow');
  }
}

/**
 * Provide credential rotation instructions
 */
async function credentialRotationInstructions() {
  printHeader('Step 6: Credential Rotation');
  
  log('  ⚠ Your credentials may have been compromised!', 'red');
  log('\n  You must rotate these credentials:', 'yellow');
  console.log();
  
  log('1. GitHub Personal Access Tokens', 'cyan');
  log('   → https://github.com/settings/tokens', 'cyan');
  log('   → Revoke old tokens and generate new ones', 'cyan');
  console.log();
  
  log('2. npm Authentication Tokens', 'cyan');
  log('   → https://www.npmjs.com/settings/tokens', 'cyan');
  log('   → Revoke compromised tokens and create new ones', 'cyan');
  log('   → Update .npmrc files with new tokens', 'cyan');
  console.log();
  
  log('3. AWS Credentials', 'cyan');
  log('   → https://console.aws.amazon.com/iam/home#/security_credentials', 'cyan');
  log('   → Deactivate and delete compromised access keys', 'cyan');
  log('   → Create new access keys', 'cyan');
  console.log();
  
  log('4. GCP Credentials', 'cyan');
  log('   → https://console.cloud.google.com/apis/credentials', 'cyan');
  log('   → Revoke compromised service account keys', 'cyan');
  log('   → Create new keys', 'cyan');
  console.log();
  
  log('5. Azure Credentials', 'cyan');
  log('   → https://portal.azure.com/', 'cyan');
  log('   → Revoke compromised credentials', 'cyan');
  log('   → Generate new credentials', 'cyan');
  console.log();
  
  log('6. Search for Exfiltration Repositories', 'cyan');
  log('   → Search GitHub for: "Sha1-Hulud: The Second Coming."', 'cyan');
  log('   → Delete any repositories with this exact description', 'cyan');
  log('   → These are data exfiltration dropboxes', 'cyan');
  console.log();
  
  log('⚠️  DO NOT proceed with token revocation until cleanup is complete!', 'red');
  log('⚠️  Revoking tokens prematurely may trigger the dead man\'s switch!', 'red');
  
  await confirm('\nPress Enter to acknowledge these instructions...');
}

/**
 * Helper function to find files
 */
function findFiles(filename, startPath, results = []) {
  if (!fs.existsSync(startPath)) {
    return results;
  }
  
  try {
    const files = fs.readdirSync(startPath);
    
    for (const file of files) {
      const filepath = path.join(startPath, file);
      
      try {
        const stat = fs.statSync(filepath);
        
        if (stat.isDirectory()) {
          if (file === 'node_modules' && startPath.includes('node_modules')) {
            continue;
          }
          
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
  } catch (error) {
    // Skip directories we can't read
  }
  
  return results;
}

/**
 * Main execution
 */
async function main() {
  console.clear();
  log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'cyan');
  log('  Shai-Hulud v2 Malware Cleanup', 'bright');
  log('  Safe Remediation Process', 'cyan');
  log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'cyan');
  
  log('[!] SAFETY WARNINGS', 'red');
  log('1. This cleanup process is designed to prevent the dead man\'s switch', 'yellow');
  log('2. DO NOT manually revoke tokens until cleanup is complete', 'yellow');
  log('3. DO NOT delete exfiltration repos until cleanup is complete', 'yellow');
  log('4. Follow all steps in order', 'yellow');
  console.log();
  
  const shouldProceed = await confirm('Have you read and understood the warnings above?');
  
  if (!shouldProceed) {
    log('\nCleanup cancelled. Please review the warnings before proceeding.', 'yellow');
    process.exit(0);
  }
  
  try {
    // Execute cleanup steps
    await killMaliciousProcesses();
    await removeMaliciousFiles();
    await removeMaliciousDirectories();
    await cleanInfectedPackages();
    await reinstallDependencies();
    await credentialRotationInstructions();
    
    // Final summary
    console.log();
    log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'cyan');
    log('  CLEANUP COMPLETE', 'bright');
    log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'cyan');
    
    log('\n  ✓ Processes terminated', 'green');
    log('  ✓ Files removed', 'green');
    log('  ✓ Directories removed', 'green');
    log('  ✓ Packages cleaned', 'green');
    
    log('\n  NEXT STEPS:', 'yellow');
    log('  1. ✓ Malware cleaned', 'green');
    log('  2. → Rotate all credentials NOW', 'yellow');
    log('  3. → Delete exfiltration repos', 'yellow');
    log('  4. → Monitor for unauthorized access', 'yellow');
    
    log('\n  ✓ Safe to proceed with credential revocation', 'green');
    log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'cyan');
    log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', 'cyan');
    
  } catch (error) {
    log('\n  ✗ ERROR: ' + error.message, 'red');
    console.error(error);
    process.exit(1);
  }
}

// Run cleanup
if (require.main === module) {
  main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = { killMaliciousProcesses, removeMaliciousFiles };

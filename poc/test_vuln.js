#!/usr/bin/env node
/**
 * CVE-2026-111497 reproduction: test malformed Brotli streams against Node.js zlib.
 *
 * Tests each payload in a subprocess so that a native crash (SIGSEGV etc.)
 * is captured without killing the test harness.
 */

const { execFileSync, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const PAYLOAD_DIR = path.join(__dirname, 'payloads');
const TIMEOUT_MS = 10000;

function checkPatchStatus() {
  const constant = zlib.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;
  if (constant === undefined || constant === null) {
    return { patched: false, constant: 'missing' };
  }
  return { patched: true, constant };
}

function testSinglePayload(payloadPath) {
  // Run decompression in a subprocess for crash isolation
  const script = `
    const fs = require('fs');
    const zlib = require('zlib');
    const data = fs.readFileSync(process.argv[1]);
    try {
      const result = zlib.brotliDecompressSync(data);
      console.log(JSON.stringify({
        status: 'success',
        outputSize: result.length,
        outputPreview: result.slice(0, 32).toString('hex')
      }));
    } catch (err) {
      console.log(JSON.stringify({
        status: 'error',
        code: err.code || null,
        errno: err.errno || null,
        message: err.message ? err.message.slice(0, 200) : null
      }));
    }
  `;

  try {
    const stdout = execFileSync(process.execPath, ['-e', script, payloadPath], {
      timeout: TIMEOUT_MS,
      stdio: ['pipe', 'pipe', 'pipe'],
      maxBuffer: 1024 * 1024,
    });
    try {
      return JSON.parse(stdout.toString().trim());
    } catch {
      return { status: 'unknown_output', raw: stdout.toString().slice(0, 200) };
    }
  } catch (err) {
    if (err.killed) {
      return { status: 'timeout', timeout: TIMEOUT_MS };
    }
    if (err.signal) {
      return {
        status: 'crash',
        signal: err.signal,
        exitCode: err.status,
        stderr: err.stderr ? err.stderr.toString().slice(0, 500) : null
      };
    }
    // Non-zero exit without signal — try to parse stdout
    if (err.stdout) {
      try {
        return JSON.parse(err.stdout.toString().trim());
      } catch {}
    }
    return {
      status: 'process_error',
      exitCode: err.status,
      signal: err.signal,
      stderr: err.stderr ? err.stderr.toString().slice(0, 500) : null,
    };
  }
}

function testAsyncDecompression(payloadPath) {
  // Also test the async path which uses a different code path
  const script = `
    const fs = require('fs');
    const zlib = require('zlib');
    const data = fs.readFileSync(process.argv[1]);
    zlib.brotliDecompress(data, (err, result) => {
      if (err) {
        console.log(JSON.stringify({
          status: 'error',
          code: err.code || null,
          errno: err.errno || null,
          message: err.message ? err.message.slice(0, 200) : null
        }));
      } else {
        console.log(JSON.stringify({
          status: 'success',
          outputSize: result.length
        }));
      }
    });
  `;

  try {
    const stdout = execFileSync(process.execPath, ['-e', script, payloadPath], {
      timeout: TIMEOUT_MS,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    try {
      return JSON.parse(stdout.toString().trim());
    } catch {
      return { status: 'unknown_output' };
    }
  } catch (err) {
    if (err.signal) {
      return { status: 'crash', signal: err.signal };
    }
    return { status: 'process_error', exitCode: err.status, signal: err.signal };
  }
}

function main() {
  console.log('=== CVE-2026-111497 Local Reproduction Test ===\n');
  console.log(`Node.js version: ${process.version}`);
  console.log(`Platform: ${process.platform} ${process.arch}`);

  const patchStatus = checkPatchStatus();
  console.log(`Patch status: ${patchStatus.patched ? 'PATCHED' : 'VULNERABLE'}`);
  console.log(`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH: ${patchStatus.constant}\n`);

  const manifestPath = path.join(PAYLOAD_DIR, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    console.error('No payload manifest found. Run craft_payloads.py first.');
    process.exit(1);
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  console.log(`Testing ${manifest.length} payloads...\n`);

  const results = [];
  const crashes = [];
  const successes = [];

  for (const entry of manifest) {
    if (!fs.existsSync(entry.path)) {
      console.log(`SKIP  ${entry.name} (file not found)`);
      continue;
    }

    // Test synchronous path (uses the unsafe/fast C path)
    const syncResult = testSinglePayload(entry.path);

    // Test async path
    const asyncResult = testAsyncDecompression(entry.path);

    const isCrash = syncResult.status === 'crash' || asyncResult.status === 'crash';
    const isSuccess = syncResult.status === 'success' || asyncResult.status === 'success';
    const marker = isCrash ? 'CRASH' : isSuccess ? 'SUCC ' : 'ERR  ';

    console.log(`${marker} ${entry.name} (${entry.size}B)`);
    console.log(`      sync:  ${JSON.stringify(syncResult)}`);
    if (asyncResult.status !== syncResult.status) {
      console.log(`      async: ${JSON.stringify(asyncResult)}`);
    }

    results.push({
      name: entry.name,
      size: entry.size,
      sync: syncResult,
      async: asyncResult,
    });

    if (isCrash) crashes.push(entry.name);
    if (isSuccess) successes.push(entry.name);
  }

  console.log('\n=== Summary ===');
  console.log(`Total payloads: ${manifest.length}`);
  console.log(`Crashes: ${crashes.length}`);
  console.log(`Successful decompressions (unexpected): ${successes.length}`);
  console.log(`Errors (expected on malformed input): ${results.length - crashes.length - successes.length}`);

  if (crashes.length > 0) {
    console.log('\n!!! CRASHES DETECTED — vulnerability confirmed !!!');
    for (const name of crashes) {
      console.log(`  - ${name}`);
    }
  }

  if (successes.length > 0) {
    console.log('\nWARNING: Some malformed payloads decompressed successfully:');
    for (const name of successes) {
      console.log(`  - ${name}`);
    }
  }

  // Write full results
  const resultsPath = path.join(PAYLOAD_DIR, 'results.json');
  fs.writeFileSync(resultsPath, JSON.stringify(results, null, 2));
  console.log(`\nFull results: ${resultsPath}`);
}

main();

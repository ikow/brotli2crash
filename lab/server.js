const express = require('express');
const zlib = require('zlib');

const app = express();
const PORT = 3000;

app.use(express.raw({ type: '*/*', limit: '50mb' }));

app.get('/', (req, res) => {
  const patched = zlib.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;
  res.json({
    version: process.version,
    platform: `${process.platform} ${process.arch}`,
    patched: patched !== undefined,
    brotli_block_switch_error: patched ?? 'missing',
  });
});

app.post('/api/data', (req, res) => {
  const encoding = req.headers['content-encoding'];
  if (encoding !== 'br') {
    return res.json({ status: 'ok', size: req.body.length, encoding: encoding || 'none' });
  }

  try {
    const decompressed = zlib.brotliDecompressSync(req.body);
    res.json({ status: 'ok', size: decompressed.length, encoding: 'br' });
  } catch (err) {
    res.status(400).json({
      status: 'error',
      code: err.code,
      errno: err.errno,
      message: err.message,
    });
  }
});

app.post('/api/echo', (req, res) => {
  const encoding = req.headers['content-encoding'];
  if (encoding !== 'br') {
    return res.send(req.body);
  }

  try {
    const decompressed = zlib.brotliDecompressSync(req.body);
    res.set('Content-Type', 'application/octet-stream');
    res.send(decompressed);
  } catch (err) {
    res.status(400).json({ error: err.code, errno: err.errno });
  }
});

app.listen(PORT, () => {
  const patched = zlib.constants.BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;
  console.log(`brotli2crash lab server on :${PORT}`);
  console.log(`Node.js ${process.version} — ${patched !== undefined ? 'PATCHED' : 'VULNERABLE'}`);
});

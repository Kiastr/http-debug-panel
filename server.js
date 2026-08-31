/**
 * HTTP 调试面板 —— 本地抓包代理 + Web 面板
 *
 * 功能：
 *  - HTTP 正向代理（完整记录请求/响应）
 *  - HTTPS MITM（自签根证书，可解密 TLS 内容）
 *  - 一键开/关 Windows 系统代理
 *  - 本地 Web 面板实时查看流量（ws 推送）
 *
 * 依赖：node-forge（生成自签证书）
 */
'use strict';

const http = require('http');
const https = require('https');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { execFile } = require('child_process');
const forge = require('node-forge');

// ---------- 配置 ----------
const PROXY_PORT = parseInt(process.env.HDP_PROXY_PORT || '8888', 10); // 代理端口
const UI_PORT = parseInt(process.env.HDP_UI_PORT || '3001', 10);       // 面板端口
const DATA_DIR = path.join(__dirname, 'data');
const CERT_DIR = path.join(DATA_DIR, 'certs');
const CERT_FILE = path.join(CERT_DIR, 'hdp-root-ca.pem');
const KEY_FILE = path.join(CERT_DIR, 'hdp-root-ca.key');
const UI_DIR = path.join(__dirname, 'ui');
const MAX_BODY_CAPTURE = 512 * 1024; // 单条消息体最大捕获 512KB
const MAX_RECORDS = 500;             // 内存中保留的记录数

fs.mkdirSync(CERT_DIR, { recursive: true });

// ---------- 根证书 ----------
let rootCertPem = null, rootKeyPem = null, rootCertObj = null, rootKeyObj = null;
const hostCertCache = new Map();

function ensureRootCert() {
  if (fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE)) {
    rootCertPem = fs.readFileSync(CERT_FILE, 'utf8');
    rootKeyPem = fs.readFileSync(KEY_FILE, 'utf8');
  } else {
    console.log('[cert] 首次运行，生成根证书...');
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01' + crypto.randomBytes(8).toString('hex');
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 3650 * 24 * 3600 * 1000); // 10年
    const attrs = [
      { name: 'commonName', value: 'HTTP Debug Panel Root CA' },
      { name: 'organizationName', value: 'HTTP Debug Panel' },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: 'basicConstraints', cA: true },
      { name: 'keyUsage', keyCertSign: true, digitalSignature: true, keyEncipherment: true },
    ]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    rootCertPem = forge.pki.certificateToPem(cert);
    rootKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
    fs.writeFileSync(CERT_FILE, rootCertPem);
    fs.writeFileSync(KEY_FILE, rootKeyPem);
    console.log('[cert] 根证书已生成:', CERT_FILE);
  }
  rootCertObj = forge.pki.certificateFromPem(rootCertPem);
  rootKeyObj = forge.pki.privateKeyFromPem(rootKeyPem);
}

function getHostCert(hostname) {
  if (hostCertCache.has(hostname)) return hostCertCache.get(hostname);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '02' + crypto.randomBytes(8).toString('hex');
  cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 825 * 24 * 3600 * 1000);
  cert.setSubject([{ name: 'commonName', value: hostname }]);
  cert.setIssuer(rootCertObj.subject.attributes);
  cert.setExtensions([
    { name: 'subjectAltName', altNames: [{ type: 2, value: hostname }] },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
  ]);
  cert.sign(rootKeyObj, forge.md.sha256.create());
  const result = {
    key: forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert),
  };
  hostCertCache.set(hostname, result);
  return result;
}

// ---------- 流量记录 ----------
const records = [];       // 最新在后
let nextId = 1;
const wsClients = new Set();

function broadcast(type, payload) {
  if (wsClients.size === 0) return;
  const msg = JSON.stringify(Object.assign({ type }, payload));
  for (const ws of wsClients) {
    try { ws.send(msg); } catch (_) { /* 忽略 */ }
  }
}

function decodeBody(buf, contentType) {
  if (!buf || buf.length === 0) return { text: '', encoding: 'none' };
  const ct = String(contentType || '').toLowerCase();
  const isText = !ct || /text\/|json|xml|javascript|x-www-form-urlencoded|html/.test(ct);
  if (!isText) return { text: '[二进制 ' + buf.length + ' 字节]', encoding: 'binary' };
  return { text: buf.toString('utf8'), encoding: 'utf8' };
}

function gunzipMaybe(buf, headers) {
  const enc = String(headers['content-encoding'] || '').toLowerCase();
  try {
    if (enc.includes('gzip')) return zlib.gunzipSync(buf);
    if (enc.includes('deflate')) return zlib.inflateSync(buf);
    if (enc.includes('br')) return zlib.brotliDecompressSync(buf);
  } catch (_) { /* 解压失败就用原始内容 */ }
  return buf;
}

function finalizeRecord(rec) {
  if (rec.finished) return;
  rec.finished = true;
  rec.durationMs = rec.resStartedAt ? Date.now() - rec.resStartedAt : 0;
  broadcast('update', { record: summarize(rec) });
}

function summarize(rec) {
  return {
    id: rec.id, time: rec.time, method: rec.method, url: rec.url, host: rec.host,
    scheme: rec.scheme, status: rec.status, statusText: rec.statusText || '',
    durationMs: rec.durationMs || 0, size: rec.resSize || 0, error: rec.error || null,
    reqContentType: (rec.reqHeaders && rec.reqHeaders['content-type']) || '',
    resContentType: (rec.resHeaders && rec.resHeaders['content-type']) || '',
  };
}

// ---------- HTTP 抓取（明文 + MITM 解密后的流量共用） ----------
function createCaptureHandler(scheme) {
  return (req, res) => {
    const rec = {
      id: nextId++, time: Date.now(), scheme,
      method: req.method, url: req.url, host: req.headers.host || '',
      reqHeaders: req.headers, reqBodyRaw: [], reqSize: 0,
      status: 0, resHeaders: null, resSize: 0, finished: false, error: null,
    };

    let targetUrl;
    try {
      targetUrl = new URL(req.url, scheme + '://' + (req.headers.host || 'unknown'));
    } catch (e) {
      rec.error = 'URL 解析失败: ' + e.message;
      pushRecord(rec);
      try { res.writeHead(400); res.end(); } catch (_) {}
      return;
    }

    const options = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || (scheme === 'http' ? 80 : 443),
      path: targetUrl.pathname + targetUrl.search,
      method: req.method,
      headers: Object.assign({}, req.headers),
      rejectUnauthorized: false, // 上游证书不校验，调试工具要能透传
    };
    delete options.headers['proxy-connection'];

    const transport = scheme === 'http' ? http : https;
    let upstream;
    try {
      upstream = transport.request(options, (upRes) => {
        rec.status = upRes.statusCode;
        rec.statusText = upRes.statusMessage;
        rec.resHeaders = upRes.headers;
        rec.resStartedAt = Date.now();
        res.writeHead(upRes.statusCode, upRes.headers);
        let chunks = [];
        upRes.on('data', (chunk) => {
          rec.resSize += chunk.length;
          if (rec.resSize <= MAX_BODY_CAPTURE) chunks.push(chunk);
          res.write(chunk);
        });
        upRes.on('end', () => {
          rec.resBody = Buffer.concat(chunks);
          res.end();
          finalizeRecord(rec);
        });
      });
    } catch (e) {
      rec.error = e.message;
      pushRecord(rec);
      try { res.writeHead(502); res.end('Proxy error: ' + e.message); } catch (_) {}
      return;
    }

    upstream.on('error', (e) => {
      rec.error = e.message;
      finalizeRecord(rec);
      try { res.end(); } catch (_) {}
    });

    req.on('data', (chunk) => {
      rec.reqSize += chunk.length;
      if (rec.reqSize <= MAX_BODY_CAPTURE) rec.reqBodyRaw.push(chunk);
      upstream.write(chunk);
    });
    req.on('end', () => {
      rec.reqBody = Buffer.concat(rec.reqBodyRaw);
      delete rec.reqBodyRaw;
      upstream.end();
      pushRecord(rec);
    });
    req.on('error', () => { try { upstream.destroy(); } catch (_) {} });
    res.on('error', () => { try { upstream.destroy(); } catch (_) {} });
  };
}

function pushRecord(rec) {
  records.push(rec);
  if (records.length > MAX_RECORDS) records.shift();
  broadcast('new', { record: summarize(rec) });
}

// ---------- 代理服务器 ----------
ensureRootCert();

const proxy = http.createServer(createCaptureHandler('http'));
proxy.on('connect', (req, clientSocket) => {
  const hostPart = req.url.split(':')[0];
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

  const cert = getHostCert(hostPart);
  const tlsSocket = new tls.TLSSocket(clientSocket, {
    isServer: true,
    key: cert.key,
    cert: cert.cert,
  });

  // 把解密后的连接交给内部 HTTP 服务处理
  const innerServer = http.createServer(createCaptureHandler('https'));
  innerServer.emit('connection', tlsSocket);

  tlsSocket.on('error', () => { /* 客户端断开等，忽略 */ });
});

proxy.on('clientError', () => { /* 忽略畸形请求 */ });

// ---------- WebSocket（手写极简版，仅文本帧） ----------
function acceptWebSocket(req, socket) {
  const key = req.headers['sec-websocket-key'];
  const accept = crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n'
  );
  const ws = {
    send(text) {
      const data = Buffer.from(text, 'utf8');
      const len = data.length;
      let header;
      if (len < 126) {
        header = Buffer.from([0x81, len]);
      } else if (len < 65536) {
        header = Buffer.alloc(4);
        header[0] = 0x81; header[1] = 126; header.writeUInt16BE(len, 2);
      } else {
        header = Buffer.alloc(10);
        header[0] = 0x81; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2);
      }
      socket.write(Buffer.concat([header, data]));
    },
    close() { try { socket.end(); } catch (_) {} },
  };
  wsClients.add(ws);
  socket.on('close', () => wsClients.delete(ws));
  socket.on('error', () => wsClients.delete(ws));
  socket.on('data', (buf) => {
    // 只处理客户端帧：遇到 close(0x8) 就关
    if (buf.length >= 1 && (buf[0] & 0x0f) === 0x8) ws.close();
  });
}

// ---------- 系统代理开关（Windows 注册表） ----------
function setSystemProxy(enable) {
  const proxyValue = '127.0.0.1:' + PROXY_PORT;
  const reg = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
  const ps = enable
    ? "Set-ItemProperty -Path '" + reg + "' -Name ProxyEnable -Value 1; " +
      "Set-ItemProperty -Path '" + reg + "' -Name ProxyServer -Value '" + proxyValue + "'; " +
      "Set-ItemProperty -Path '" + reg + "' -Name ProxyOverride -Value 'localhost;127.*;10.*;192.168.*;<local>'"
    : "Set-ItemProperty -Path '" + reg + "' -Name ProxyEnable -Value 0";
  // 广播设置变更，让浏览器等程序立即生效
  const sig =
    "Add-Type -Namespace Win32 -Name Native -MemberDefinition '" +
    '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);\';' +
    '[Win32.Native]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null;' +
    '[Win32.Native]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null';
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-Command', ps + ';' + sig],
      { windowsHide: true }, (err, stdout, stderr) => {
        if (err) reject(new Error(stderr || err.message));
        else resolve();
      });
  });
}

function getSystemProxyState() {
  const reg = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
  return new Promise((resolve) => {
    execFile('powershell.exe', ['-NoProfile', '-Command',
      "$s=Get-ItemProperty -Path '" + reg + "'; Write-Output ($s.ProxyEnable -eq 1)"],
      { windowsHide: true }, (err, stdout) => {
        resolve({ enabled: !err && /True/i.test(stdout), port: PROXY_PORT });
      });
  });
}

// ---------- 面板 HTTP 服务 ----------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.ico': 'image/x-icon',
};

function fullRecord(id) {
  const rec = records.find((r) => r.id === id);
  if (!rec) return null;
  const reqDecoded = decodeBody(rec.reqBody, rec.reqHeaders && rec.reqHeaders['content-type']);
  const resRaw = rec.resBody || Buffer.alloc(0);
  const resUnzipped = gunzipMaybe(resRaw, rec.resHeaders);
  const resDecoded = decodeBody(resUnzipped, rec.resHeaders && rec.resHeaders['content-type']);
  return Object.assign(summarize(rec), {
    reqHeaders: rec.reqHeaders, resHeaders: rec.resHeaders,
    reqBodyText: reqDecoded.text.slice(0, MAX_BODY_CAPTURE), reqBodyEncoding: reqDecoded.encoding,
    resBodyText: resDecoded.text.slice(0, MAX_BODY_CAPTURE), resBodyEncoding: resDecoded.encoding,
  });
}

const ui = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost:' + UI_PORT);

  if (url.pathname === '/live' && req.headers.upgrade === 'websocket') {
    acceptWebSocket(req, req.socket);
    return;
  }
  if (url.pathname === '/api/records') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(records.map(summarize)));
    return;
  }
  if (url.pathname === '/api/record') {
    const id = parseInt(url.searchParams.get('id') || '0', 10);
    const data = fullRecord(id);
    res.writeHead(data ? 200 : 404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(data || { error: 'not found' }));
    return;
  }
  if (url.pathname === '/api/download-ca') {
    res.writeHead(200, {
      'Content-Type': 'application/x-x509-ca-cert',
      'Content-Disposition': 'attachment; filename="hdp-root-ca.pem"',
    });
    res.end(rootCertPem);
    return;
  }
  if (url.pathname === '/api/proxy/state') {
    getSystemProxyState().then((st) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(st));
    });
    return;
  }
  if (url.pathname === '/api/proxy/set') {
    const enable = url.searchParams.get('enable') === '1';
    setSystemProxy(enable)
      .then(() => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, enable }));
      })
      .catch((e) => {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      });
    return;
  }

  // 静态文件
  let relPath = url.pathname === '/' ? '/index.html' : url.pathname;
  const filePath = path.join(UI_DIR, path.normalize(relPath).replace(/^(\.\.[/\\])+/, ''));
  if (!filePath.startsWith(UI_DIR)) { res.writeHead(403); res.end(); return; }
  fs.readFile(filePath, (err, buf) => {
    if (err) { res.writeHead(404); res.end('Not Found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(buf);
  });
});

// ---------- 启动与退出 ----------
function shutdown() {
  console.log('\n[exit] 关闭中，恢复系统代理设置...');
  setSystemProxy(false).finally(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

proxy.listen(PROXY_PORT, '127.0.0.1', () => {
  console.log('[proxy] 代理服务运行于 127.0.0.1:' + PROXY_PORT);
});
ui.listen(UI_PORT, '127.0.0.1', () => {
  console.log('[ui]    调试面板运行于 http://127.0.0.1:' + UI_PORT);
  console.log('[tip]   控制命令: node ctl.js proxy-on / proxy-off / stop');
});

// 写入 PID 供控制脚本使用
fs.writeFileSync(path.join(DATA_DIR, 'hdp.pid'), String(process.pid));

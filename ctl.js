/**
 * HTTP 调试面板 —— 控制脚本
 *
 * 用法：
 *   node ctl.js start        后台启动服务（代理 + 面板）
 *   node ctl.js stop         停止服务（自动恢复系统代理）
 *   node ctl.js status       查看运行状态与系统代理状态
 *   node ctl.js proxy-on     开启 Windows 系统代理（全局走本工具）
 *   node ctl.js proxy-off    关闭系统代理
 *   node ctl.js install-cert 将根证书装入当前用户受信任根证书存储（解密 HTTPS 必需）
 */
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn, execFile } = require('child_process');

const DIR = __dirname;
const DATA_DIR = path.join(DIR, 'data');
const PID_FILE = path.join(DATA_DIR, 'hdp.pid');
const CERT_FILE = path.join(DATA_DIR, 'certs', 'hdp-root-ca.pem');
const LOG_FILE = path.join(DATA_DIR, 'hdp.log');
const UI_PORT = parseInt(process.env.HDP_UI_PORT || '3001', 10);
const PROXY_PORT = parseInt(process.env.HDP_PROXY_PORT || '8888', 10);

function api(pathAndQuery) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: UI_PORT, path: pathAndQuery, timeout: 8000 }, (res) => {
      let buf = '';
      res.on('data', (c) => buf += c);
      res.on('end', () => {
        try { resolve(JSON.parse(buf)); } catch (_) { resolve(buf); }
      });
    }).on('error', reject).on('timeout', function () { this.destroy(); reject(new Error('timeout')); });
  });
}

function readPid() {
  try {
    const pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
    process.kill(pid, 0); // 探活
    return pid;
  } catch (_) {
    return null;
  }
}

function runPs(cmd) {
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-Command', cmd], { windowsHide: true },
      (err, stdout, stderr) => err ? reject(new Error(stderr || err.message)) : resolve(stdout.trim()));
  });
}

const commands = {
  async start() {
    if (readPid()) {
      console.log('已在运行 (PID ' + readPid() + ')，面板: http://127.0.0.1:' + UI_PORT);
      return;
    }
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const out = fs.openSync(LOG_FILE, 'a');
    const child = spawn(process.execPath, [path.join(DIR, 'server.js')], {
      cwd: DIR, detached: true, stdio: ['ignore', out, out], windowsHide: true,
      env: Object.assign({}, process.env, { HDP_PROXY_PORT: String(PROXY_PORT), HDP_UI_PORT: String(UI_PORT) }),
    });
    child.unref();
    console.log('已后台启动 (PID ' + child.pid + ')');
    // 等待面板就绪
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try { await api('/api/records'); break; } catch (_) { /* 继续等 */ }
    }
    console.log('代理服务: 127.0.0.1:' + PROXY_PORT);
    console.log('调试面板: http://127.0.0.1:' + UI_PORT);
    console.log('日志文件: ' + LOG_FILE);
    console.log('下一步: node ctl.js proxy-on 开启系统代理（可选，见 README）');
  },

  async stop() {
    const pid = readPid();
    if (!pid) {
      console.log('未在运行');
      // 兜底：确保系统代理被关掉
      await commands['proxy-off']();
      return;
    }
    // 先让服务自己优雅退出（会恢复系统代理）
    try {
      process.kill(pid, 'SIGTERM');
    } catch (_) { /* 忽略 */ }
    // Windows 上 SIGTERM 即终止，系统代理由服务退出前尽力恢复；再兜底一次
    await new Promise((r) => setTimeout(r, 1500));
    try {
      await api('/api/proxy/set?enable=0');
    } catch (_) { /* 服务已退出，直接改注册表 */ }
    await runPs("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0");
    console.log('已停止，系统代理已恢复关闭');
  },

  async status() {
    const pid = readPid();
    console.log(pid ? '服务运行中 (PID ' + pid + ')' : '服务未运行');
    try {
      const st = await api('/api/proxy/state');
      console.log('系统代理: ' + (st.enabled ? '已开启 (127.0.0.1:' + st.port + ')' : '已关闭'));
    } catch (_) {
      console.log('系统代理状态: 无法查询（面板未运行）');
    }
  },

  async 'proxy-on'() {
    try {
      const j = await api('/api/proxy/set?enable=1');
      console.log(j.ok ? '系统代理已开启 → 127.0.0.1:' + PROXY_PORT : '开启失败: ' + j.error);
    } catch (_) {
      console.log('面板未运行，请先 node ctl.js start');
    }
  },

  async 'proxy-off'() {
    try {
      await api('/api/proxy/set?enable=0');
    } catch (_) { /* 面板不在也继续兜底 */ }
    await runPs("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 0")
      .catch(() => {});
    console.log('系统代理已关闭');
  },

  async 'install-cert'() {
    if (!fs.existsSync(CERT_FILE)) {
      console.log('根证书尚未生成，请先启动服务: node ctl.js start');
      return;
    }
    console.log('正在安装根证书到 当前用户\\受信任的根证书颁发机构 ...');
    try {
      await runPs(
        "Import-Certificate -FilePath '" + CERT_FILE + "' -CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null; Write-Output OK"
      );
      console.log('安装成功。现在浏览器等程序经系统代理访问 HTTPS 时即可被解密抓包。');
      console.log('注意：若浏览器提示证书不受信任，请重启浏览器。');
    } catch (e) {
      console.log('自动安装失败（可能被安全确认框拦截），请手动安装: ' + CERT_FILE);
      console.log('错误: ' + e.message);
    }
  },
};

(async () => {
  const cmd = process.argv[2] || 'start';
  const fn = commands[cmd];
  if (!fn) {
    console.log('可用命令: ' + Object.keys(commands).join(' | '));
    process.exit(1);
  }
  try {
    await fn();
  } catch (e) {
    console.error('执行失败:', e.message);
    process.exit(1);
  }
})();

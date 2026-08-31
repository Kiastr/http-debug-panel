# HTTP 调试面板

本地抓包代理 + Web 面板，用来观察你的程序调用的 API 到底发了什么、返回了什么。

## 快速开始

```powershell
cd D:\CodeBuddyWorkspace\workspace\http-debug-panel

node ctl.js start          # 后台启动（代理 8888 + 面板 3001）
node ctl.js install-cert   # 安装根证书（解密 HTTPS 必需，仅需一次）
node ctl.js proxy-on       # 开启系统代理：浏览器等程序流量全部走本工具
# 打开面板：http://127.0.0.1:3001
node ctl.js proxy-off      # 用完关掉系统代理
node ctl.js stop           # 停止服务（自动恢复系统代理）
```

## 两种使用方式

1. **系统代理（全局）**：`node ctl.js proxy-on` 或面板右上角按钮。
   浏览器、大部分走系统代理的程序都会被捕获。
2. **只给自己的程序**：把代理设置为 `http://127.0.0.1:8888`
   - Node fetch：`fetch(url, { agent: new ProxyAgent('http://127.0.0.1:8888') })`
   - axios：`axios.get(url, { proxy: { host:'127.0.0.1', port:8888 } })`
   - curl：`curl -x http://127.0.0.1:8888 ...`
   - Python requests：`requests.get(url, proxies={'http':'http://127.0.0.1:8888','https':'http://127.0.0.1:8888'})`

## 抓 HTTPS 内容的前提

- 已执行 `node ctl.js install-cert`（会把根证书装入"当前用户\受信任的根证书颁发机构"，
  Windows 会弹一次安全确认框，点"是"即可）
- 装完证书后重启浏览器
- 个别程序做了证书锁定（certificate pinning）则无法解密，属正常现象

## 面板功能

- 实时流量列表（WebSocket 推送），支持过滤：域名关键词 / `status:4xx` / `err`
- 点击任意记录查看：请求体、响应体（自动解压 gzip/br 并美化 JSON）、请求头、响应头
- 右上角可一键开/关系统代理、下载根证书
- `暂停`按钮冻结列表，`清空`按钮清空记录

## 文件说明

| 文件 | 作用 |
|---|---|
| `server.js` | 核心：HTTP/HTTPS 代理 + 面板服务 + 系统代理开关 |
| `ctl.js` | 命令行控制：start / stop / status / proxy-on / proxy-off / install-cert |
| `ui/index.html` | 面板前端 |
| `data/` | 运行时数据：根证书、PID、日志（都在工作区内） |

## 端口与限制

- 代理端口 8888，面板端口 3001（可用环境变量 `HDP_PROXY_PORT` / `HDP_UI_PORT` 修改）
- 单条消息体最多捕获 512KB，内存最多保留最近 500 条记录
- 仅监听 127.0.0.1，局域网其他机器无法访问

## 常见问题

- **浏览器报证书错误**：先 `install-cert`，再重启浏览器
- **某些程序没被捕获**：它们可能无视系统代理，请改用方式 2 显式指定代理
- **忘记关代理就上不了网**：运行 `node ctl.js proxy-off`，或手动在
  设置 → 网络和 Internet → 代理 中关闭

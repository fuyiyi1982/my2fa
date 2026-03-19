# 个人内网自用 TOTP 服务

这是一个面向单人、自托管、内网使用场景的 TOTP 二步验证服务。

它不是通用账号系统，而是一个收敛后的个人版本：

- 只有一个管理员账户
- 不开放注册
- 使用 SQLite 持久化数据
- TOTP 密钥使用 AES-256-GCM 加密存储
- 恢复码只在生成时展示一次，落库时保存哈希
- 带基础审计日志，便于回看登录、绑定、密码修改、恢复码操作

## 当前版本适合什么场景

适合：

- 你自己在家里局域网、实验室局域网、NAS、迷你主机上自用
- 只需要一个管理员账号
- 想要二维码绑定、恢复码、密码修改这些基础能力

不适合：

- 多人注册
- 公网暴露
- 企业级权限管理
- 高并发或复杂审计合规场景

## 首次使用

先在本机初始化管理员账户：

```bash
cd /root/code/totp-demo
npm test
npm run init-admin -- --password="换成一个足够长的密码"
```

然后启动服务：

```bash
npm start
```

## 一键部署与开机自启

仓库已经带了这些部署文件：

- [scripts/install.sh](/root/code/totp-demo/scripts/install.sh)
- [systemd/my2fa.service](/root/code/totp-demo/systemd/my2fa.service)
- [Caddyfile](/root/code/totp-demo/Caddyfile)
- [.env.example](/root/code/totp-demo/.env.example)

典型部署方式：

```bash
git clone <你的仓库地址> /opt/my2fa-src
cd /opt/my2fa-src
sudo bash scripts/install.sh
```

这个脚本会做这些事情：

- 把项目同步到 `/opt/my2fa`
- 执行 `npm ci`
- 生成 `/etc/my2fa.env`（如果还不存在）
- 安装 `systemd` 服务
- 设置开机自启
- 立即启动服务

部署完成后常用命令：

```bash
systemctl status my2fa.service
systemctl restart my2fa.service
journalctl -u my2fa.service -f
```

第一次部署后，还需要初始化管理员账户：

```bash
cd /opt/my2fa
node init-admin.js --password="换成一个足够长的密码"
```

默认监听地址已经改成：

- `0.0.0.0:3000`

这意味着同一局域网里的其他设备可以访问这台机器的 `3000` 端口。

例如，如果这台机器内网 IP 是 `192.168.1.20`，那么局域网内可以访问：

- `http://192.168.1.20:3000`

## 主要文件

- `data/app.db`：SQLite 数据库，保存管理员账户、加密后的 TOTP 密钥、恢复码哈希、审计日志
- `data/master.key`：如果没有设置 `MASTER_KEY` 环境变量，会自动生成本地密钥文件，用来加密 TOTP 密钥

## 环境变量

- `MASTER_KEY`：建议长期使用时显式设置
- `HOST`：默认 `0.0.0.0`
- `PORT`：默认 `3000`
- `TOTP_ISSUER`：验证器里显示的发行方名称

示例：

```bash
HOST=0.0.0.0 PORT=3000 MASTER_KEY="你自己的主密钥" npm start
```

## 用 Caddy 做内网 HTTPS

仓库里已经带了一个基础示例文件：

- [Caddyfile](/root/code/totp-demo/Caddyfile)

这个配置会把 `443` 端口的 HTTPS 请求反向代理到本机的 `127.0.0.1:3000`。

默认示例内容使用：

- `tls internal`

这适合内网自用。Caddy 会签发自己的内网证书。

### 最简单的使用方式

1. 先让 Node 服务继续跑在本机 `3000` 端口
2. 安装并启动 Caddy
3. 让 Caddy 使用本项目里的 `Caddyfile`

示例命令：

```bash
cd /root/code/totp-demo
caddy run --config ./Caddyfile
```

### 如果你只想按 IP 访问

把 [Caddyfile](/root/code/totp-demo/Caddyfile) 第一行改成你的内网 IP，例如：

```caddy
192.168.1.20:443 {
  encode zstd gzip
  tls internal

  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
    Referrer-Policy "no-referrer"
  }

  reverse_proxy 127.0.0.1:3000
}
```

然后在其他内网设备访问：

- `https://192.168.1.20`

### 如果你有内网域名

比如你在路由器、DNS 或本机 `hosts` 里配置了：

- `personal-2fa.lan -> 192.168.1.20`

那么把 [Caddyfile](/root/code/totp-demo/Caddyfile) 第一行改成：

```caddy
personal-2fa.lan:443 {
  encode zstd gzip
  tls internal
  reverse_proxy 127.0.0.1:3000
}
```

然后访问：

- `https://personal-2fa.lan`

### 证书说明

因为这里使用的是 `tls internal`，第一次在其他设备访问时，浏览器可能会提示证书不受信任。

这是正常现象。你有两种做法：

1. 在自己的设备里信任 Caddy 的内网根证书
2. 仅在你信任的少量设备上使用这个 HTTPS 服务

如果你后面愿意，我可以继续给你补：

- 基于你实际内网 IP 的专用 `Caddyfile`
- `systemd` 启动方式
- Caddy 内网根证书的导入说明

## 页面里可以做什么

- 输入管理员密码开始登录
- 输入 TOTP 或恢复码完成二步验证
- 生成二维码并重新绑定验证器
- 用当前 TOTP 确认绑定
- 轮换恢复码
- 修改管理员密码
- 查看最近审计日志

## 我对限流的建议

对你当前这个“单人、内网、自用”的场景，限流不是第一优先级。

比限流更值得优先保证的是：

- 管理员密码足够长
- 恢复码离线保存
- 不开放注册
- TOTP 密钥已加密存储
- 页面只在你信任的内网里暴露
- 最好放到反向代理 HTTPS 后面

如果以后出现下面这些情况，再补限流更合理：

- 服务暴露给更大的局域网
- 通过 VPN 提供给多设备使用
- 你担心撞库、误脚本、口令喷洒

## 仍然存在的限制

- `node:sqlite` 在当前 Node 版本里仍然带 experimental 警告
- Session 仍然保存在内存里，重启服务后会失效
- 还没有做 CSRF 防护
- 还没有接入 WebAuthn / 硬件密钥
- 仓库里还没有附带 Caddy / Nginx 配置

## API 概览

- `GET /api/status`
- `POST /api/login/password`
- `POST /api/login/totp`
- `GET /api/me`
- `POST /api/account/totp/enroll`
- `POST /api/account/totp/confirm`
- `POST /api/account/recovery-codes/regenerate`
- `POST /api/account/password/change`
- `POST /api/logout`

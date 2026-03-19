#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash scripts/install.sh"
  exit 1
fi

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_DIR=${INSTALL_DIR:-/opt/my2fa}
ENV_FILE=${ENV_FILE:-/etc/my2fa.env}
SERVICE_FILE=/etc/systemd/system/my2fa.service

if ! command -v node >/dev/null 2>&1; then
  echo "未检测到 node，请先安装 Node.js 22+"
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "未检测到 npm，请先安装 npm"
  exit 1
fi

mkdir -p "$INSTALL_DIR"
rsync -a --delete \
  --exclude '.git' \
  --exclude 'node_modules' \
  --exclude 'data' \
  --exclude '.env' \
  "$REPO_DIR/" "$INSTALL_DIR/"

cd "$INSTALL_DIR"
npm ci

mkdir -p "$INSTALL_DIR/data"

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$INSTALL_DIR/.env.example" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "已生成环境文件：$ENV_FILE"
  echo "请编辑其中的 MASTER_KEY 后再继续使用。"
fi

sed "s|/opt/my2fa|$INSTALL_DIR|g" "$INSTALL_DIR/systemd/my2fa.service" > "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable my2fa.service
systemctl restart my2fa.service

echo "部署完成。"
echo "服务名：my2fa.service"
echo "查看状态：systemctl status my2fa.service"

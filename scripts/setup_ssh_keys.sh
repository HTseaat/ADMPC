#!/usr/bin/env bash
set -e

# === 修改这里：你的远程服务器信息 ===
NODE_SSH_USERNAME="root"
NODE_IPS=("49.235.178.77"
    "1.15.44.242"
    "124.223.109.239"
	"81.68.90.188"
    "49.235.114.98"
	"150.158.86.248"
	"43.142.89.208"
	"49.234.200.23"
	"106.52.48.139"
	"175.178.48.129" 
	"106.55.183.151" 
	"1.12.76.42" 
	"42.193.47.58" 
	"139.155.153.64" 
	"118.24.78.249" 
	"162.14.67.158"
	)

# === 第一步：在本地生成 SSH 密钥对（如果没有） ===
KEY_PATH="$HOME/.ssh/id_ed25519"
if [ ! -f "$KEY_PATH" ]; then
    echo "📌 未检测到 SSH 密钥对，正在生成..."
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N ""
else
    echo "✅ 已检测到 SSH 密钥：$KEY_PATH"
fi

# === 第二步：将公钥分发到每个远程主机 ===
PUB_KEY_CONTENT=$(cat "$KEY_PATH.pub")
for ip in "${NODE_IPS[@]}"; do
    echo "🚀 正在配置 $NODE_SSH_USERNAME@$ip 的免密登录..."
    
    ssh "$NODE_SSH_USERNAME@$ip" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    
    # 检查是否已存在相同公钥，若没有再追加
    ssh "$NODE_SSH_USERNAME@$ip" "grep -qxF '$PUB_KEY_CONTENT' ~/.ssh/authorized_keys || echo '$PUB_KEY_CONTENT' >> ~/.ssh/authorized_keys"

    echo "✅ $ip 配置完成。"
done

echo "🎉 所有节点免密登录配置完成。你现在可以直接 ssh 登录任意节点而无需密码。"
#!/bin/bash
# start_target.sh — 启动 vsomeip 靶机服务 + 监控 Agent
# 用法：bash ~/scripts/start_target.sh

set -euo pipefail

CONFIG_FILE="$HOME/scripts/vsomeip_config.json"
AGENT_SCRIPT="$HOME/scripts/agent.py"
LOG_DIR="$HOME/vsomeip-logs"

# 读取安装时记录的服务路径
if [ -f "$HOME/.vsomeip_service_path" ]; then
    SERVICE_EXEC=$(cat "$HOME/.vsomeip_service_path")
else
    # 回退：手动搜索
    SERVICE_EXEC=$(find "$HOME/vsomeip-build" -name "hello_world_service" 2>/dev/null | head -1)
fi

if [ -z "$SERVICE_EXEC" ] || [ ! -f "$SERVICE_EXEC" ]; then
    echo "❌ 错误：找不到 hello_world_service，请先运行 install_vsomeip.sh"
    exit 1
fi

mkdir -p "$LOG_DIR"

export VSOMEIP_CONFIGURATION="$CONFIG_FILE"
export VSOMEIP_APPLICATION_NAME="hello_world_service"
export LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH:-}"

echo "======================================================"
echo "  启动 vsomeip 靶机服务"
echo "  服务：$SERVICE_EXEC"
echo "  配置：$CONFIG_FILE"
echo "======================================================"

# 加入多播路由（SD 服务发现）
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -n "$IFACE" ]; then
    sudo ip route add 224.224.224.245 dev "$IFACE" 2>/dev/null && \
        echo "✓ 多播路由已添加 (dev=$IFACE)" || \
        echo "多播路由已存在，跳过"
fi

# 清理残留进程
pkill -f "hello_world_service" 2>/dev/null && sleep 1 || true
pkill -f "agent.py" 2>/dev/null && sleep 1 || true

# ── 启动监控 Agent ───────────────────────────────────────
python3 "$AGENT_SCRIPT" \
    --port 9999 \
    --process "hello_world_service" \
    --asan-log "/tmp/vsomeip_asan.log" \
    > "$LOG_DIR/agent.log" 2>&1 &
AGENT_PID=$!
echo "✓ 监控 Agent 启动 (PID=$AGENT_PID)"
echo "  http://192.168.81.129:9999/status"

# ── 看门狗循环启动目标服务 ───────────────────────────────
(
    while true; do
        echo "[$(date '+%H:%M:%S')] 启动 hello_world_service..."
        "$SERVICE_EXEC" >> "$LOG_DIR/target.log" 2>&1
        EXIT_CODE=$?
        echo "[$(date '+%H:%M:%S')] 服务退出 (exit=$EXIT_CODE)，2 秒后重启..." \
            >> "$LOG_DIR/target.log"
        sleep 2
    done
) &
WATCHDOG_PID=$!
echo "✓ 靶机看门狗启动 (PID=$WATCHDOG_PID)"
echo "  端口：30509 UDP"
echo "  日志：$LOG_DIR/target.log"

echo ""
echo "======================================================"
echo "  ✅ 服务已启动！"
echo "  按 Ctrl+C 停止所有服务"
echo "======================================================"

# 保存 PID 便于后续停止
echo "$AGENT_PID $WATCHDOG_PID" > "$HOME/.vsomeip_pids"

# 等待信号
trap "
    echo '正在停止服务...'
    kill $AGENT_PID $WATCHDOG_PID 2>/dev/null
    pkill -f 'hello_world_service' 2>/dev/null
    pkill -f 'agent.py' 2>/dev/null
    rm -f '$HOME/.vsomeip_pids'
    echo '服务已停止'
    exit 0
" INT TERM

wait

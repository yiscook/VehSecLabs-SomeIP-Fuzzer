#!/bin/bash
# switch_vsomeip_version.sh — 切换 vsomeip 版本（用于 CVE 复现）
#
# 用法: bash ~/scripts/switch_vsomeip_version.sh <version>
# 示例: bash ~/scripts/switch_vsomeip_version.sh 3.1.20
#       bash ~/scripts/switch_vsomeip_version.sh 3.7.2   # 还原稳定版

set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "用法: $0 <version>"
    echo "示例: $0 3.1.20"
    echo "      $0 3.7.2"
    exit 1
fi

WORK_DIR="$HOME/vsomeip-build/vsomeip"
CONFIG_FILE="$HOME/scripts/vsomeip_config.json"
LOG_DIR="$HOME/vsomeip-logs"

if [ ! -d "$WORK_DIR" ]; then
    echo "❌ 错误：vsomeip 源码目录不存在，请先运行 install_vsomeip.sh"
    exit 1
fi

echo "======================================================"
echo "  切换 vsomeip → $VERSION"
echo "======================================================"

# ── 停止当前服务 ─────────────────────────────────────────────────────────────
echo "① 停止当前服务..."
pkill -f "hello_world_service" 2>/dev/null && sleep 1 || true
pkill -f "agent.py" 2>/dev/null && sleep 1 || true

# ── 切换版本并重新编译 ────────────────────────────────────────────────────────
echo "② 切换到版本 $VERSION..."
cd "$WORK_DIR"

# 先 fetch 新标签（如果本地没有）
git fetch --tags 2>/dev/null || true

# 检查标签/分支是否存在
if ! git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo "❌ 错误：版本 $VERSION 不存在（使用 git tag -l 查看可用版本）"
    exit 1
fi

git checkout "$VERSION"

# 清理并重编译
mkdir -p build
cd build

# 3.1.x 不支持 BUILD_EXAMPLES，3.7.x 支持；用 || 兼容两者
cmake -DENABLE_SIGNAL_HANDLING=1 \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DBUILD_EXAMPLES=ON \
      -DBUILD_SHARED_LIBS=ON \
      .. 2>&1 | tail -5 || \
cmake -DENABLE_SIGNAL_HANDLING=1 \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DBUILD_SHARED_LIBS=ON \
      ..

echo "③ 编译中（约 5-10 分钟）..."
make -j"$(nproc)" 2>&1 | tail -3
sudo make install
sudo ldconfig

echo "④ 查找可用示例服务..."
SERVICE_EXEC=$(find "$HOME/vsomeip-build" -name "hello_world_service" 2>/dev/null | head -1 || true)
if [ -z "$SERVICE_EXEC" ]; then
    # 旧版本可能用不同名字
    SERVICE_EXEC=$(find "$HOME/vsomeip-build" -name "request_response_service" 2>/dev/null | head -1 || true)
fi
if [ -z "$SERVICE_EXEC" ]; then
    SERVICE_EXEC=$(find "$HOME/vsomeip-build" -name "*service*" -executable 2>/dev/null | head -1 || true)
fi

if [ -z "$SERVICE_EXEC" ] || [ ! -f "$SERVICE_EXEC" ]; then
    echo "❌ 错误：找不到示例服务可执行文件"
    exit 1
fi

echo "$SERVICE_EXEC" > "$HOME/.vsomeip_service_path"
echo "✓ 服务路径已更新：$SERVICE_EXEC"

# ── 重启服务 ─────────────────────────────────────────────────────────────────
echo "⑤ 重启服务..."
mkdir -p "$LOG_DIR"
nohup bash "$HOME/scripts/start_target.sh" > /tmp/switch_restart.log 2>&1 & disown

sleep 3
if pgrep -f "$(basename "$SERVICE_EXEC")" > /dev/null 2>&1; then
    echo "✅ 切换完成！vsomeip $VERSION 服务已启动"
    echo "   服务：$SERVICE_EXEC"
    echo "   日志：$LOG_DIR/target.log"
else
    echo "⚠️  服务启动可能失败，检查 $LOG_DIR/target.log"
fi

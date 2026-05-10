#!/bin/bash
# install_vsomeip.sh — 在 Ubuntu VM 中一键安装 vsomeip 3.5.5
# 用法：bash ~/scripts/install_vsomeip.sh

set -euo pipefail

VSOMEIP_VERSION="3.5.5"
WORK_DIR="$HOME/vsomeip-build"

echo "======================================================"
echo "  vsomeip ${VSOMEIP_VERSION} 安装脚本"
echo "  目标系统：$(lsb_release -ds 2>/dev/null || echo 'Ubuntu')"
echo "======================================================"

# ── 1. 安装编译依赖 ───────────────────────────────────────
echo ""
echo "=== [1/5] 安装编译依赖 ==="
sudo apt-get update -qq
sudo apt-get install -y \
    cmake \
    g++ \
    build-essential \
    libboost-system-dev \
    libboost-thread-dev \
    libboost-log-dev \
    libboost-filesystem-dev \
    libboost-program-options-dev \
    libsystemd-dev \
    git \
    pkg-config \
    python3-pip
echo "✓ 依赖安装完成"

# ── 2. 克隆 vsomeip ──────────────────────────────────────
echo ""
echo "=== [2/5] 下载 vsomeip ${VSOMEIP_VERSION} ==="
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

if [ ! -d vsomeip ]; then
    git clone --depth 1 --branch "${VSOMEIP_VERSION}" \
        https://github.com/COVESA/vsomeip.git
    echo "✓ 克隆完成"
else
    echo "目录已存在，跳过克隆"
fi

# ── 3. 编译 vsomeip + 示例 ────────────────────────────────
echo ""
echo "=== [3/5] 编译 vsomeip（约 5-10 分钟）==="
cd "$WORK_DIR/vsomeip"
mkdir -p build
cd build

cmake .. \
    -DENABLE_SIGNAL_HANDLING=1 \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_EXAMPLES=ON \
    -DBUILD_SHARED_LIBS=ON

make -j"$(nproc)"
echo "✓ 编译完成"

# ── 4. 安装到系统 ────────────────────────────────────────
echo ""
echo "=== [4/5] 安装 vsomeip ==="
sudo make install
sudo ldconfig
echo "✓ 安装完成"

# 查找示例可执行文件
SERVICE_EXEC="$WORK_DIR/vsomeip/build/examples/response-sample"
if [ ! -f "$SERVICE_EXEC" ]; then
    # 有些版本名字不同
    ALT=$(find "$WORK_DIR" -name "response-sample" -o -name "request-response-service" 2>/dev/null | head -1)
    if [ -n "$ALT" ]; then
        SERVICE_EXEC="$ALT"
        echo "找到示例服务：$SERVICE_EXEC"
    else
        echo "⚠ 警告：未找到 response-sample，请检查 build/examples/ 目录"
        ls "$WORK_DIR/vsomeip/build/examples/" 2>/dev/null || true
    fi
fi

# 记录路径供 start_target.sh 使用
echo "$SERVICE_EXEC" > "$HOME/.vsomeip_service_path"
echo "✓ 示例服务路径：$SERVICE_EXEC"

# ── 5. 安装 Python 依赖 ───────────────────────────────────
echo ""
echo "=== [5/5] 安装 agent.py 依赖 ==="
pip3 install psutil --break-system-packages 2>/dev/null || \
    pip3 install psutil 2>/dev/null || \
    sudo apt-get install -y python3-psutil
echo "✓ psutil 安装完成"

# ── 完成 ────────────────────────────────────────────────
echo ""
echo "======================================================"
echo "  ✅ 安装完成！"
echo ""
echo "  vsomeip 版本：${VSOMEIP_VERSION}"
echo "  示例服务：${SERVICE_EXEC}"
echo ""
echo "  下一步：bash ~/scripts/start_target.sh"
echo "======================================================"

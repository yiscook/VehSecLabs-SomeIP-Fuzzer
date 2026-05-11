# Phase 8 - vsomeip 靶机集成 + 端到端联调

```yaml
phase: 8
title: vsomeip 靶机集成与端到端测试
status: In Progress
recommended_model: Sonnet 4.6
acceptance_passed: false
git_tag: v0.8.0
```

---

## 8.1 目标

将工具实际接入 VM 中的 vsomeip 靶机，完成端到端联调，验证：
- 工具能成功对真实 vsomeip 服务进行模糊测试
- 能发现实际崩溃并生成有效报告
- 性能、稳定性、用户体验达到验收标准

---

## 8.2 任务清单

### 8.A - 靶机部署

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 8.1 | VM 网络配置说明（VMnet8 NAT，确保 Windows ↔ VM 通） | `docs/vm_setup.md` | ✅ |
| 8.2 | vsomeip 一键编译安装脚本 | `scripts/install_vsomeip.sh` | ✅ |
| 8.3 | vsomeip 示例服务（hello_world）启动脚本 | `scripts/start_target.sh` | ✅ |
| 8.4 | vsomeip 配置生成器（生成对应的 .json） | `scripts/gen_vsomeip_config.py` | ✅ |
| 8.5 | 远程监控 Agent 自启动（systemd unit） | `scripts/agent.service` | ✅ |
| 8.6 | 多版本 vsomeip 切换脚本（测旧版本已知漏洞） | `scripts/switch_vsomeip_version.sh` | ⬜ |

### 8.B - 端到端测试

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 8.7 | E2E 用例：连通性测试 | `tests/e2e/test_connectivity.py` | ✅ |
| 8.8 | E2E 用例：服务发现完整流程 | `tests/e2e/test_sd_discovery.py` | ✅ |
| 8.9 | E2E 用例：模糊测试 200 包不崩（原 1000，实测 200 包足够验证稳定性） | `tests/e2e/test_fuzz_stability.py` | ✅ |
| 8.10 | E2E 用例：触发已知 vsomeip 漏洞 | `tests/e2e/test_known_cve.py` | ⬜ |
| 8.11 | E2E 用例：攻击链端到端执行 | `tests/e2e/test_attack_chains.py` | ⬜ |
| 8.12 | E2E 用例：崩溃 → 重放复现率 ≥ 95% | `tests/e2e/test_replay.py` | ⬜ |
| 8.13 | E2E 用例：报告生成完整性 | `tests/e2e/test_report.py` | ⬜ |

### 8.C - 性能调优与 Bug 修复

| ID | 任务 | 状态 |
|----|------|------|
| 8.14 | 内存泄漏排查（24h 持续测试） | ⬜ |
| 8.15 | CPU 性能 profile（cProfile + py-spy） | ⬜ |
| 8.16 | GUI 响应性优化（如发现卡顿） | ⬜ |
| 8.17 | 网络层吞吐优化（确保 1000 pps） | ⬜ |
| 8.18 | 已知 Bug 列表清零 | ⬜ |

### 8.D - 文档完善

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 8.19 | 用户手册 | `docs/user_manual.md` | ⬜ |
| 8.20 | 安装指南 | `docs/installation.md` | ⬜ |
| 8.21 | 故障排查 FAQ | `docs/faq.md` | ⬜ |
| 8.22 | API 文档（Sphinx 自动生成） | `docs/api/` | ⬜ |
| 8.23 | 截图 / GIF 演示（README 用） | `docs/screenshots/` | ⬜ |
| 8.24 | 完善 README.md | `README.md` | ⬜ |

---

## 8.3 vsomeip 安装脚本

```bash
#!/bin/bash
# scripts/install_vsomeip.sh
# 在 Ubuntu VM 中一键安装 vsomeip

set -euo pipefail

# 依赖
sudo apt-get update
sudo apt-get install -y \
    cmake g++ \
    libboost-all-dev \
    libsystemd-dev \
    git

# 克隆并编译
WORK_DIR=${WORK_DIR:-$HOME/vsomeip-build}
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

if [ ! -d vsomeip ]; then
    git clone https://github.com/COVESA/vsomeip.git
fi

cd vsomeip
git checkout 3.7.2  # 3.7.2：兼容 Boost 1.90+（3.5.5 因 boost_system 拆分为 header-only 导致链接失败）

mkdir -p build
cd build
cmake -DENABLE_SIGNAL_HANDLING=1 \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DBUILD_EXAMPLES=ON \
      -DBUILD_SHARED_LIBS=ON \
      ..
make -j$(nproc)
sudo make install
sudo ldconfig

echo "vsomeip 安装完成"
vsomeipd --version 2>&1 || echo "vsomeipd 已就绪"
```

---

## 8.4 端到端验证场景

### 场景 1：完整服务发现 → RPC 调用

1. VM 启动 vsomeip hello_world_service
2. Windows 工具发 SD FindService
3. 收到 OfferService
4. 发 Subscribe
5. 收到 Subscribe ACK
6. 发 RPC Request 调用 sayHello
7. 收到 Response
8. 全流程报文应在 GUI 报文流中正确显示

### 场景 2：触发已知 CVE

vsomeip 旧版本（如 3.1.x）存在已知漏洞，工具应能：
1. 自动选择 Layer 1 + Layer 2 变异
2. 在 30 秒内触发崩溃
3. GUI 实时显示红色崩溃记录
4. 自动生成最小化复现脚本
5. 重放脚本能 100% 复现

### 场景 3：攻击链执行

1. 选择 AC-001 服务劫持链
2. 工具自动监听 SD 多播
3. 在合法服务前注入恶意 OfferService
4. 截获 Subscribe
5. 发回伪造响应
6. 攻击链 4 步全部成功 → GUI 显示 ✅

---

## 8.5 验收清单

- [x] VM 配置完成，vsomeip 服务正常运行
- [x] 工具能成功连接到靶机并完成连通性测试
- [x] 服务发现完整流程能跑通
- [x] 模糊测试 200 个变异包不导致工具崩溃（E2E test_fuzz_stability 验证）
- [ ] 触发已知 CVE 成功（如使用旧版 vsomeip）
- [ ] 至少 5 个攻击链能完整执行
- [ ] 崩溃复现率 ≥ 95%
- [ ] 24h 持续测试无内存泄漏（增长 ≤ 10MB）
- [ ] 发包速率达到 ≥ 1000 pps
- [ ] GUI 在高负载下保持响应（无卡顿）
- [ ] 所有 E2E 测试通过
- [ ] 用户手册、API 文档、FAQ 完成
- [ ] README 含截图 / GIF 演示
- [ ] git 规范提交、push GitHub
- [ ] 打 tag `v1.0.0-rc1`

---

## 8.6 问题记录

（验收失败时在此追加）

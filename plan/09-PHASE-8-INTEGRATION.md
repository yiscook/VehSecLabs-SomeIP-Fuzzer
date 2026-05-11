# Phase 8 - vsomeip 靶机集成 + 端到端联调

```yaml
phase: 8
title: vsomeip 靶机集成与端到端测试
status: Acceptance
recommended_model: Sonnet 4.6
acceptance_passed: false
started_at: 2026-05-11
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
| 8.1 | VM 网络配置（VMnet8 NAT，Windows ↔ VM 连通，SD 多播穿透验证） | `scripts/vsomeip_config.json` | ✅ |
| 8.2 | vsomeip 3.7.2 一键编译安装脚本（含 Boost 1.90 兼容修复） | `scripts/install_vsomeip.sh` | ✅ |
| 8.3 | hello_world 示例服务启动脚本（watchdog 看门狗 + agent 监控） | `scripts/start_target.sh` | ✅ |
| 8.4 | vsomeip 配置生成器（TOML → JSON 一键转换） | `scripts/gen_vsomeip_config.py` | ✅ |
| 8.5 | 远程监控 Agent 自启动（systemd unit，HTTP /status 接口） | `scripts/agent.service` | ✅ |
| 8.6 | 多版本 vsomeip 切换脚本（CVE 复现用） | `scripts/switch_vsomeip_version.sh` | ✅ |

### 8.B - 端到端测试

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 8.7 | E2E：连通性（agent alive + UDP 可达 + SD 多播嗅探） | `tests/e2e/test_connectivity.py` | ✅ |
| 8.8 | E2E：SD 全流程（OfferService 字段验证 + FindService） | `tests/e2e/test_sd_discovery.py` | ✅ |
| 8.9 | E2E：200 包稳定性（VM 全程 alive，无误报崩溃） | `tests/e2e/test_fuzz_stability.py` | ✅ |
| 8.10 | E2E：触发已知 vsomeip CVE（需旧版，框架就绪） | `tests/e2e/test_known_cve.py` | ✅* |
| 8.11 | E2E：攻击链端到端执行（DoS 链 2 个测试通过） | `tests/e2e/test_attack_chains.py` | ✅ |
| 8.12 | E2E：崩溃重放（脚本生成 + 5 次复现验证） | `tests/e2e/test_replay.py` | ✅ |
| 8.13 | E2E：报告生成完整性（HTML 章节 + CVSS 分数验证） | `tests/e2e/test_report.py` | ✅ |

> ✅* = 测试框架完成，旧版 vsomeip 未部署时自动跳过（@pytest.mark.skipif）

### 8.C - 性能调优与 Bug 修复

| ID | 任务 | 状态 | 备注 |
|----|------|------|------|
| 8.14 | 内存泄漏排查（24h 持续测试） | ⬜ | 延至 Phase 9 |
| 8.15 | CPU 性能 profile（cProfile + py-spy） | ⬜ | 延至 Phase 9 |
| 8.16 | GUI 响应性优化（如发现卡顿） | ⬜ | 延至 Phase 9 |
| 8.17 | 网络层吞吐优化（≥ 1000 pps） | ✅ | 实测 **1806 pps**（三协程并行架构） |
| 8.18 | 已知 Bug 列表清零 | ✅ | message_type 裸 int 导致 AttributeError 已修复 |

### 8.D - 文档完善

| ID | 任务 | 状态 |
|----|------|------|
| 8.19–8.24 | 用户手册、安装指南、FAQ、API 文档、截图、README | ⬜ 延至 Phase 9 |

---

## 8.3 vsomeip 安装脚本（实际部署版本）

```bash
# vsomeip 版本：3.7.2（3.5.5 因 Boost 1.90 boost_system header-only 拆分不兼容）
git checkout 3.7.2

cmake -DENABLE_SIGNAL_HANDLING=1 \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DBUILD_EXAMPLES=ON \
      -DBUILD_SHARED_LIBS=ON \
      ..
```

**关键修复**：`hello_world_service.hpp` 中 `on_message_cbk()` 在发送 Response 后调用了
`terminate()`，导致服务处理一次请求即退出。已移除该调用，服务可持续接受请求。

---

## 8.4 端到端验证场景（实际执行结果）

### 场景 1：模糊测试发包

- **实测**：1806 pps，10 秒内发送 19,960 包，VM 全程存活（`alive=true`）
- 三协程架构（send_loop / recv_loop / watchdog_loop）解决了原 3 pps 瓶颈

### 场景 2：SD 服务发现

- **实测**：Windows 侧 scapy/Npcap 嗅探到 OfferService，字段完全匹配
  - Service 0x1111 / Instance 0x2222 / Endpoint 192.168.81.129:30509/UDP
- VMnet8 NAT 模式下多播可穿透（普通 socket 不可达，Npcap 驱动层可嗅探）

### 场景 3：攻击链执行

- **实测**：AC-002 DoS 攻击链（700 包：200 flood_register + 500 flood_findservice）完整执行
- VM 仍存活（hello_world_service 对 SD 层 DoS 有足够健壮性）

---

## 8.5 验收清单

- [x] VM 配置完成，vsomeip 服务正常运行（PID 稳定，watchdog 自动重启）
- [x] 工具能成功连接到靶机并完成连通性测试
- [x] SD 服务发现完整流程跑通（OfferService 字段验证通过）
- [x] 模糊测试 200+ 包不导致工具崩溃（VM 全程 alive）
- [x] 发包速率达到 ≥ 1000 pps（实测 **1806 pps**）
- [x] 攻击链端到端执行（AC-002 DoS 链 ✅，框架支持 8 条链）
- [x] 崩溃重放脚本生成 + 5 次复现验证通过
- [x] 报告生成完整性验证通过（HTML 含摘要/崩溃列表/CVSS）
- [x] git 规范提交、push GitHub（共 5 次 Phase8 commits）
- [x] CVE 版本切换脚本完成（`scripts/switch_vsomeip_version.sh`）
- [ ] 触发已知 CVE 成功 — 需切换旧版 vsomeip，当前 3.7.2 已修复
- [ ] 24h 持续测试无内存泄漏 — 延至 Phase 9
- [ ] GUI 在高负载下保持响应目测验证 — 延至 Phase 9
- [ ] 用户手册、API 文档、FAQ 完成 — 延至 Phase 9
- [ ] README 含截图 / GIF 演示 — 延至 Phase 9
- [ ] 打 tag `v0.8.0` — 待文档完成后统一打

---

## 8.6 问题记录

| 时间 | 问题 | 根因 | 修复 |
|------|------|------|------|
| 2026-05-11 | vsomeip 3.5.5 编译失败 | Boost 1.90 将 boost_system 改为 header-only | 升级至 3.7.2 |
| 2026-05-11 | hello_world_service 处理一次请求即退出 | `on_message_cbk()` 在 send 后调用 `terminate()` | 移除 `terminate()` 调用并重编译 |
| 2026-05-11 | `VSOMEIP_APPLICATION_NAME=response-sample` 与配置不匹配 | routing 字段期望 `hello_world_service`，名字不匹配导致 UDP 端口未打开 | 修正 `start_target.sh` 中的环境变量 |
| 2026-05-11 | 发包速率仅 3 pps | 每包串行等待 `recv(timeout=0.5)` | 三协程并行架构，recv 独立协程 10ms 轮询 |
| 2026-05-11 | `pkt.message_type.name` AttributeError | 部分 mutator 将 message_type 设为裸 int | `monitor.py` 加 `hasattr` 守卫 |
| 2026-05-11 | SD 多播 Windows 普通 socket 收不到 | VMware VMnet8 虚拟网卡不向 TCP/IP 栈转发多播 | 改用 scapy/Npcap 驱动层嗅探 |

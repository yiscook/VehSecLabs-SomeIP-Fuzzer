# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 常用命令

```bash
uv sync                          # 安装/同步依赖
uv run someip-fuzzer             # 启动 GUI
uv run pytest                    # 运行全部测试（含 GUI tests）
uv run pytest tests/gui/ -v      # 仅跑 GUI 测试
uv run pytest tests/test_protocol.py::test_name -v  # 运行单个测试
uv run ruff check src/           # Lint
uv run mypy src/                 # 类型检查
```

pytest 配置（`pyproject.toml`）：`testpaths = ["tests"]`，默认附带 `--cov=someip_fuzzer`。GUI 测试依赖 `pytest-qt`，需要显示器（Windows 直接可用）。

## 架构概述

### 数据流

```
SomeIpPacket  →  MutationScheduler  →  Transport  →  靶机
   ↑                   ↑                              ↓
SeedCorpus      FeedbackEngine           HeartbeatMonitor / ResponseAnalyzer / AgentClient
                                                      ↓
                                               CrashDetector → CrashStore → replay.py
                                                                    ↓
                                                             Reporter → HTML/PDF/DOCX
```

### 核心引擎（`src/someip_fuzzer/core/`）

**无 GUI 依赖，全部基于 asyncio。**

| 模块 | 职责 |
|------|------|
| `protocol.py` | `SomeIpPacket` dataclass + scapy 封装，`to_bytes()` / `from_bytes()`，SD 报文构造函数 |
| `transport.py` | `SomeIpUdpTransport` / `SomeIpTcpTransport`，异步 send/recv，`on_sent` / `on_received` 回调钩子 |
| `mutator.py` | `BaseMutator` 抽象基类，`MutationResult` 容器，`MUTATOR_REGISTRY` 全局注册表，`MutationScheduler` 权重调度 |
| `mutators/` | 5 层变异实现：layer1_fields/payload（L1，53 种），layer2_semantic/sd（L2，40 种），layer3_state（L3，12 种） |
| `state_machine.py` | `ServiceStateMachine`：按 service_id+instance_id 跟踪 SD 状态（UNKNOWN→DISCOVERED→READY→SUBSCRIBED→RUNNING→EXPIRED），`export_mermaid()` 输出可视化 |
| `attack_chain.py` | YAML DSL → `AttackChain`/`ChainStep`，异步执行多步攻击序列，支持 `${var}` 上下文变量 |
| `feedback.py` | `CompositeFeedback`（0.5×GA + 0.3×Markov + 0.2×Entropy）→ `update_weight()` 驱动调度器 |
| `monitor.py` | `HeartbeatMonitor` + `ResponseAnalyzer` + `AgentClient` 三路融合，任一触发即记录崩溃 |
| `replay.py` | `ReplayScriptGenerator`（生成独立 .py 脚本）+ `DeltaDebugger`（二分最小化） |

### 变异器命名与注册规范

- 命名格式：`L{layer}-{abbr}{NN}.{strategy}`，例如 `L1-S01.boundary_min`
- 每个变异器类必须定义 4 个 `ClassVar`：`name`, `layer`, `target_field`, `strategy`
- 用 `@register_mutator` 装饰器注册到 `MUTATOR_REGISTRY`（`mutator.py`）
- `mutate(seed, rng)` 中**禁用全局 `random` 模块**，必须使用传入的 `rng` 实例（保证重放）
- 合法变异调用 `_make_result(mutated_packet)`；畸形字节调用 `_make_raw_result(raw_bytes)`

### GUI（`src/someip_fuzzer/gui/`）

PyQt6 + qasync 事件循环。**GUI 与核心引擎完全解耦**，通过 `GuiBridge(QObject)` 信号槽通信：核心引擎运行在 asyncio 任务，GUI 在 Qt 主线程。

| 模块 | 职责 |
|------|------|
| `main_window.py` | `MainWindow`：5 Tab 容器、菜单栏、工具栏（F5/F7/F8）、状态栏、主题切换（深色/亮色，`QSettings` 持久化） |
| `bridge.py` | `GuiBridge`：核心引擎→GUI 信号（`packet_sent`/`crash_detected`/`stats_updated`/`log_message`/`state_changed`）；GUI→引擎槽（`start_fuzzing`/`stop_fuzzing`/`update_mutation_config`） |
| `tab_target.py` | Tab 1：靶机网络配置、服务定义表格、连通性测试、TOML 导入导出 |
| `tab_analysis.py` | Tab 2：协议分析，三联面板（虚拟报文列表 + 字段树 + Hex View），pcap 文件加载 |
| `tab_fuzzer.py` | Tab 3：模糊测试，三栏布局（策略树+参数 \| 高性能报文流+日志 \| 实时图表+状态机） |
| `resources/style.qss` | 深色主题（Catppuccin Mocha） |
| `resources/style_light.qss` | 亮色主题（Catppuccin Latte） |

#### 高性能报文流模式（Tab 3 核心）

`PacketStreamModel`（`widgets/packet_stream.py`）采用 5 层机制：
1. `QAbstractTableModel` 虚拟渲染（只绘可视行）
2. `deque(maxlen=5000)` 环形缓冲
3. `BatchedUpdater`（100ms 定时批量刷新，解耦发包线程与 Qt 主线程）
4. 暂停标志位（`is_paused`），崩溃报文绕过暂停立即刷新
5. 颜色编码：蓝发送 / 绿正常 / 黄超时 / 红崩溃

扩展新 Tab 的报文列表时，复用 `PacketTableModel`（Tab 2 版本，无颜色编码，容量 10000）或 `PacketStreamModel`（Tab 3 版本，有颜色，容量 5000）。

### 数据层（`src/someip_fuzzer/data/`）

- `corpus.py`：SQLite 种子语料库，`SeedCorpus.add()` / `sample()` / `update_fitness()`
- `crash_store.py`：`CrashStore`，崩溃记录持久化，`CrashRecord` 含 `severity`（critical/high/medium/low）和 `cvss_score` 字段
- `storage.py`：`SessionStorage`，状态机跨会话持久化

### 工具层（`src/someip_fuzzer/utils/`）

- `config.py`：`load_config()` / `save_config()`，TOML ↔ `AppConfig`（`TargetConfig` + `SdConfig` + `ServiceDef` dataclass）
- `logger.py`：`loguru` 封装，全局 `logger` 实例

## 开发规范

### Git 提交格式（强制）

```
[Phase{N}.{X}] <type>: <subject>
```

type 值：`feat` / `fix` / `refactor` / `test` / `docs` / `chore` / `perf`

每个 Phase 完成后从最终 tag 创建同名保护分支（只读快照）：
```bash
git checkout -b phase-N vN.N.0 && git push origin phase-N && git checkout master
```

### SPEC 驱动流程

`plan/` 目录下每个阶段文档定义任务、验收清单和文件路径。完成后更新状态：`⬜→✅`，`[ ]→[x]`，`status: Not Started → Complete`，并同步 `00-MASTER-SPEC.md`。

### 模型分工

| 任务类型 | 模型 |
|---------|------|
| 常规编码、GUI 实现、测试 | Sonnet 4.6（当前） |
| 高复杂度架构设计（状态机、算法） | Opus 4.7 |
| 重复性模板任务（HTML/CSS/文档润色） | Haiku 4.5 |
| Phase 9 论文/专利/技术报告 | Opus 4.7 |

## 当前进度

| Phase | 状态 | Tag |
|-------|------|-----|
| 0–4（协议核心、变异、状态机、反馈） | ✅ Complete | v0.4.0 |
| 5（GUI 框架 + Tab 1 目标配置 + 双主题） | ✅ Complete | v0.5.0 |
| 6（Tab 2 协议分析 + Tab 3 模糊测试） | ✅ Complete | v0.6.0 |
| 7（Tab 4 结果分析 + Tab 5 报告生成） | ⬜ Next | — |
| 8–9 | ⬜ Not Started | — |

**Phase 4 遗留项（延至 Phase 8）：** 在 vsomeip 已知漏洞版本上实测自动发现崩溃（需 VM 靶机）。

**全部 GUI 完成后（Phase 7 后）：** 使用 PyInstaller 打包为 Windows 单文件 exe。

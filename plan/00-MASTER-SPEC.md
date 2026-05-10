# VehSecLabs-SomeIP-Fuzzer 主SPEC文档

> 项目代号：VSL-SomeIP-Fuzzer
> 配套科研项目：面向车载以太网SOME/IP服务的自动化模糊测试技术研究（TECHKY202503）
> 项目周期：2025.6 - 2026.5
> 主开发：Claude（AI 辅助开发）
> 远程仓库：https://github.com/yiscook/VehSecLabs-SomeIP-Fuzzer

---

## 1. 项目目标（对齐申报书）

开发一套针对车载以太网 SOME/IP 服务的**自动化模糊测试工具**，实现申报书要求的四大创新点：

| 编号 | 创新点 | 对应模块 |
|------|--------|---------|
| C1 | 协议语义感知变异（vs 传统纯语法变异） | `core/mutator.py` Layer 1-2 |
| C2 | 动态服务状态机模型 | `core/state_machine.py` |
| C3 | 多报文攻击链建模 | `core/attack_chain.py` |
| C4 | 反馈优化驱动的测试效率提升 | `core/feedback.py` |

---

## 2. 交付物

### 2.1 软件交付物
- 自动化模糊测试工具（PyQt6 GUI + Python 引擎）
- 一键化 vsomeip 靶机部署脚本
- 完整的单元测试与集成测试

### 2.2 文档交付物
- SPEC 系列文档（本目录 `plan/`）
- 用户手册（`docs/user_manual.md`）
- API 文档（sphinx 自动生成）
- 技术报告 1：协议分析与攻击建模
- 技术报告 2：模糊测试方法论
- 学术论文初稿
- 发明专利初稿

---

## 3. 阶段划分与模型分配

> **模型说明：** Pro 套餐用量有限，按任务复杂度分级使用模型节流。
> - **Opus 4.7（高耗）**：架构设计、SPEC 撰写、关键算法（变异引擎核心、状态机、反馈引擎）
> - **Sonnet 4.6（默认）**：常规编码、GUI 实现、测试用例、调试
> - **Haiku 4.5（轻耗）**：简单重复任务（重命名、注释、commit message、文档润色）

| 阶段 | 内容 | 推荐模型 | 状态 |
|------|------|---------|------|
| Phase 0 | 项目初始化（uv、git、目录） | Haiku | ✅ Complete (2026-05-10) |
| Phase 1 | 协议核心层（报文构造、传输） | Sonnet | ✅ Complete (2026-05-10, v0.1.0) |
| Phase 2 | 变异引擎（5 层变异） | **Opus** + Sonnet | ✅ Complete (2026-05-10, v0.2.0) |
| Phase 3 | 状态机 + 攻击链 | **Opus** + Sonnet | ✅ Complete (2026-05-10, v0.3.0) |
| Phase 4 | 反馈引擎 + 崩溃检测 + 重放 | **Opus** + Sonnet | ✅ Complete (2026-05-10, v0.4.0) |
| Phase 5 | GUI 框架 + 目标配置 | Sonnet | ✅ Complete (2026-05-10, v0.5.0) |
| Phase 6 | GUI 协议分析 + 模糊测试（高性能报文流） | Sonnet | ✅ Complete (2026-05-11, v0.6.0) |
| Phase 7 | GUI 结果分析 + 报告生成 | Sonnet + Haiku | ✅ Complete (2026-05-11, v0.7.0) |
| Phase 8 | vsomeip 靶机集成 + 端到端联调 | Sonnet | ⬜ Not Started |
| Phase 9 | 文档与交付物（专利、论文、技术报告） | **Opus** | ⬜ Not Started |

---

## 4. 工作流（每阶段必须遵循）

```
┌────────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ 阅读 SPEC   │──>│ 编码实现 │──>│ 单元测试 │──>│ 验收检查 │──>│ Git 提交 │
└────────────┘   └──────────┘   └──────────┘   └────┬─────┘   └────┬─────┘
                       │                            │              │
                       │   ┌─────────┐    fail      │              │
                       └──<│ 修复优化│<─────────────┘              │
                           └─────────┘                              │
                                                              ┌────▼─────┐
                                                              │push GitHub│
                                                              └──────────┘
```

**强制规则：**
1. 每阶段开始前，必须先打开本阶段的 SPEC 文档，确认任务清单
2. 每完成一个**子任务**（不是整个 Phase），立刻 `git commit`，commit message 格式 `[PhaseN.M] 子任务描述`
3. 单元测试覆盖率 ≥ 70%
4. 验收清单必须 100% 通过才能进入下一阶段
5. 每阶段验收通过后，必须 `git push` 到 GitHub
6. 验收失败时，在 SPEC 文档的"问题记录"章节追加问题，修复后重新验收

---

## 5. 全局技术栈

| 层级 | 选型 | 备注 |
|------|------|------|
| 包管理 | **uv** ≥ 0.11 | 跨设备一致环境 |
| Python 版本 | ≥ 3.11 | 利用新语法、性能改进 |
| 协议库 | `scapy.contrib.automotive.someip` | SOME/IP + SD 报文构造 |
| GUI 框架 | **PyQt6** ≥ 6.6 | 跨平台、性能好 |
| 异步框架 | `asyncio` + `qasync` | GUI 与 IO 解耦 |
| 数据库 | SQLite（标准库） | 测试用例 + 崩溃存档 |
| 配置 | TOML（`tomli`/`tomllib`） | 现代、可读 |
| 报告模板 | Jinja2 + WeasyPrint | HTML → PDF |
| 图表 | PyQtGraph | GUI 内嵌实时图表（比 matplotlib 快 10x） |
| 抓包 | scapy + Npcap | Windows 已装 |
| 日志 | loguru | 比标准 logging 简洁 |
| 测试 | pytest + pytest-qt | 含 GUI 测试 |
| 文档 | Sphinx | API 文档自动生成 |

**禁用：**
- ❌ boofuzz（已确认不需要）
- ❌ someipy（不适合模糊测试）
- ❌ eth_scapy_someip（功能与 scapy 内置重叠）
- ❌ TensorFlow / PyTorch（性能受限，留接口给后续 Demo）

---

## 6. 项目目录约定

```
VehSecLabs-SomeIP-Fuzzer/
├── pyproject.toml          # uv 项目定义
├── uv.lock                 # 依赖锁
├── README.md
├── .gitignore
├── .python-version
│
├── plan/                   # SPEC 文档（本目录）
│   ├── 00-MASTER-SPEC.md
│   ├── 01-PHASE-0-INIT.md
│   ├── 02-PHASE-1-PROTOCOL.md
│   ├── ...
│   └── 10-PHASE-9-DELIVERABLES.md
│
├── src/someip_fuzzer/      # 源码主目录
│   ├── core/               # 核心引擎（无 GUI 依赖）
│   ├── gui/                # PyQt6 GUI
│   ├── data/               # 数据模型与持久化
│   └── utils/              # 工具
│
├── tests/                  # pytest 测试
├── configs/                # 配置模板
├── corpus/                 # 种子报文库
├── scripts/                # 部署脚本（vsomeip 安装等）
├── docs/                   # 用户文档（手册、API）
└── results/                # 运行时输出（gitignore）
```

---

## 7. 关键性能 / 质量指标

| 指标 | 目标值 | 测量方式 |
|------|--------|---------|
| 模糊测试发包速率 | ≥ 1000 pps | 内置统计 |
| GUI 在 10000+ 报文显示时无卡顿 | 滚动 60fps | 手动 + pytest-qt |
| 崩溃复现成功率 | ≥ 95% | 重放统计 |
| 单元测试覆盖率 | ≥ 70% | pytest-cov |
| 启动到首屏 | ≤ 2s | 计时 |
| 内存占用（24h 测试后） | ≤ 500MB | psutil 监控 |

---

## 8. Git 提交规范

```
[Phase{N}.{M}] <type>: <subject>

<body>

<footer>
```

**type：** feat / fix / refactor / test / docs / chore / perf

**示例：**
```
[Phase2.3] feat: 实现 Layer 3 状态机变异

- 新增 StateMachineMutator 类
- 支持 4 种状态迁移异常注入
- 单元测试覆盖率 85%

Refs: plan/03-PHASE-2-MUTATION.md
```

---

## 9. 阶段索引

- [Phase 0 - 项目初始化](./01-PHASE-0-INIT.md)
- [Phase 1 - 协议核心层](./02-PHASE-1-PROTOCOL.md)
- [Phase 2 - 变异引擎](./03-PHASE-2-MUTATION.md)
- [Phase 3 - 状态机+攻击链](./04-PHASE-3-STATE-ATTACK.md)
- [Phase 4 - 反馈引擎+崩溃检测](./05-PHASE-4-FEEDBACK-CRASH.md)
- [Phase 5 - GUI 框架+目标配置](./06-PHASE-5-GUI-BASE.md)
- [Phase 6 - GUI 协议分析+模糊测试](./07-PHASE-6-GUI-FUZZ.md)
- [Phase 7 - GUI 结果分析+报告](./08-PHASE-7-GUI-REPORT.md)
- [Phase 8 - vsomeip 集成联调](./09-PHASE-8-INTEGRATION.md)
- [Phase 9 - 交付物（专利、论文、报告）](./10-PHASE-9-DELIVERABLES.md)

---

## 10. 状态字段约定

每个阶段 SPEC 顶部维护：

```yaml
phase: N
title: <阶段名>
status: Not Started | In Progress | Testing | Acceptance | Complete | Failed
started_at: YYYY-MM-DD
completed_at: YYYY-MM-DD
acceptance_passed: false
git_tag: v0.N.0
```

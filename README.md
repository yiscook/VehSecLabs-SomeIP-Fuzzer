# VehSecLabs-SomeIP-Fuzzer

[![CI](https://github.com/yiscook/VehSecLabs-SomeIP-Fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/yiscook/VehSecLabs-SomeIP-Fuzzer/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

面向车载以太网 SOME/IP 服务的自动化模糊测试工具。

> 科研项目 TECHKY202503「面向车载以太网SOME/IP服务的自动化模糊测试技术研究」配套软件

---

## 功能特性

- **5 层变异架构**：协议字段变异 → 语义感知变异 → 状态机变异 → 攻击链编排 → 反馈优化
- **118+ 种变异策略**：覆盖 SOME/IP 报头、服务发现、序列化数据等全部关键字段
- **动态状态机建模**：跟踪服务生命周期，注入状态迁移异常
- **多报文攻击链**：YAML DSL 定义 8 种内置攻击链（服务劫持、DoS、重放等）
- **高性能 GUI**：PyQt6 + 虚拟列表，1000 pps 发包下 GUI 不卡顿
- **专业报告生成**：HTML / PDF / DOCX 三种格式，含 CVSS 评分

## 环境要求

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) 包管理器
- Windows 11 + Npcap（主机侧）
- Ubuntu VM + vsomeip（靶机侧，见 `scripts/install_vsomeip.sh`）

## 快速开始

```bash
# 克隆仓库
git clone https://github.com/yiscook/VehSecLabs-SomeIP-Fuzzer.git
cd VehSecLabs-SomeIP-Fuzzer

# 安装依赖（uv 自动创建 .venv）
uv sync

# 启动工具
uv run someip-fuzzer
```

## 开发

```bash
# 运行测试
uv run pytest

# 代码格式检查
uv run ruff check src/

# 类型检查
uv run mypy src/
```

## 项目结构

```
src/someip_fuzzer/
├── core/        # 核心引擎（协议、变异、状态机、反馈）
├── gui/         # PyQt6 GUI（5 个 Tab）
├── data/        # 数据模型与 SQLite 持久化
└── utils/       # 工具函数
```

## 许可证

MIT License — 详见 [LICENSE](LICENSE)

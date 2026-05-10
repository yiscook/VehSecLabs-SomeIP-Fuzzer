# Phase 0 - 项目初始化

```yaml
phase: 0
title: 项目初始化
status: Complete
recommended_model: Haiku 4.5
acceptance_passed: true
started_at: 2026-05-10
completed_at: 2026-05-10
git_tag: v0.0.0
```

---

## 0.1 目标

建立工程脚手架，确保 `git clone + uv sync` 即可在任何设备复现开发环境。

---

## 0.2 任务清单

| ID | 任务 | 状态 |
|----|------|------|
| 0.1 | 创建标准目录结构 | ✅ |
| 0.2 | 编写 `pyproject.toml`（uv 项目定义） | ✅ |
| 0.3 | 编写 `.python-version`（锁定 Python 版本） | ✅ |
| 0.4 | 编写 `.gitignore` | ✅ |
| 0.5 | 编写初始 `README.md` | ✅ |
| 0.6 | 执行 `uv sync` 生成 `uv.lock` | ✅ |
| 0.7 | 初始化 git 仓库并添加 remote | ✅ |
| 0.8 | 创建 `src/someip_fuzzer/__init__.py` 骨架 | ✅ |
| 0.9 | 创建 `src/someip_fuzzer/main.py` 入口（仅打印 banner） | ✅ |
| 0.10 | 创建初始 GitHub Actions CI 配置（pytest） | ✅ |
| 0.11 | 验证 `uv run someip-fuzzer` 可正常启动 | ✅ |

---

## 0.3 目录结构（标准）

```
VehSecLabs-SomeIP-Fuzzer/
├── pyproject.toml
├── uv.lock
├── .python-version
├── .gitignore
├── README.md
├── LICENSE
│
├── plan/                # SPEC 文档（已存在）
│
├── src/someip_fuzzer/
│   ├── __init__.py
│   ├── main.py          # 入口
│   ├── core/__init__.py
│   ├── gui/__init__.py
│   ├── data/__init__.py
│   └── utils/__init__.py
│
├── tests/
│   ├── __init__.py
│   └── test_smoke.py    # 启动冒烟测试
│
├── configs/
├── corpus/seeds/
├── scripts/
├── docs/
├── results/             # gitignore
│
└── .github/workflows/
    └── ci.yml
```

---

## 0.4 关键文件内容

### `pyproject.toml`

```toml
[project]
name = "someip-fuzzer"
version = "0.1.0"
description = "Automated fuzzing tool for automotive SOME/IP services"
authors = [{name = "VehSecLabs"}]
requires-python = ">=3.11"
license = {text = "MIT"}
dependencies = [
    "scapy>=2.5",
    "PyQt6>=6.6",
    "qasync>=0.27",
    "pyqtgraph>=0.13",
    "loguru>=0.7",
    "jinja2>=3.1",
    "weasyprint>=60",
    "tomli-w>=1.0",
    "psutil>=5.9",
]

[project.scripts]
someip-fuzzer = "someip_fuzzer.main:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/someip_fuzzer"]

[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-qt>=4.4",
    "pytest-asyncio>=0.23",
    "ruff>=0.6",
    "mypy>=1.10",
    "sphinx>=7.0",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --cov=someip_fuzzer --cov-report=term-missing"

[tool.ruff]
line-length = 100
target-version = "py311"
```

### `.python-version`
```
3.11
```

### `.gitignore`
```
# Python
__pycache__/
*.py[cod]
*.egg-info/
.venv/
.pytest_cache/
.coverage
htmlcov/
.mypy_cache/
.ruff_cache/

# IDE
.vscode/
.idea/
*.swp

# Build
build/
dist/

# Project specific
results/
*.pcap
*.db

# OS
.DS_Store
Thumbs.db
```

---

## 0.5 测试

### 单元测试 `tests/test_smoke.py`
```python
def test_import():
    """模块可导入"""
    import someip_fuzzer
    assert someip_fuzzer.__version__ == "0.2.0"

def test_main_callable():
    """入口函数可调用"""
    from someip_fuzzer.main import main
    assert callable(main)
```

### 手动验证
```bash
uv sync
uv run pytest
uv run someip-fuzzer --help
```

---

## 0.6 验收清单

- [x] `uv sync` 在干净环境成功执行
- [x] `uv run pytest` 通过（包含 `test_smoke.py`）
- [x] `uv run someip-fuzzer` 能正常启动并打印 banner
- [x] `git status` 干净，无未追踪文件（除了 results/）
- [x] `git log` 至少 5 条原子提交（共 6 条）
- [x] 远程 https://github.com/yiscook/VehSecLabs-SomeIP-Fuzzer 同步

---

## 0.7 问题记录

**2026-05-10 问题：中文路径 GBK 编码冲突**

Windows 中文系统 GBK locale 下，Python site 模块读 `.pth` 文件时用 GBK 解码，但 uv 写的 `.pth` 是 UTF-8，导致 `init_import_site` 崩溃。

修复方案：
1. `setx PYTHONUTF8 1` — 永久设置用户环境变量（新 Terminal 后生效，uv sync 后可正常读 UTF-8 `.pth`）
2. 当次会话临时修复：PowerShell 将 `.pth` 文件重写为 GBK 编码：
   ```powershell
   $gbk = [System.Text.Encoding]::GetEncoding(936)
   [System.IO.File]::WriteAllText($pthFile, $content, $gbk)
   ```

# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for VehSecLabs SomeIP Fuzzer.
Build: uv run pyinstaller someip_fuzzer.spec
Output: dist/VehSecLabs-SomeIP-Fuzzer/
"""

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

# ── 数据文件 ──────────────────────────────────────────────────────────────────
datas = [
    # QSS 主题文件（路径需与 Path(__file__).parent/"resources"/"style.qss" 对齐）
    ('src/someip_fuzzer/gui/resources/style.qss', 'someip_fuzzer/gui/resources'),
    # 攻击链 YAML 配置
    ('configs', 'configs'),
    # 报告 Jinja2 模板（如果有）
]

# 加入 scapy contrib 数据文件
datas += collect_data_files('scapy', includes=['**/*.py'])

# ── 隐式导入 ──────────────────────────────────────────────────────────────────
hiddenimports = [
    # 变异器——由 @register_mutator 装饰器在运行时注册，PyInstaller 无法静态分析
    'someip_fuzzer.core.mutators',
    'someip_fuzzer.core.mutators.layer1_fields',
    'someip_fuzzer.core.mutators.layer1_payload',
    'someip_fuzzer.core.mutators.layer2_semantic',
    'someip_fuzzer.core.mutators.layer2_sd',
    'someip_fuzzer.core.mutators.layer3_state',
    # scapy contrib
    'scapy.contrib.automotive.someip',
    'scapy.contrib.automotive',
    'scapy.layers.inet',
    'scapy.layers.l2',
    'scapy.utils',
    'scapy.sendrecv',
    # 运行时库
    'qasync',
    'pyqtgraph',
    'psutil',
    'yaml',
    'jinja2',
    'jinja2.ext',
    'tomllib',
    'tomli_w',
    'loguru',
    'docx',
    'docx.oxml',
    'docx.oxml.ns',
    # weasyprint 是可选项（需要系统 GTK），ImportError 由代码层面 catch
    # 不强制包含，避免打包体积过大
    'asyncio',
    'sqlite3',
    'email',
    'email.mime',
    'email.mime.text',
]

# 收集所有 scapy 子模块（scapy 大量使用动态导入）
hiddenimports += collect_submodules('scapy')
hiddenimports += collect_submodules('PyQt6')

# ── 排除不需要的大型库 ────────────────────────────────────────────────────────
excludes = [
    'matplotlib',
    'numpy',          # scapy 可选依赖，不需要
    'IPython',
    'jupyter',
    'tkinter',
    'wx',
    'gi',             # GTK（weasyprint 在无 GTK 时会优雅降级）
    'cairo',
    'test',
    'unittest',
    'pytest',
    'sphinx',
    'mypy',
    'ruff',
]

# ── Analysis ──────────────────────────────────────────────────────────────────
a = Analysis(
    ['src/someip_fuzzer/main.py'],
    pathex=['src'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ── EXE ───────────────────────────────────────────────────────────────────────
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,          # 使用 COLLECT（one-dir 模式）
    name='VehSecLabs-SomeIP-Fuzzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                      # UPX 可能触发杀毒软件误报，关闭
    console=False,                  # 不显示控制台窗口（GUI 应用）
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

# ── COLLECT（one-dir 输出到 dist/VehSecLabs-SomeIP-Fuzzer/） ──────────────────
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='VehSecLabs-SomeIP-Fuzzer',
)

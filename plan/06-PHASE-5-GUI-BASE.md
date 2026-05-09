# Phase 5 - GUI 框架 + 目标配置 Tab

```yaml
phase: 5
title: PyQt6 主框架 + 目标配置
status: Not Started
recommended_model: Sonnet 4.6
acceptance_passed: false
git_tag: v0.5.0
```

---

## 5.1 目标

搭建 PyQt6 主窗口和 Tab 容器框架，完成第一个 Tab（目标配置），建立 GUI ↔ 核心引擎的异步通信骨架。

---

## 5.2 任务清单

### 5.A - 主框架

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 5.1 | 主窗口 `MainWindow`（菜单栏、Tab、状态栏） | `gui/main_window.py` | ⬜ |
| 5.2 | qasync 集成（asyncio 与 Qt 事件循环融合） | `gui/main_window.py` | ⬜ |
| 5.3 | 主题与样式表（深色主题，专业感） | `gui/resources/style.qss` | ⬜ |
| 5.4 | 全局快捷键（F5 启动、F8 停止、Ctrl+S 保存） | `gui/main_window.py` | ⬜ |
| 5.5 | 项目树侧边栏（左侧 Dock） | `gui/widgets/project_tree.py` | ⬜ |
| 5.6 | 全局状态栏（靶机连接状态、统计） | `gui/main_window.py` | ⬜ |
| 5.7 | 工具栏（常用操作快捷按钮） | `gui/main_window.py` | ⬜ |
| 5.8 | 关于对话框（含项目信息、版本） | `gui/dialogs/about.py` | ⬜ |
| 5.9 | 菜单：文件/视图/工具/帮助 | `gui/main_window.py` | ⬜ |
| 5.10 | GUI ↔ 核心引擎的信号桥（QSignal） | `gui/bridge.py` | ⬜ |

### 5.B - Tab 1: 目标配置

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 5.11 | 靶机网络配置组（IP、端口、传输协议） | `gui/tab_target.py` | ⬜ |
| 5.12 | SOME/IP 服务定义组（Service ID、Instance、Method/Event 列表） | `gui/tab_target.py` | ⬜ |
| 5.13 | 服务定义表格（动态增删行） | `gui/tab_target.py` | ⬜ |
| 5.14 | 连通性测试按钮（异步发心跳） | `gui/tab_target.py` | ⬜ |
| 5.15 | 配置导入/导出（TOML） | `gui/tab_target.py` | ⬜ |
| 5.16 | 最近使用配置列表 | `gui/tab_target.py` | ⬜ |
| 5.17 | 模板选择（vsomeip 默认、自定义） | `gui/tab_target.py` | ⬜ |
| 5.18 | 网络接口选择（列出 Windows 所有网卡） | `gui/tab_target.py` | ⬜ |

---

## 5.3 主窗口布局设计

```
┌──────────────────────────────────────────────────────────────────────┐
│ 文件(F)  视图(V)  工具(T)  帮助(H)                                    │
├──────────────────────────────────────────────────────────────────────┤
│ [▶启动F5] [⏸暂停F7] [⏹停止F8]  │ [📥导入] [📤导出] │ [🔍抓包] [📊报告] │
├──────┬────────────────────────────────────────────────────────────────┤
│      │  ┌─目标配置─协议分析─模糊测试─结果分析─报告生成─┐               │
│ 项目 │  │                                                  │              │
│ 树   │  │                                                  │              │
│      │  │              （当前 Tab 内容）                    │              │
│ 历史 │  │                                                  │              │
│ 会话 │  │                                                  │              │
│      │  │                                                  │              │
│      │  └──────────────────────────────────────────────────┘              │
├──────┴────────────────────────────────────────────────────────────────┤
│ 🟢 靶机:192.168.81.128:30509  │ 已发送:0  崩溃:0  速率:0pps  │ 14:30:45│
└──────────────────────────────────────────────────────────────────────┘
```

### 设计原则

- **左侧项目树**：可折叠 Dock，方便切换历史会话
- **中央 Tab**：始终可见
- **底部状态栏**：核心指标常驻（连接状态、发送量、崩溃数、速率、时间）
- **顶部工具栏**：高频操作一键到位
- **菜单栏**：完整功能入口

---

## 5.4 Tab 1 - 目标配置详细布局

```
┌──────────────────────────────────────────────────────────────┐
│  📡 靶机网络配置                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ IP 地址：  [192.168.81.128         ▼] (历史)           │  │
│  │ 端口：     [30509          ]                          │  │
│  │ 传输协议：  ⊙ UDP   ○ TCP   ○ TCP+UDP                  │  │
│  │ 网络接口：  [VMnet8 (192.168.81.1)            ▼]       │  │
│  │ SD 多播组：[224.224.224.245     ]   端口:[30490]     │  │
│  │                                  [🔌 连通性测试]         │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  📋 SOME/IP 服务定义                                          │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Service ID │ Instance │ Major │ Minor │ Methods        │  │
│  │  0x1234   │  0x0001  │   1   │   0   │ 0x8001,0x8002 │  │
│  │  0xA994   │  0x5678  │   1   │   0   │ 0x0100,0x0101 │  │
│  │  ...                                                    │  │
│  │ [+ 添加]  [- 删除]  [编辑]                             │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  💾 配置管理                                                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ 模板：[vsomeip 默认  ▼]   [📥导入TOML] [📤导出TOML]   │  │
│  │ 当前：configs/target_vsomeip.toml                      │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## 5.5 GUI ↔ 引擎通信桥

GUI 和核心引擎完全解耦，通过信号槽通信：

```python
class GuiBridge(QObject):
    # 信号：核心引擎 → GUI
    packet_sent = pyqtSignal(SomeIpPacket)
    packet_received = pyqtSignal(SomeIpPacket)
    crash_detected = pyqtSignal(CrashInfo)
    state_changed = pyqtSignal(str, str)  # service, new_state
    stats_updated = pyqtSignal(dict)       # 统计数据
    log_message = pyqtSignal(str, str)     # level, message
    
    # 槽：GUI → 核心引擎
    @pyqtSlot()
    def start_fuzzing(self): ...
    
    @pyqtSlot()
    def stop_fuzzing(self): ...
```

**关键：核心引擎运行在 asyncio 任务，GUI 在主线程。** 通过 qasync 桥接两者。

---

## 5.6 配置文件格式

`configs/target_vsomeip.toml`:
```toml
[target]
name = "vsomeip 默认靶机"
ip = "192.168.81.128"
port = 30509
transport = "udp"
interface = "VMnet8"

[sd]
multicast = "224.224.224.245"
port = 30490

[[services]]
service_id = 0x1234
instance_id = 0x0001
major_version = 1
minor_version = 0
methods = [0x8001, 0x8002]
events = [0x0100]

[[services]]
service_id = 0xA994
instance_id = 0x5678
major_version = 1
minor_version = 0
methods = [0x0100, 0x0101]
```

---

## 5.7 测试

### GUI 测试（pytest-qt）

```python
def test_main_window_starts(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    assert window.isVisible() is False
    window.show()
    assert window.tabWidget.count() == 5

def test_target_tab_save_load(qtbot, tmp_path):
    window = MainWindow()
    qtbot.addWidget(window)
    target_tab = window.tab_target
    target_tab.ip_input.setText("10.0.0.1")
    target_tab.port_input.setValue(30509)
    
    config_path = tmp_path / "test.toml"
    target_tab.save_config(config_path)
    
    target_tab.ip_input.setText("0.0.0.0")
    target_tab.load_config(config_path)
    assert target_tab.ip_input.text() == "10.0.0.1"
```

### 启动测试

```python
def test_app_launches():
    app = QApplication([])
    window = MainWindow()
    window.show()
    QTimer.singleShot(100, app.quit)
    app.exec()  # 不应抛异常
```

---

## 5.8 验收清单

- [ ] 主窗口能正常启动并显示 5 个 Tab
- [ ] qasync 集成正常，可发起异步任务不卡 UI
- [ ] 项目树、状态栏、工具栏齐备
- [ ] 目标配置 Tab 完整可用
- [ ] 配置可导入导出 TOML
- [ ] 连通性测试可实际发包并显示结果
- [ ] 网络接口列表自动加载本机所有可用接口
- [ ] 启动到首屏 ≤ 2s
- [ ] 单元测试覆盖率 ≥ 60%（GUI 测试相对宽松）
- [ ] git 规范提交、push GitHub

---

## 5.9 问题记录

（验收失败时在此追加）

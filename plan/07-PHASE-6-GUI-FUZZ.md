# Phase 6 - GUI 协议分析 + 模糊测试 Tab（高性能报文流）

```yaml
phase: 6
title: 协议分析 + 模糊测试 Tab（重点解决高性能报文流显示）
status: Complete
recommended_model: Sonnet 4.6
acceptance_passed: true
started_at: 2026-05-11
completed_at: 2026-05-11
git_tag: v0.6.0
```

---

## 6.1 目标

实现两个核心 Tab，**重点解决高吞吐量下报文流显示不卡顿的问题**：
- Tab 2：协议分析（实时抓包、字段可视化）
- Tab 3：模糊测试（变异策略选择、启动控制、实时报文流、统计图表）

---

## 6.2 高性能报文流显示方案

### 6.2.1 性能问题分析

模糊测试每秒可能发 1000+ 报文。如果 GUI 直接显示每个报文：
- ❌ 直接 append 到 QListWidget → 几千条后明显卡顿
- ❌ 每个报文触发 GUI 重绘 → 主线程阻塞
- ❌ 全量持久化每个报文 → 磁盘 IO 瓶颈

### 6.2.2 解决方案（5 个机制叠加）

#### 机制 1：虚拟列表（QAbstractTableModel）

不用 QListWidget/QTableWidget，**用 QAbstractTableModel + QTableView**。
- 只渲染可视区域的行（即使有 100 万条数据也只画 30 行）
- 内置高效索引

#### 机制 2：环形缓冲区

GUI 只保留最近 N 条（如 5000 条），更早的数据自动转入磁盘存储。
```python
class RingBuffer:
    def __init__(self, capacity: int = 5000):
        self.buffer = collections.deque(maxlen=capacity)
    
    def append(self, item):
        self.buffer.append(item)  # 自动丢弃旧数据
```

#### 机制 3：批量更新（节流）

不要每个报文都更新 UI，攒到一起批量提交：
```python
class BatchedUpdater(QObject):
    def __init__(self, interval_ms: int = 100):
        self.pending = []
        self.timer = QTimer()
        self.timer.setInterval(interval_ms)
        self.timer.timeout.connect(self.flush)
        self.timer.start()
    
    def add(self, item):
        self.pending.append(item)
    
    def flush(self):
        if self.pending:
            self.model.beginInsertRows(...)
            self.model.items.extend(self.pending)
            self.model.endInsertRows()
            self.pending.clear()
```

#### 机制 4：生产者-消费者解耦

核心引擎在 worker 线程发包，通过线程安全队列把报文交给 GUI：
```python
# 发包线程
async def fuzzer_loop():
    while running:
        pkt = mutator.generate()
        await transport.send(pkt)
        gui_queue.put_nowait(pkt)  # 不阻塞

# GUI 线程
def consume_packets():
    while not gui_queue.empty():
        pkt = gui_queue.get_nowait()
        batched_updater.add(pkt)
```

#### 机制 5：暂停/继续显示（不影响发包）

显示暂停按钮，让 GUI 停止刷新，但发包继续。这样用户能仔细查看时不会被新报文挤走。

---

## 6.3 任务清单

### 6.A - Tab 2: 协议分析

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 6.1 | 抓包源选择（实时网卡 / pcap 文件） | `gui/tab_analysis.py` | ✅ |
| 6.2 | 抓包过滤器（BPF 表达式） | `gui/tab_analysis.py` | ✅ |
| 6.3 | 报文列表视图（虚拟模型） | `gui/widgets/packet_table.py` | ✅ |
| 6.4 | 报文字段树视图（解析后字段） | `gui/widgets/packet_tree.py` | ✅ |
| 6.5 | 原始字节 Hex View | `gui/widgets/hex_view.py` | ✅ |
| 6.6 | 字段值与 Hex 联动高亮 | `gui/widgets/hex_view.py` | ✅ |
| 6.7 | 一键加入 corpus（作为变异种子） | `gui/tab_analysis.py` | ✅ |
| 6.8 | 导出选中报文为 pcap | `gui/tab_analysis.py` | ✅ |
| 6.9 | 协议过滤（只显示 SOME/IP / SD） | `gui/tab_analysis.py` | ✅ |

### 6.B - Tab 3: 模糊测试（核心）

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 6.10 | 变异策略选择树（按 Layer 分组，可勾选） | `gui/widgets/strategy_tree.py` | ✅ |
| 6.11 | 目标字段勾选面板 | `gui/tab_fuzzer.py` | ✅ |
| 6.12 | 测试参数（用例数、时长、速率、超时） | `gui/tab_fuzzer.py` | ✅ |
| 6.13 | 攻击链选择（来自 Phase 3） | `gui/tab_fuzzer.py` | ✅ |
| 6.14 | 启动/暂停/停止大按钮 | `gui/tab_fuzzer.py` | ✅ |
| 6.15 | 实时报文流显示（虚拟表格 + 批量更新） | `gui/widgets/packet_stream.py` | ✅ |
| 6.16 | 报文流过滤（只看崩溃、只看响应、关键字） | `gui/widgets/packet_stream.py` | ✅ |
| 6.17 | 暂停/继续显示按钮（不影响发包） | `gui/widgets/packet_stream.py` | ✅ |
| 6.18 | 实时统计图（PyQtGraph，发送速率、崩溃时间线） | `gui/widgets/stats_charts.py` | ✅ |
| 6.19 | 状态机可视化面板（Phase 3 状态实时显示） | `gui/widgets/state_view.py` | ✅ |
| 6.20 | 日志窗口（彩色分级，限流） | `gui/widgets/log_view.py` | ✅ |
| 6.21 | 预设配置（保存/加载常用变异组合） | `gui/tab_fuzzer.py` | ✅ |

---

## 6.4 Tab 3 模糊测试 详细布局

```
┌──────────────────────────────────────────────────────────────────────┐
│  ┌─[左侧]变异控制────┐ ┌─[中央]报文流────────────────────┐ ┌─[右侧]统计─┐│
│  │ 📚 变异策略       │ │ ┌─────────────────────────────┐ │ │ 📊 实时图表  │
│  │  ☑ Layer 1 字段  │ │ │时间│方向│SrvID│Type│长度│状态│ │ │            │
│  │   ☑ Service ID   │ │ ├────┼────┼─────┼────┼────┼───┤ │ │ [发送速率] │
│  │   ☑ Method ID    │ │ │... │ →  │1234 │REQ │ 16 │OK │ │ │  ╱╲ ╱╲    │
│  │  ☑ Layer 2 语义  │ │ │... │ ←  │1234 │RES │ 24 │OK │ │ │ ╱  V  ╲   │
│  │  ☑ Layer 3 状态  │ │ │... │ →  │FFFF │REQ │1MB │💥 │ │ │            │
│  │  ☐ Layer 4 攻击链│ │ │...                          │ │ │ [崩溃时间]  │
│  │  ☐ Layer 5 反馈  │ │ │   (虚拟列表，5000+条不卡)    │ │ │  | | ||  | │
│  │                   │ │ └─────────────────────────────┘ │ │            │
│  │ 📋 攻击链         │ │ [▶继续显示] [过滤▼] [Hex] 5421条│ │ [状态机]   │
│  │  ○ 服务劫持链     │ │                                  │ │ ○─→●─→○   │
│  │  ○ DoS耗尽链     │ │ ┌─[底部]单条详情──────────────┐ │ │            │
│  │  ● 无             │ │ │字段树 + Hex View（同 Tab2） │ │ │            │
│  │                   │ │ └─────────────────────────────┘ │ │            │
│  │ ⚙️ 参数            │ │                                  │ │            │
│  │  用例数: [10000]  │ │ ┌─[更底部]日志窗口─────────────┐│ │            │
│  │  速率:[1000pps]   │ │ │[14:30:01] INFO  开始测试...  ││ │            │
│  │  超时:[2.0s]      │ │ │[14:30:02] WARN  超时         ││ │            │
│  │                   │ │ │[14:30:05] ERROR 检测到崩溃   ││ │            │
│  │ [▶ 开始 F5]      │ │ └─────────────────────────────┘│ │            │
│  │ [⏸ 暂停 F7]      │ └──────────────────────────────────┘ │            │
│  │ [⏹ 停止 F8]      │                                       │            │
│  └───────────────────┘                                       └────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

### 用户体验设计

- **左侧策略区**：树形多选，记忆用户选择
- **中央报文流**：虚拟表格，5000+ 报文流畅滚动
- **报文颜色编码**：
  - 🔵 蓝色 = 发送
  - 🟢 绿色 = 收到正常响应
  - 🟡 黄色 = 超时
  - 🔴 红色 = 检测到崩溃
- **暂停继续**：暂停后表格停止刷新但发包继续，方便用户检查
- **底部详情**：选中任一报文显示完整字段树
- **右侧实时图表**：动态曲线图，60fps 流畅
- **状态机可视化**：实时显示当前服务状态

---

## 6.5 关键性能指标

| 场景 | 目标 |
|------|------|
| 发包速率 1000 pps，UI 是否流畅 | ✅ 60fps 滚动 |
| 累计 100,000 报文后内存占用 | ≤ 200MB |
| 单报文添加到 UI 的延迟 | ≤ 100ms |
| 字段树展开/折叠响应 | ≤ 50ms |
| 暂停后立即可滚动检查 | ≤ 16ms |

---

## 6.6 测试

### 性能压测

```python
def test_packet_stream_under_high_load(qtbot, benchmark):
    stream = PacketStreamWidget()
    qtbot.addWidget(stream)
    
    def add_10000():
        for i in range(10000):
            stream.add_packet(make_test_packet(i))
    
    benchmark(add_10000)
    # 断言：10000 条添加在 1 秒内完成
    assert benchmark.stats['mean'] < 1.0

def test_ui_responsive_during_fuzzing(qtbot):
    """模糊测试运行时，UI 仍可响应点击"""
    window = MainWindow()
    qtbot.addWidget(window)
    window.tab_fuzzer.start_fuzzing()
    
    # 模拟 1000 报文涌入
    for _ in range(1000):
        window.tab_fuzzer.bridge.packet_sent.emit(random_packet())
    
    # UI 应仍能响应按钮点击
    qtbot.mouseClick(window.tab_fuzzer.btn_pause, Qt.MouseButton.LeftButton)
    assert window.tab_fuzzer.is_paused()
```

---

## 6.7 验收清单

- [x] Tab 2 能从网卡实时抓包 SOME/IP 报文
- [x] Tab 2 能加载 pcap 文件并解析
- [x] Tab 2 字段树与 Hex View 联动高亮
- [x] Tab 3 变异策略树包含 Phase 2-4 全部策略
- [x] Tab 3 攻击链下拉包含 Phase 3 全部 8 个内置链
- [x] Tab 3 报文流在 1000 pps 持续 60s 不卡顿
- [x] Tab 3 报文颜色编码正确（蓝/绿/黄/红）
- [x] Tab 3 暂停显示按钮工作正常（发包不停）
- [x] Tab 3 实时图表 60fps 流畅
- [x] Tab 3 状态机可视化与 Phase 3 状态机同步
- [x] 100,000 报文后内存 ≤ 200MB
- [x] 单元测试覆盖率 ≥ 65%
- [x] git 规范提交、push GitHub

---

## 6.8 问题记录

（验收失败时在此追加）

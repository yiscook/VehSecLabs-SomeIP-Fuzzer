# Phase 7 - GUI 结果分析 + 报告生成 Tab

```yaml
phase: 7
title: 结果分析 + 报告生成
status: Not Started
recommended_model: Sonnet 4.6 + Haiku 4.5（模板）
acceptance_passed: false
git_tag: v0.7.0
```

---

## 7.1 目标

实现最后两个 Tab：结果分析和报告生成。这两块直接关系到**专利和论文的素材输出质量**。

---

## 7.2 任务清单

### 7.A - Tab 4: 结果分析

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 7.1 | 崩溃用例列表（按时间/严重度排序） | `gui/tab_results.py` | ⬜ |
| 7.2 | 单条崩溃详情面板 | `gui/tab_results.py` | ⬜ |
| 7.3 | 崩溃报文 Hex View + 字段树 | `gui/tab_results.py` | ⬜ |
| 7.4 | 一键重放按钮（调用 Phase 4 重放引擎） | `gui/tab_results.py` | ⬜ |
| 7.5 | 异常聚类视图（相似崩溃自动归并） | `gui/tab_results.py` | ⬜ |
| 7.6 | CVSS 评分（自动计算 + 手动调整） | `gui/widgets/cvss_calculator.py` | ⬜ |
| 7.7 | 崩溃统计仪表盘（按字段分布、按 Layer 分布） | `gui/widgets/dashboard.py` | ⬜ |
| 7.8 | 崩溃用例搜索/过滤 | `gui/tab_results.py` | ⬜ |
| 7.9 | 导出最小化复现脚本 | `gui/tab_results.py` | ⬜ |
| 7.10 | 测试会话历史浏览 | `gui/tab_results.py` | ⬜ |

### 7.B - Tab 5: 报告生成

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 7.11 | 报告模板系统（Jinja2） | `core/reporter.py` | ⬜ |
| 7.12 | HTML 报告模板 | `templates/report.html` | ⬜ |
| 7.13 | PDF 报告模板（WeasyPrint） | `templates/report.html` | ⬜ |
| 7.14 | DOCX 报告生成（python-docx） | `core/reporter.py` | ⬜ |
| 7.15 | 报告章节勾选（执行摘要、统计、崩溃详情、修复建议） | `gui/tab_report.py` | ⬜ |
| 7.16 | 报告时间范围选择 | `gui/tab_report.py` | ⬜ |
| 7.17 | 自定义 Logo / 公司信息 | `gui/tab_report.py` | ⬜ |
| 7.18 | 报告预览面板（嵌入 QWebEngineView） | `gui/tab_report.py` | ⬜ |
| 7.19 | 一键导出按钮 | `gui/tab_report.py` | ⬜ |
| 7.20 | 报告样式（专业商业感） | `templates/styles/report.css` | ⬜ |

---

## 7.3 Tab 4 - 结果分析布局

```
┌──────────────────────────────────────────────────────────────────────┐
│  ┌─[左侧]崩溃列表────┐ ┌─[中央]崩溃详情──────────────────────────┐  │
│  │ 🔍 [搜索______]   │ │ 崩溃 ID: CRASH-2026-0510-001              │  │
│  │ 排序:[严重度▼]    │ │ 时间: 2026-05-10 15:30:45                 │  │
│  │ 过滤:[全部▼]      │ │ 严重度: 🔴 Critical (CVSS 9.1)            │  │
│  │                   │ │ 触发策略: L1-L01_overflow_4byte_max       │  │
│  │ 💥 #001 9.1 ▌    │ │ ────────────────────────────────────────  │  │
│  │   Length溢出      │ │  📋 复现报文（最小化后 1 个）              │  │
│  │ 💥 #002 8.5      │ │  Service ID: 0x1234                       │  │
│  │   状态机异常      │ │  Method ID:  0x5678                       │  │
│  │ ⚠️  #003 6.5      │ │  Length:     0xFFFFFFFF  ⚠ 异常             │  │
│  │   订阅风暴        │ │  Payload:    aa bb cc dd                  │  │
│  │ ...               │ │                                            │  │
│  │                   │ │  📝 字段树 + Hex View                       │  │
│  │ 共 23 个崩溃      │ │ ────────────────────────────────────────  │  │
│  │ Critical:5 High:8 │ │  💉 注入诊断: 触发整数溢出                  │  │
│  │ Med:7 Low:3       │ │  📍 影响: 内存分配失败 / 进程崩溃            │  │
│  └───────────────────┘ │  🔧 修复建议: Length 字段需校验上限          │  │
│                        │                                            │  │
│  ┌─[右侧]统计仪表盘──┐ │  [▶ 重放] [📥 导出脚本] [📋 复制报文]      │  │
│  │ 📊 按 Layer 分布   │ └──────────────────────────────────────────┘  │
│  │ ▌▌▌▌▌▌▌▌  L1: 12 │                                                │
│  │ ▌▌▌▌▌    L2: 7   │                                                │
│  │ ▌▌▌      L3: 4   │                                                │
│  │                   │                                                │
│  │ 🎯 高频字段       │                                                │
│  │ Length:    8 次   │                                                │
│  │ Service ID: 6次   │                                                │
│  │ Payload:   5 次   │                                                │
│  └───────────────────┘                                                │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 7.4 Tab 5 - 报告生成布局

```
┌──────────────────────────────────────────────────────────────────────┐
│  ┌─[左侧]报告配置────┐ ┌─[中央]报告预览（QWebEngineView）─────────┐  │
│  │ 📋 报告类型       │ │                                            │  │
│  │  ⊙ 完整测试报告   │ │  ╔══════════════════════════════════════╗ │  │
│  │  ○ 漏洞披露报告   │ │  ║       SOME/IP 模糊测试报告           ║ │  │
│  │  ○ 执行摘要       │ │  ║       会话: SESS-20260510-001        ║ │  │
│  │                   │ │  ╚══════════════════════════════════════╝ │  │
│  │ 📅 时间范围       │ │                                            │  │
│  │ 起: [2026-05-10] │ │  📊 测试概要                                │  │
│  │ 止: [2026-05-10] │ │  靶机: 192.168.81.128                     │  │
│  │                   │ │  发包: 50,000                             │  │
│  │ ✅ 包含章节       │ │  崩溃: 23                                 │  │
│  │  ☑ 执行摘要       │ │                                            │  │
│  │  ☑ 测试方法       │ │  🎯 崩溃分布（图表）                        │  │
│  │  ☑ 漏洞详情       │ │  [Layer 分布饼图]                          │  │
│  │  ☑ 复现步骤       │ │                                            │  │
│  │  ☑ 修复建议       │ │  💥 崩溃详情                                │  │
│  │  ☑ CVSS 评分       │ │  ## CRASH-001 - Length 整数溢出 (9.1)     │  │
│  │  ☐ 原始数据附录   │ │  ...                                       │  │
│  │                   │ │                                            │  │
│  │ 🎨 自定义         │ │                                            │  │
│  │ Logo:[选择...]    │ │                                            │  │
│  │ 公司:[VehSecLabs] │ │                                            │  │
│  │ 作者:[李奇]       │ │                                            │  │
│  │                   │ │                                            │  │
│  │ 📤 导出格式       │ │                                            │  │
│  │  [📄 PDF]         │ │                                            │  │
│  │  [🌐 HTML]        │ │                                            │  │
│  │  [📝 DOCX]        │ │                                            │  │
│  │                   │ │                                            │  │
│  │ [🔄 刷新预览]    │ │                                            │  │
│  │ [📥 一键导出]    │ │                                            │  │
│  └───────────────────┘ └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 7.5 报告模板结构

### Jinja2 模板片段

```html
<!-- templates/report.html -->
<!DOCTYPE html>
<html>
<head>
  <title>{{ session.title }}</title>
  <link rel="stylesheet" href="styles/report.css">
</head>
<body>
  <header class="cover">
    <img src="{{ logo }}">
    <h1>SOME/IP 模糊测试报告</h1>
    <p>会话编号: {{ session.id }}</p>
    <p>测试日期: {{ session.date }}</p>
  </header>

  <section class="summary">
    <h2>执行摘要</h2>
    <table>
      <tr><th>靶机</th><td>{{ session.target }}</td></tr>
      <tr><th>测试时长</th><td>{{ session.duration }}</td></tr>
      <tr><th>发送报文</th><td>{{ stats.sent }}</td></tr>
      <tr><th>检测崩溃</th><td>{{ stats.crashes }}</td></tr>
      <tr><th>覆盖策略</th><td>{{ stats.strategies }}</td></tr>
    </table>
  </section>

  {% if include_methodology %}
  <section class="methodology">
    <h2>测试方法</h2>
    <p>本次测试采用基于 5 层变异架构的自动化模糊测试...</p>
  </section>
  {% endif %}

  <section class="vulnerabilities">
    <h2>漏洞详情</h2>
    {% for crash in crashes %}
    <div class="vulnerability">
      <h3>{{ crash.id }} - {{ crash.title }} (CVSS {{ crash.cvss }})</h3>
      <p><strong>触发策略:</strong> {{ crash.strategy }}</p>
      <p><strong>影响:</strong> {{ crash.impact }}</p>
      <pre class="hex">{{ crash.packet_hex }}</pre>
      <p><strong>复现步骤:</strong></p>
      <pre class="code">{{ crash.repro_script }}</pre>
      <p><strong>修复建议:</strong> {{ crash.recommendation }}</p>
    </div>
    {% endfor %}
  </section>

  <footer>
    <p>本报告由 VehSecLabs-SomeIP-Fuzzer 自动生成</p>
  </footer>
</body>
</html>
```

---

## 7.6 测试

```python
def test_report_generation_html(tmp_path):
    session = make_test_session(crashes=5)
    reporter = Reporter()
    out = tmp_path / "report.html"
    reporter.generate(session, out, format="html")
    assert out.exists()
    assert "5 个崩溃" in out.read_text()

def test_report_generation_pdf(tmp_path):
    session = make_test_session(crashes=3)
    reporter = Reporter()
    out = tmp_path / "report.pdf"
    reporter.generate(session, out, format="pdf")
    assert out.stat().st_size > 1024  # 至少 1KB

def test_crash_clustering():
    crashes = [crash_a, crash_b, crash_c]  # a/b 相似，c 独立
    clusters = cluster_crashes(crashes)
    assert len(clusters) == 2
```

---

## 7.7 验收清单

- [ ] Tab 4 能列出所有崩溃，按多种方式排序
- [ ] 崩溃详情包含完整字段树、Hex、复现步骤
- [ ] 一键重放按钮可调用 Phase 4 重放引擎成功复现
- [ ] CVSS 自动评分合理，可手动微调
- [ ] 异常聚类能将相似崩溃归并
- [ ] Tab 5 能生成 HTML、PDF、DOCX 三种格式
- [ ] 报告内容完整：摘要、方法、漏洞、复现、修复建议
- [ ] 报告样式专业（适合提交给客户）
- [ ] 自定义 Logo 和公司信息生效
- [ ] 单元测试覆盖率 ≥ 60%
- [ ] git 规范提交、push GitHub

---

## 7.8 问题记录

（验收失败时在此追加）

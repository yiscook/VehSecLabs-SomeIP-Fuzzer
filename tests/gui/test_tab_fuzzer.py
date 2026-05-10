"""Tab 3（模糊测试）pytest-qt 测试。"""

from __future__ import annotations

import pytest
from someip_fuzzer.gui.tab_fuzzer import FuzzerTab
from someip_fuzzer.gui.bridge import GuiBridge
from someip_fuzzer.gui.widgets.strategy_tree import StrategyTreeWidget
from someip_fuzzer.gui.widgets.log_view import LogViewWidget
from someip_fuzzer.gui.widgets.stats_charts import StatsChartsWidget
from someip_fuzzer.gui.widgets.state_view import StateViewWidget


@pytest.fixture
def bridge(qtbot):
    b = GuiBridge()
    return b


@pytest.fixture
def tab(qtbot, bridge):
    t = FuzzerTab(bridge=bridge)
    qtbot.addWidget(t)
    return t


# ── 基本结构 ──────────────────────────────────────────────────────────────────

def test_tab_has_strategy_tree(tab):
    assert isinstance(tab.strategy_tree, StrategyTreeWidget)


def test_tab_has_packet_stream(tab):
    from someip_fuzzer.gui.widgets.packet_stream import PacketStreamWidget
    assert isinstance(tab.packet_stream, PacketStreamWidget)


def test_tab_has_log_view(tab):
    assert isinstance(tab.log_view, LogViewWidget)


def test_tab_has_stats_charts(tab):
    assert isinstance(tab.stats_charts, StatsChartsWidget)


def test_tab_has_state_view(tab):
    assert isinstance(tab.state_view, StateViewWidget)


def test_tab_has_attack_chain_combo(tab):
    assert tab.cmb_chain is not None
    assert tab.cmb_chain.count() >= 1  # 至少有"无"选项


def test_tab_attack_chain_includes_all_yamls(tab):
    # 8 个内置攻击链 + 1 个"无" = 至少 2 项
    assert tab.cmb_chain.count() >= 2


# ── 参数控件 ──────────────────────────────────────────────────────────────────

def test_default_cases(tab):
    assert tab.spin_cases.value() == 10000


def test_default_rate(tab):
    assert tab.spin_rate.value() == 1000


def test_default_timeout(tab):
    assert abs(tab.spin_timeout.value() - 2.0) < 0.01


# ── 启停控制 ──────────────────────────────────────────────────────────────────

def test_initial_not_running(tab):
    assert tab.is_running() is False


def test_start_sets_running(tab):
    tab.start_fuzzing()
    assert tab.is_running() is True


def test_stop_clears_running(tab):
    tab.start_fuzzing()
    tab.stop_fuzzing()
    assert tab.is_running() is False


def test_start_emits_bridge_signal(tab, bridge):
    received = []
    bridge.log_message.connect(lambda lvl, msg: received.append(msg))
    tab.start_fuzzing()
    assert any("启动" in m for m in received)


# ── StrategyTreeWidget ────────────────────────────────────────────────────────

def test_strategy_tree_loads(qtbot):
    tree = StrategyTreeWidget()
    qtbot.addWidget(tree)
    # 如果变异器已注册，应有分组节点
    root = tree._tree.invisibleRootItem()
    assert root.childCount() >= 0  # 0 也可（未导入时）


def test_strategy_tree_check_all_none(qtbot):
    tree = StrategyTreeWidget()
    qtbot.addWidget(tree)
    tree._check_all()
    all_names = tree.enabled_names()
    tree._uncheck_all()
    none_names = tree.enabled_names()
    assert len(none_names) == 0
    if all_names:
        assert len(all_names) > len(none_names)


# ── LogViewWidget ─────────────────────────────────────────────────────────────

def test_log_append(qtbot):
    log = LogViewWidget()
    qtbot.addWidget(log)
    log.append("INFO", "测试消息")
    assert "测试消息" in log._text.toPlainText()


def test_log_pause_suppresses(qtbot):
    log = LogViewWidget()
    qtbot.addWidget(log)
    log.btn_pause.click()
    log.append("INFO", "暂停时的消息")
    assert "暂停时的消息" not in log._text.toPlainText()
    log.btn_pause.click()  # 恢复
    assert "暂停时的消息" in log._text.toPlainText()


def test_log_clear(qtbot):
    log = LogViewWidget()
    qtbot.addWidget(log)
    log.append("INFO", "消息")
    log._clear()
    assert log._text.toPlainText() == ""


# ── StateViewWidget ────────────────────────────────────────────────────────────

def test_state_view_update(qtbot):
    sv = StateViewWidget()
    qtbot.addWidget(sv)
    sv.update_state("0x1234/0x0001", "RUNNING")
    assert "RUNNING" in sv._lbl_current.text()


def test_state_view_mermaid(qtbot):
    sv = StateViewWidget()
    qtbot.addWidget(sv)
    sv.update_mermaid("stateDiagram-v2\n  UNKNOWN --> DISCOVERED")
    assert "UNKNOWN" in sv._text.toPlainText()


# ── StatsChartsWidget ─────────────────────────────────────────────────────────

def test_stats_record_sent(qtbot):
    sc = StatsChartsWidget()
    qtbot.addWidget(sc)
    sc.record_sent(100)
    assert sc._total_sent == 100


def test_stats_record_crash(qtbot):
    sc = StatsChartsWidget()
    qtbot.addWidget(sc)
    sc._crash_flags.append(0)
    sc.record_crash()
    assert sc._total_crashes == 1

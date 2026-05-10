"""Tab 4（结果分析）pytest-qt 测试。"""

from __future__ import annotations

import pytest
from someip_fuzzer.data.crash_store import CrashRecord, CrashStorage
from someip_fuzzer.gui.tab_results import ResultsTab
from someip_fuzzer.gui.widgets.crash_list import CrashListModel, CrashListWidget
from someip_fuzzer.gui.widgets.cvss_calculator import CvssCalculatorWidget, compute_cvss31
from someip_fuzzer.gui.widgets.dashboard import DashboardWidget


_counter = 0

def make_crash(severity="high", mutator="L1-S01.boundary_min", cvss=7.5) -> CrashRecord:
    global _counter
    _counter += 1
    return CrashRecord(
        triggering_bytes=b"\x12\x34\x00\x01" + _counter.to_bytes(4, "big") + b"\x00" * 8,
        mutator_name=mutator,
        severity=severity,
        cvss_score=cvss,
        detection_method="heartbeat",
        target_addr=("192.168.81.128", 30509),
    )


@pytest.fixture
def store():
    s = CrashStorage(":memory:")
    s.save(make_crash("critical", "L1-L01.overflow", 9.1))
    s.save(make_crash("high", "L2-S01.utf8_overlong", 7.5))
    s.save(make_crash("medium", "L1-S02.boundary_max", 5.0))
    s.save(make_crash("low", "L3-SM01.invalid_state", 2.5))
    return s


@pytest.fixture
def tab(qtbot, store):
    t = ResultsTab()
    t._store = store
    t.refresh()
    qtbot.addWidget(t)
    return t


# ── CrashListModel ────────────────────────────────────────────────────────────

def test_model_load():
    m = CrashListModel()
    crashes = [make_crash() for _ in range(5)]
    m.load(crashes)
    assert m.rowCount() == 5


def test_model_get_record():
    m = CrashListModel()
    crashes = [make_crash(severity="critical")]
    m.load(crashes)
    rec = m.get_record(0)
    assert rec is not None
    assert rec.severity == "critical"


def test_model_sort_by_cvss():
    from PyQt6.QtCore import Qt
    m = CrashListModel()
    crashes = [
        make_crash(cvss=9.1), make_crash(cvss=5.0), make_crash(cvss=7.5)
    ]
    m.load(crashes)
    m.sort(4, Qt.SortOrder.DescendingOrder)
    assert m.get_record(0).cvss_score == 9.1


def test_model_sort_by_severity():
    from PyQt6.QtCore import Qt
    m = CrashListModel()
    crashes = [
        make_crash(severity="low"), make_crash(severity="critical"), make_crash(severity="medium")
    ]
    m.load(crashes)
    m.sort(2)  # 严重度列
    assert m.get_record(0).severity == "critical"


def test_model_background_critical():
    from PyQt6.QtCore import Qt
    m = CrashListModel()
    m.load([make_crash(severity="critical")])
    idx = m.index(0, 0)
    color = m.data(idx, Qt.ItemDataRole.BackgroundRole)
    assert color is not None


def test_model_empty():
    m = CrashListModel()
    assert m.rowCount() == 0
    assert m.get_record(0) is None


# ── CrashListWidget ───────────────────────────────────────────────────────────

def test_widget_load(qtbot):
    w = CrashListWidget()
    qtbot.addWidget(w)
    crashes = [make_crash() for _ in range(3)]
    w.load(crashes)
    assert w.model.rowCount() == 3


def test_widget_signal(qtbot):
    w = CrashListWidget()
    qtbot.addWidget(w)
    received = []
    w.crash_selected.connect(received.append)
    w.load([make_crash(severity="high")])
    w.table.selectRow(0)
    assert len(received) == 1
    assert received[0].severity == "high"


# ── CvssCalculatorWidget ──────────────────────────────────────────────────────

def test_cvss_calculator_initial(qtbot):
    w = CvssCalculatorWidget()
    qtbot.addWidget(w)
    score = w.get_score()
    assert 0.0 <= score <= 10.0


def test_cvss_vector_string(qtbot):
    w = CvssCalculatorWidget()
    qtbot.addWidget(w)
    vec = w.get_vector_string()
    assert "CVSS:3.1" in vec


def test_cvss_set_score_from_record_critical(qtbot):
    w = CvssCalculatorWidget()
    qtbot.addWidget(w)
    w.set_score_from_record(9.5)
    score = w.get_score()
    assert score >= 9.0


def test_cvss_compute_known():
    # 已知向量：AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
    score = compute_cvss31(
        "Network (N)", "Low (L)", "None (N)", "None (N)",
        "Unchanged (U)", "High (H)", "High (H)", "High (H)"
    )
    assert 9.0 <= score <= 10.0


def test_cvss_compute_low():
    score = compute_cvss31(
        "Physical (P)", "High (H)", "High (H)", "Required (R)",
        "Unchanged (U)", "None (N)", "None (N)", "Low (L)"
    )
    assert score <= 3.0


# ── DashboardWidget ───────────────────────────────────────────────────────────

def test_dashboard_refresh_empty(qtbot):
    d = DashboardWidget()
    qtbot.addWidget(d)
    d.refresh([])  # 不应崩溃


def test_dashboard_refresh_with_crashes(qtbot):
    d = DashboardWidget()
    qtbot.addWidget(d)
    crashes = [make_crash("critical", "L1-L01.overflow", 9.1),
               make_crash("high",     "L2-S01.utf8",    7.5),
               make_crash("medium",   "L1-S02.max",     5.0)]
    d.refresh(crashes)
    assert "3" in d.lbl_summary.text()


# ── ResultsTab ────────────────────────────────────────────────────────────────

def test_results_tab_has_crash_list(tab):
    assert tab.crash_list is not None


def test_results_tab_has_hex_view(tab):
    assert tab.hex_view is not None


def test_results_tab_has_tree(tab):
    assert tab.packet_tree is not None


def test_results_tab_has_cvss_calc(tab):
    assert tab.cvss_calc is not None


def test_results_tab_refresh_loads_data(tab):
    tab.refresh()
    assert tab.crash_list.model.rowCount() >= 4


def test_results_tab_filter_by_severity(tab):
    tab.cmb_severity.setCurrentText("critical")
    assert tab.crash_list.model.rowCount() == 1


def test_results_tab_filter_keyword(tab):
    tab.edit_search.setText("L1")
    rows = tab.crash_list.model.rowCount()
    assert rows >= 1


def test_results_tab_select_crash(tab, qtbot):
    tab.refresh()
    if tab.crash_list.model.rowCount() > 0:
        tab.crash_list.table.selectRow(0)
        assert tab._current_crash is not None
        assert tab.hex_view._raw != b""

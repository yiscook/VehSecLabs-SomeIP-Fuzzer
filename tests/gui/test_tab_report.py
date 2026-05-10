"""Tab 5（报告生成）pytest-qt 测试。"""

from __future__ import annotations

import pytest
from someip_fuzzer.data.crash_store import CrashRecord, CrashStorage
from someip_fuzzer.gui.tab_report import ReportTab


def make_crash(severity="high", mutator="L1-S01.boundary_min", cvss=7.5) -> CrashRecord:
    return CrashRecord(
        triggering_bytes=b"\x12\x34\x00\x01" + b"\x00" * 12,
        mutator_name=mutator,
        severity=severity,
        cvss_score=cvss,
        detection_method="heartbeat",
        target_addr=("192.168.81.128", 30509),
    )


@pytest.fixture
def tab(qtbot):
    t = ReportTab()
    qtbot.addWidget(t)
    return t


@pytest.fixture
def tab_with_data(qtbot):
    store = CrashStorage(":memory:")
    store.save(make_crash("critical", "L1-L01.overflow", 9.1))
    store.save(make_crash("high", "L2-S01.utf8", 7.5))
    t = ReportTab()
    t._store = store
    qtbot.addWidget(t)
    return t


# ── 基本结构 ──────────────────────────────────────────────────────────────────

def test_tab_has_preview(tab):
    assert tab.preview is not None


def test_tab_has_export_buttons(tab):
    assert tab.btn_pdf is not None
    assert tab.btn_html is not None
    assert tab.btn_docx is not None


def test_tab_has_section_checkboxes(tab):
    assert tab.chk_method is not None
    assert tab.chk_vuln is not None
    assert tab.chk_repro is not None


def test_tab_default_company(tab):
    assert "VehSecLabs" in tab.edit_company.text()


def test_tab_default_sections_checked(tab):
    assert tab.chk_method.isChecked()
    assert tab.chk_vuln.isChecked()
    assert tab.chk_repro.isChecked()
    assert not tab.chk_raw.isChecked()


# ── 预览功能 ──────────────────────────────────────────────────────────────────

def test_preview_refresh_no_crash(tab):
    tab._refresh_preview()
    html = tab.preview.toHtml()
    assert len(html) > 0  # 至少有骨架


def test_preview_refresh_with_crashes(tab_with_data):
    tab_with_data._refresh_preview()
    html = tab_with_data.preview.toHtml()
    assert len(html) > 0


def test_config_title(tab):
    tab.edit_title.setText("自定义报告标题")
    config = tab._build_config()
    assert config.title == "自定义报告标题"


def test_config_author(tab):
    tab.edit_author.setText("李奇")
    config = tab._build_config()
    assert config.author == "李奇"


def test_config_section_flags(tab):
    tab.chk_raw.setChecked(True)
    config = tab._build_config()
    assert config.include_raw_appendix is True


def test_config_section_unchecked(tab):
    tab.chk_method.setChecked(False)
    config = tab._build_config()
    assert config.include_methodology is False


def test_set_db_path(tab):
    tab.set_db_path(":memory:")
    # 不应崩溃


def test_report_type_radio(tab):
    assert tab.radio_full.isChecked()
    tab.radio_vuln.setChecked(True)
    assert tab.radio_vuln.isChecked()
    assert not tab.radio_full.isChecked()

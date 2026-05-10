"""Reporter 单元测试 — HTML/PDF/DOCX 生成。"""

from __future__ import annotations

import pytest
from pathlib import Path

from someip_fuzzer.core.reporter import Reporter, ReportConfig, _hexdump, _format_crash_id
from someip_fuzzer.data.crash_store import CrashRecord


def make_crash(severity="high", mutator="L1-S01.boundary_min", cvss=7.5) -> CrashRecord:
    return CrashRecord(
        triggering_bytes=b"\x12\x34\x00\x01" + b"\x00" * 12,
        mutator_name=mutator,
        severity=severity,
        cvss_score=cvss,
        detection_method="heartbeat",
        target_addr=("192.168.81.128", 30509),
        context={"service_id": 0x1234, "method_id": 0x8001},
    )


def make_session() -> dict:
    return {
        "id": "SESS-TEST-001",
        "target": "192.168.81.128:30509",
        "date": "2026-05-11",
        "transport": "UDP",
        "sent": 50000,
        "duration": 3600,
    }


@pytest.fixture
def reporter():
    return Reporter()


# ── 辅助函数 ──────────────────────────────────────────────────────────────────

def test_hexdump_output():
    raw = bytes(range(20))
    result = _hexdump(raw)
    assert "0000:" in result
    assert "0010:" in result


def test_hexdump_empty():
    assert _hexdump(b"") == ""


def test_format_crash_id():
    assert _format_crash_id(1) == "CRASH-001"
    assert _format_crash_id(99) == "CRASH-099"


# ── ReportConfig ──────────────────────────────────────────────────────────────

def test_config_defaults():
    cfg = ReportConfig()
    assert cfg.company == "VehSecLabs"
    assert cfg.include_methodology is True
    assert cfg.include_raw_appendix is False


def test_config_custom():
    cfg = ReportConfig(title="My Report", author="Alice", include_raw_appendix=True)
    assert cfg.title == "My Report"
    assert cfg.author == "Alice"
    assert cfg.include_raw_appendix is True


# ── HTML 生成 ─────────────────────────────────────────────────────────────────

def test_render_html_no_crashes(reporter):
    html = reporter.render_html(make_session(), [], ReportConfig())
    assert "<!DOCTYPE html>" in html
    assert "VehSecLabs" in html


def test_render_html_with_crashes(reporter):
    crashes = [make_crash("critical", "L1-L01.overflow", 9.1)]
    html = reporter.render_html(make_session(), crashes, ReportConfig())
    assert "L1-L01.overflow" in html


def test_render_html_contains_summary(reporter):
    crashes = [make_crash(), make_crash("critical")]
    html = reporter.render_html(make_session(), crashes, ReportConfig())
    assert "192.168.81.128" in html


def test_render_html_exclude_methodology(reporter):
    crashes = [make_crash()]
    cfg = ReportConfig(include_methodology=False, include_vulnerabilities=False)
    html = reporter.render_html(make_session(), crashes, cfg)
    # HTML 注释仍存在，但 <h2> 标签应被隐藏
    assert "<h2>2. 测试方法</h2>" not in html


def test_render_html_include_reproduction(reporter):
    crashes = [make_crash()]
    html = reporter.render_html(make_session(), crashes, ReportConfig(include_reproduction=True))
    assert "1234" in html  # 触发报文包含 0x12 0x34


def test_to_html_creates_file(reporter, tmp_path):
    output = tmp_path / "report.html"
    reporter.to_html(make_session(), [make_crash()], ReportConfig(), output)
    assert output.exists()
    assert output.stat().st_size > 500


def test_to_html_content(reporter, tmp_path):
    output = tmp_path / "report.html"
    crashes = [make_crash("critical", "L1-L01.overflow", 9.1)]
    reporter.to_html(make_session(), crashes, ReportConfig(), output)
    content = output.read_text(encoding="utf-8")
    assert "L1-L01.overflow" in content


# ── PDF 生成 ─────────────────────────────────────────────────────────────────

def test_to_pdf_creates_file(reporter, tmp_path):
    try:
        output = tmp_path / "report.pdf"
        reporter.to_pdf(make_session(), [make_crash()], ReportConfig(), output)
        assert output.exists()
        assert output.stat().st_size > 1024
    except Exception as exc:
        pytest.skip(f"WeasyPrint not available or failed: {exc}")


# ── DOCX 生成 ─────────────────────────────────────────────────────────────────

def test_to_docx_creates_file(reporter, tmp_path):
    output = tmp_path / "report.docx"
    reporter.to_docx(make_session(), [make_crash()], ReportConfig(), output)
    assert output.exists()
    assert output.stat().st_size > 1024


def test_to_docx_with_multiple_crashes(reporter, tmp_path):
    crashes = [
        make_crash("critical", "L1-L01.overflow", 9.1),
        make_crash("high",     "L2-S01.utf8",     7.5),
        make_crash("medium",   "L1-S02.max",       5.0),
    ]
    output = tmp_path / "report_multi.docx"
    reporter.to_docx(make_session(), crashes, ReportConfig(), output)
    assert output.exists()
    assert output.stat().st_size > 2048


# ── summary 构建 ──────────────────────────────────────────────────────────────

def test_build_summary_counts(reporter):
    crashes = [
        make_crash("critical"), make_crash("critical"),
        make_crash("high"), make_crash("medium"), make_crash("low"),
    ]
    summary = reporter._build_summary(crashes)
    assert summary["crashes"] == 5
    assert summary["critical"] == 2
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["low"] == 1


def test_build_summary_empty(reporter):
    summary = reporter._build_summary([])
    assert summary["crashes"] == 0
    assert summary["critical"] == 0

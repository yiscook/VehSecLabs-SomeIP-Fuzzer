"""高性能报文流核心测试 — PacketStreamModel / BatchedUpdater / PacketStreamWidget。"""

from __future__ import annotations

import time

import pytest
from PyQt6.QtCore import QCoreApplication

from someip_fuzzer.gui.widgets.packet_stream import (
    BatchedUpdater,
    PacketStatus,
    PacketStreamModel,
    PacketStreamWidget,
    StreamRow,
)


# ── PacketStreamModel ─────────────────────────────────────────────────────────

def test_model_initially_empty():
    m = PacketStreamModel()
    assert m.rowCount() == 0
    assert m.total == 0


def test_model_append_batch():
    m = PacketStreamModel()
    rows = [m.make_row(PacketStatus.SENT, 0x1234, 0x8001, 16) for _ in range(50)]
    m.append_batch(rows)
    assert m.rowCount() == 50
    assert m.total == 50


def test_model_ring_buffer():
    m = PacketStreamModel(capacity=10)
    rows = [m.make_row(PacketStatus.SENT, 0, 0, 0) for _ in range(25)]
    m.append_batch(rows)
    assert m.rowCount() == 10  # 环形缓冲，只保留最新 10 条


def test_model_clear():
    m = PacketStreamModel()
    m.append_batch([m.make_row(PacketStatus.SENT, 0, 0, 0) for _ in range(5)])
    m.clear()
    assert m.rowCount() == 0


def test_model_get_row():
    m = PacketStreamModel()
    row = m.make_row(PacketStatus.CRASH, 0xABCD, 0x1234, 42)
    m.append_batch([row])
    r = m.get_row(0)
    assert r is not None
    assert r.service_id == 0xABCD
    assert r.status == PacketStatus.CRASH


def test_model_data_display():
    from PyQt6.QtCore import Qt
    m = PacketStreamModel()
    row = m.make_row(PacketStatus.OK, 0x1234, 0x8001, 32)
    m.append_batch([row])
    idx = m.index(0, 2)  # 方向列
    val = m.data(idx, Qt.ItemDataRole.DisplayRole)
    assert val == PacketStatus.OK.value


def test_model_background_color():
    from PyQt6.QtCore import Qt
    m = PacketStreamModel()
    row = m.make_row(PacketStatus.CRASH, 0, 0, 0)
    m.append_batch([row])
    idx = m.index(0, 0)
    color = m.data(idx, Qt.ItemDataRole.BackgroundRole)
    assert color is not None  # 崩溃行有背景色


def test_model_sequential_nos():
    m = PacketStreamModel()
    rows = [m.make_row(PacketStatus.SENT, 0, 0, 0) for _ in range(5)]
    m.append_batch(rows)
    nos = [m.get_row(i).no for i in range(5)]
    assert nos == list(range(1, 6))


# ── 性能测试 —— 10000 条 < 1s ─────────────────────────────────────────────────

def test_high_load_performance():
    """10000 条批量添加应在 1 秒内完成。"""
    m = PacketStreamModel(capacity=10000)
    rows = [m.make_row(PacketStatus.SENT, 0x1234, 0x8001, 16) for _ in range(10000)]
    t0 = time.monotonic()
    m.append_batch(rows)
    elapsed = time.monotonic() - t0
    assert elapsed < 1.0, f"10000 条插入耗时 {elapsed:.3f}s > 1s"


# ── PacketStreamWidget ────────────────────────────────────────────────────────

@pytest.fixture
def stream_widget(qtbot):
    w = PacketStreamWidget()
    qtbot.addWidget(w)
    return w


def test_stream_widget_initial_not_paused(stream_widget):
    assert stream_widget.is_paused() is False


def test_stream_widget_pause_toggle(stream_widget):
    stream_widget.btn_pause.click()
    assert stream_widget.is_paused() is True
    stream_widget.btn_pause.click()
    assert stream_widget.is_paused() is False


def test_stream_widget_add_sent(stream_widget, qtbot):
    stream_widget.add_sent(0x1234, 0x8001, 16)
    # BatchedUpdater 需要 100ms timer，手动 flush
    stream_widget._updater.flush()
    assert stream_widget._model.rowCount() == 1


def test_stream_widget_add_crash_bypasses_pause(stream_widget, qtbot):
    """暂停时崩溃报文仍应被添加。"""
    stream_widget.btn_pause.click()  # 暂停
    assert stream_widget.is_paused()
    stream_widget.add_crash(0x1234, 0x8001, 16)
    assert stream_widget._model.rowCount() == 1


def test_stream_widget_pause_suppresses_sent(stream_widget):
    stream_widget.btn_pause.click()
    stream_widget.add_sent(0x1234, 0x8001, 16)
    stream_widget._updater.flush()
    assert stream_widget._model.rowCount() == 0


def test_stream_widget_clear(stream_widget):
    stream_widget.add_sent(0x1234, 0x8001, 16)
    stream_widget.clear()
    assert stream_widget._model.rowCount() == 0


# ── BatchedUpdater ────────────────────────────────────────────────────────────

def test_batched_updater_flush(qtbot):
    m = PacketStreamModel()
    updater = BatchedUpdater(m, interval_ms=500)
    rows = [m.make_row(PacketStatus.SENT, 0, 0, 0) for _ in range(20)]
    for r in rows:
        updater.add(r)
    assert m.rowCount() == 0  # timer 未触发前不刷新
    updater.flush()
    assert m.rowCount() == 20
    updater.stop()

"""Tab 2（协议分析）pytest-qt 测试。"""

from __future__ import annotations

import pytest
from someip_fuzzer.core.protocol import SomeIpPacket, MessageType, ReturnCode
from someip_fuzzer.gui.tab_analysis import AnalysisTab
from someip_fuzzer.gui.widgets.packet_table import PacketTableModel, PacketRow
from someip_fuzzer.gui.widgets.packet_tree import PacketTreeWidget
from someip_fuzzer.gui.widgets.hex_view import HexView


def make_packet(srv=0x1234, meth=0x8001) -> SomeIpPacket:
    return SomeIpPacket(service_id=srv, method_id=meth, payload=b"\xAA\xBB\xCC")


@pytest.fixture
def tab(qtbot):
    t = AnalysisTab()
    qtbot.addWidget(t)
    return t


# ── PacketTableModel ──────────────────────────────────────────────────────────

def test_model_initially_empty():
    model = PacketTableModel()
    assert model.rowCount() == 0


def test_model_add_packet():
    model = PacketTableModel()
    pkt = make_packet()
    model.add_packet(pkt, "→")
    assert model.rowCount() == 1


def test_model_add_batch():
    model = PacketTableModel()
    pkt = make_packet()
    rows = [model.make_row_obj(pkt, "→") if hasattr(model, "make_row_obj") else
            PacketRow(no=i, timestamp=0.0, direction="→", service_id=0x1234,
                      method_id=0x8001, length=16, msg_type="REQUEST", raw=pkt.to_bytes())
            for i in range(10)]
    model.append_batch(rows)
    assert model.rowCount() == 10


def test_model_capacity_ring_buffer():
    model = PacketTableModel(capacity=5)
    pkt = make_packet()
    for _ in range(10):
        model.add_packet(pkt)
    assert model.rowCount() == 5  # 环形缓冲限制


def test_model_get_row():
    model = PacketTableModel()
    pkt = make_packet()
    model.add_packet(pkt, "→")
    row = model.get_row(0)
    assert row is not None
    assert row.service_id == 0x1234


def test_model_clear():
    model = PacketTableModel()
    pkt = make_packet()
    model.add_packet(pkt)
    model.clear()
    assert model.rowCount() == 0


def test_model_data_display():
    from PyQt6.QtCore import QModelIndex, Qt
    model = PacketTableModel()
    pkt = make_packet()
    model.add_packet(pkt, "→")
    idx = model.index(0, 2)  # 方向列
    assert model.data(idx, Qt.ItemDataRole.DisplayRole) == "→"


# ── PacketTreeWidget ─────────────────────────────────────────────────────────

def test_tree_show_row(qtbot):
    tree = PacketTreeWidget()
    qtbot.addWidget(tree)
    pkt = make_packet()
    raw = pkt.to_bytes()
    row = PacketRow(no=1, timestamp=0.0, direction="→", service_id=0x1234,
                    method_id=0x8001, length=len(raw), msg_type="REQUEST", raw=raw)
    tree.show_row(row)
    assert tree.topLevelItemCount() >= 1


def test_tree_show_empty_raw(qtbot):
    tree = PacketTreeWidget()
    qtbot.addWidget(tree)
    row = PacketRow(no=1, timestamp=0.0, direction="→", service_id=0,
                    method_id=0, length=0, msg_type="", raw=b"")
    tree.show_row(row)  # 不应崩溃


# ── HexView ───────────────────────────────────────────────────────────────────

def test_hex_view_load(qtbot):
    hv = HexView()
    qtbot.addWidget(hv)
    pkt = make_packet()
    hv.load(pkt.to_bytes())
    assert hv._raw == pkt.to_bytes()


def test_hex_view_highlight(qtbot):
    hv = HexView()
    qtbot.addWidget(hv)
    hv.load(b"\x12\x34\x00\x50" + b"\x00" * 12)
    hv.highlight(0, 2)  # 不应抛异常


def test_hex_view_empty(qtbot):
    hv = HexView()
    qtbot.addWidget(hv)
    hv.load(b"")
    hv.highlight(0, 4)  # 空数据不应崩溃


# ── AnalysisTab ───────────────────────────────────────────────────────────────

def test_tab_has_table(tab):
    assert tab.table_view is not None


def test_tab_has_tree(tab):
    assert tab.packet_tree is not None


def test_tab_has_hex(tab):
    assert tab.hex_view is not None


def test_tab_add_packet(tab):
    pkt = make_packet()
    tab.add_packet(pkt, direction="→")
    assert tab._model.rowCount() == 1


def test_tab_add_multiple_packets(tab):
    for i in range(20):
        tab.add_packet(make_packet(srv=i, meth=i))
    assert tab._model.rowCount() == 20


def test_tab_clear(tab):
    tab.add_packet(make_packet())
    tab._clear()
    assert tab._model.rowCount() == 0


def test_tab_count_label_updates(tab):
    tab.add_packet(make_packet())
    assert "1" in tab.lbl_count.text()


def test_tab_add_raw(tab):
    raw = b"\x12\x34\x00\x01" + b"\x00" * 12
    tab.add_raw_bytes(raw)
    assert tab._model.rowCount() == 1

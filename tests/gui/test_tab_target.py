"""Tab 1（目标配置）pytest-qt 测试。"""

from __future__ import annotations

import pytest
from pathlib import Path

from someip_fuzzer.gui.tab_target import TargetTab
from someip_fuzzer.utils.config import AppConfig, ServiceDef, SdConfig, TargetConfig


@pytest.fixture
def tab(qtbot):
    t = TargetTab()
    qtbot.addWidget(t)
    return t


# ── 默认值 ────────────────────────────────────────────────────────────────────

def test_default_ip(tab):
    assert tab.cmb_ip.currentText() == "192.168.81.128"


def test_default_port(tab):
    assert tab.spin_port.value() == 30509


def test_default_udp_selected(tab):
    assert tab.radio_udp.isChecked()


def test_default_sd_multicast(tab):
    assert tab.edit_sd_mc.text() == "224.224.224.245"


def test_default_sd_port(tab):
    assert tab.spin_sd_port.value() == 30490


# ── load_config_obj / build_config_obj 往返 ───────────────────────────────────

def test_load_and_build_roundtrip(tab):
    cfg_in = AppConfig(
        target=TargetConfig(name="test", ip="10.0.0.1", port=12345, transport="tcp", interface=""),
        sd=SdConfig(multicast="239.0.0.1", port=9999),
        services=[
            ServiceDef(service_id=0xABCD, instance_id=0x0002, major_version=2, minor_version=1,
                       methods=[0x1001], events=[0x2001]),
        ],
    )
    tab.load_config_obj(cfg_in)

    cfg_out = tab.build_config_obj()
    assert cfg_out.target.ip == "10.0.0.1"
    assert cfg_out.target.port == 12345
    assert cfg_out.target.transport == "tcp"
    assert cfg_out.sd.multicast == "239.0.0.1"
    assert cfg_out.sd.port == 9999
    assert len(cfg_out.services) == 1
    assert cfg_out.services[0].service_id == 0xABCD
    assert cfg_out.services[0].methods == [0x1001]


def test_load_udp_protocol(tab):
    cfg = AppConfig(target=TargetConfig(transport="udp"))
    tab.load_config_obj(cfg)
    assert tab.radio_udp.isChecked()


def test_load_tcp_protocol(tab):
    cfg = AppConfig(target=TargetConfig(transport="tcp"))
    tab.load_config_obj(cfg)
    assert tab.radio_tcp.isChecked()


# ── 表格增删行 ────────────────────────────────────────────────────────────────

def test_add_service_row(tab):
    initial = tab.tbl_services.rowCount()
    tab.btn_add_row.click()
    assert tab.tbl_services.rowCount() == initial + 1


def test_del_service_row(tab):
    tab.btn_add_row.click()
    tab.btn_add_row.click()
    assert tab.tbl_services.rowCount() == 2
    tab.tbl_services.selectRow(0)
    tab.btn_del_row.click()
    assert tab.tbl_services.rowCount() == 1


def test_empty_table_no_crash(tab):
    tab.tbl_services.setRowCount(0)
    cfg = tab.build_config_obj()
    assert cfg.services == []


# ── TOML 导入导出 ────────────────────────────────────────────────────────────

def test_save_load_toml(tab, tmp_path):
    tab.cmb_ip.setCurrentText("172.16.0.1")
    tab.spin_port.setValue(55555)
    path = tmp_path / "test_config.toml"
    tab.save_config(path)
    assert path.exists()

    tab.cmb_ip.setCurrentText("0.0.0.0")
    tab.spin_port.setValue(1)
    tab.load_config(path)

    assert tab.cmb_ip.currentText() == "172.16.0.1"
    assert tab.spin_port.value() == 55555


def test_save_config_updates_path_label(tab, tmp_path):
    path = tmp_path / "cfg.toml"
    tab.save_config(path)
    assert str(path) in tab.lbl_current_path.text()


# ── 网卡列表非空 ──────────────────────────────────────────────────────────────

def test_network_interfaces_loaded(tab):
    # 至少有第一个空选项
    assert tab.cmb_iface.count() >= 1


# ── 模板切换 ──────────────────────────────────────────────────────────────────

def test_template_vsomeip_default(tab):
    tab.cmb_template.setCurrentText("vsomeip 默认")
    assert tab.cmb_ip.currentText() == "192.168.81.128"


def test_template_empty(tab):
    tab.cmb_template.setCurrentText("空模板")
    cfg = tab.build_config_obj()
    assert cfg.services == []

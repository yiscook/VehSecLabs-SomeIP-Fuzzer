"""E2E 测试公共 fixtures。

所有 E2E 测试需要 VM（192.168.81.129）在线，
VM 不可达时整个目录自动跳过。
"""

from __future__ import annotations

import socket
import urllib.request

import pytest

VM_IP = "192.168.81.129"
VM_PORT = 30509
AGENT_URL = f"http://{VM_IP}:9999"
SD_MULTICAST = "224.224.224.245"
SD_PORT = 30490

# scapy 在 Windows 上需要指定网卡；动态查找含 VM_IP 的接口
def _find_vmnet8_iface() -> str | None:
    try:
        from scapy.all import IFACES
        for name, iface in IFACES.items():
            if getattr(iface, "ip", "") == "192.168.81.1":
                return name
    except Exception:
        pass
    return None

VMNET8_IFACE = _find_vmnet8_iface()


@pytest.fixture(scope="session", autouse=True)
def require_vm() -> None:
    """Session 级别：VM 不可达则跳过全部 E2E 测试。"""
    try:
        urllib.request.urlopen(AGENT_URL + "/status", timeout=3)
    except Exception as exc:
        pytest.skip(f"VM 不可达（{AGENT_URL}），跳过 E2E：{exc}")

"""E2E 8.7 — 连通性测试。

验证：
1. Agent HTTP /status 接口可达且 alive=true
2. UDP 30509 端口可到达（无 OSError）
3. SD 多播 30490 可收到 OfferService（Service 0x1111）
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import urllib.request

import pytest

from tests.e2e.conftest import AGENT_URL, SD_MULTICAST, SD_PORT, VM_IP, VM_PORT, VMNET8_IFACE


def test_agent_alive() -> None:
    """Agent /status 返回 alive=true，pid > 0。"""
    raw = urllib.request.urlopen(AGENT_URL + "/status", timeout=3).read()
    status = json.loads(raw)
    assert status.get("alive") is True, f"agent 报告 alive=false：{status}"
    assert status.get("pid", 0) > 0, f"pid 异常：{status}"


def test_udp_reachable() -> None:
    """向 30509/UDP 发 16 字节探针，无 OSError 即视为端口可达。"""
    probe = (
        b"\x11\x11\x33\x33"  # Service 0x1111, Method 0x3333
        b"\x00\x00\x00\x08"  # Length = 8
        b"\x00\x00\x00\x01"  # Client 0, Session 1
        b"\x01\x01\x02\x00"  # PVer=1, IVer=1, MsgType=REQUEST, RC=E_OK
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        sock.sendto(probe, (VM_IP, VM_PORT))
    finally:
        sock.close()
    # UDP 无连接，sendto 不抛 OSError 即视为可达


def test_sd_offer_received() -> None:
    """用 scapy 嗅探 SD 多播（绕过 Windows TCP/IP 栈），5 秒内收到 OfferService。

    普通 socket 在 VMware 虚拟网卡上收不到多播（VMnet 限制），
    但 scapy/Npcap 可从驱动层捕获，与 Wireshark 同一层。
    """
    try:
        from scapy.all import AsyncSniffer, UDP, IP, Raw
    except ImportError:
        pytest.skip("scapy 未安装，跳过 SD 多播嗅探测试")

    found: list[bool] = [False]

    def _check(pkt) -> None:
        if IP not in pkt or UDP not in pkt:
            return
        if pkt[IP].src != VM_IP:
            return
        if pkt[UDP].dport != SD_PORT:
            return
        data = bytes(pkt[UDP].payload)
        if len(data) < 28:
            return
        # SOME/IP-SD: Service=0xFFFF, Method=0x8100
        if data[0:4] != b"\xff\xff\x81\x00":
            return
        entries_len = struct.unpack_from(">I", data, 20)[0]
        if entries_len < 16:
            return
        entry = data[24:24 + 16]
        entry_type = entry[0]
        svc_id = struct.unpack_from(">H", entry, 4)[0]
        if entry_type == 0x01 and svc_id == 0x1111:
            found[0] = True

    sniff_kwargs: dict = {"filter": f"udp port {SD_PORT}", "prn": _check,
                          "store": False, "timeout": 6}
    if VMNET8_IFACE:
        sniff_kwargs["iface"] = VMNET8_IFACE
    sniffer = AsyncSniffer(**sniff_kwargs)
    sniffer.start()
    sniffer.join(timeout=7)

    assert found[0], (
        f"6 秒内未通过 scapy/Npcap 嗅探到来自 {VM_IP} 的 OfferService（Service 0x1111）。\n"
        "请确认 Npcap 已安装，且以管理员权限运行测试。"
    )

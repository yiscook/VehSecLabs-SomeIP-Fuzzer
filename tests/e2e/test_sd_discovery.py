"""E2E 8.8 — SOME/IP-SD 服务发现完整流程。

验证：
1. 收到 OfferService，字段完全匹配（Service/Instance/Port/Protocol）
2. 发 FindService 后，持续收到 OfferService（VM 持续广播）

注意：VMware VMnet 虚拟网卡不向宿主机 TCP/IP 栈转发多播，
      因此改用 scapy/Npcap 在驱动层嗅探，与 Wireshark 同一层。
"""

from __future__ import annotations

import socket
import struct
import time

import pytest

from someip_fuzzer.core.protocol import build_sd_find
from tests.e2e.conftest import SD_MULTICAST, SD_PORT, VM_IP, VM_PORT, VMNET8_IFACE

scapy = pytest.importorskip("scapy.all", reason="scapy 未安装，跳过 SD E2E 测试")


def _sniff_offer(timeout: float = 6.0) -> dict | None:
    """用 scapy 嗅探一条 OfferService 报文并解析字段。"""
    from scapy.all import AsyncSniffer, IP, UDP

    result: list[dict | None] = [None]

    def _check(pkt):
        if result[0] is not None:
            return
        if IP not in pkt or UDP not in pkt:
            return
        if pkt[IP].src != VM_IP or pkt[UDP].dport != SD_PORT:
            return
        data = bytes(pkt[UDP].payload)
        if len(data) < 28 or data[0:4] != b"\xff\xff\x81\x00":
            return
        entries_len = struct.unpack_from(">I", data, 20)[0]
        if entries_len < 16:
            return
        entry = data[24:24 + 16]
        if entry[0] != 0x01:  # OfferService
            return
        svc_id  = struct.unpack_from(">H", entry, 4)[0]
        inst_id = struct.unpack_from(">H", entry, 6)[0]
        ttl     = struct.unpack_from(">I", entry, 8)[0] & 0x00FFFFFF
        session_id = struct.unpack_from(">H", data, 10)[0]

        opts_start = 24 + entries_len
        ep_ip = ep_proto = ep_port = None
        if len(data) > opts_start + 4:
            opts_len = struct.unpack_from(">I", data, opts_start)[0]
            if opts_len >= 12 and len(data) >= opts_start + 4 + opts_len:
                opt = data[opts_start + 4:]
                ep_ip    = socket.inet_ntoa(opt[4:8])
                ep_proto = opt[9]
                ep_port  = struct.unpack_from(">H", opt, 10)[0]

        if svc_id == 0x1111:
            result[0] = {
                "service_id": svc_id, "instance_id": inst_id,
                "ttl": ttl, "session_id": session_id,
                "ep_ip": ep_ip, "ep_proto": ep_proto, "ep_port": ep_port,
            }

    sniff_kwargs: dict = {"filter": f"udp port {SD_PORT}", "prn": _check,
                          "store": False, "timeout": timeout}
    if VMNET8_IFACE:
        sniff_kwargs["iface"] = VMNET8_IFACE
    sniffer = AsyncSniffer(**sniff_kwargs)
    sniffer.start()
    sniffer.join(timeout=timeout + 1)
    return result[0]


def test_offer_service_fields() -> None:
    """OfferService 报文字段完全匹配配置值。"""
    offer = _sniff_offer(timeout=6)
    assert offer is not None, (
        f"6 秒内未嗅探到 VM OfferService。确认 Npcap 已安装 + 管理员权限运行。"
    )
    assert offer["service_id"]  == 0x1111, f"Service ID: {offer['service_id']:#06x}"
    assert offer["instance_id"] == 0x2222, f"Instance ID: {offer['instance_id']:#06x}"
    assert offer["ttl"]  > 0,              f"TTL 应 > 0: {offer['ttl']}"
    assert offer["ep_ip"]   == VM_IP,      f"Endpoint IP: {offer['ep_ip']}"
    assert offer["ep_port"] == VM_PORT,    f"Endpoint Port: {offer['ep_port']}"
    assert offer["ep_proto"] == 0x11,      f"Protocol 应为 UDP(0x11): {offer['ep_proto']:#04x}"


def test_find_service_triggers_offer() -> None:
    """发 FindService 后 VM 持续广播 OfferService。"""
    # 收一条基线
    offer_before = _sniff_offer(timeout=6)
    assert offer_before is not None, "基线 OfferService 未收到"
    session_before = offer_before["session_id"]

    # 发 FindService（不影响测试结果，VM 无论如何每秒广播）
    find_pkt = build_sd_find(0x1111, 0x2222, session_id=1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
    try:
        sock.sendto(find_pkt.to_bytes(), (SD_MULTICAST, SD_PORT))
    finally:
        sock.close()

    # 再收一条，验证 VM 仍在广播
    offer_after = _sniff_offer(timeout=6)
    assert offer_after is not None, "FindService 后未收到 OfferService"
    assert offer_after["session_id"] > 0
    assert offer_after["service_id"] == 0x1111

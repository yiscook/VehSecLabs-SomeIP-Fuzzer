"""PCAP 抓包封装 —— 基于 scapy AsyncSniffer。"""

from __future__ import annotations

from pathlib import Path

from scapy.contrib.automotive.someip import SOMEIP
from scapy.layers.inet import UDP
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.utils import rdpcap, wrpcap

from someip_fuzzer.core.protocol import SomeIpPacket
from someip_fuzzer.utils.logger import logger


def _pkt_to_someip(pkt: Packet) -> SomeIpPacket | None:
    """将 scapy 报文转换为 SomeIpPacket，非 SOME/IP 报文返回 None。"""
    if SOMEIP not in pkt:
        return None
    try:
        return SomeIpPacket.from_scapy(pkt[SOMEIP])
    except Exception as e:
        logger.debug(f"pcap: failed to parse packet: {e}")
        return None


class PcapCapture:
    """实时网卡抓包封装（需要 Npcap / libpcap 权限）。"""

    def __init__(self) -> None:
        self._sniffer: AsyncSniffer | None = None
        self._packets: list[SomeIpPacket] = []

    def start(
        self,
        iface: str,
        bpf_filter: str = "udp port 30490 or udp port 30509",
    ) -> None:
        self._packets = []
        self._sniffer = AsyncSniffer(
            iface=iface,
            filter=bpf_filter,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()
        logger.info(f"PcapCapture started on {iface!r}, filter={bpf_filter!r}")

    def _on_packet(self, pkt: Packet) -> None:
        sp = _pkt_to_someip(pkt)
        if sp is not None:
            self._packets.append(sp)

    def stop(self) -> None:
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        logger.info(f"PcapCapture stopped, captured {len(self._packets)} packets")

    def get_packets(self) -> list[SomeIpPacket]:
        return list(self._packets)


def load_pcap(path: str | Path) -> list[SomeIpPacket]:
    """从 pcap 文件加载 SOME/IP 报文列表。"""
    path = Path(path)
    packets = rdpcap(str(path))
    result: list[SomeIpPacket] = []
    for pkt in packets:
        sp = _pkt_to_someip(pkt)
        if sp is not None:
            result.append(sp)
    logger.info(f"Loaded {len(result)} SOME/IP packets from {path}")
    return result


def save_pcap(packets: list[SomeIpPacket], path: str | Path) -> None:
    """将 SomeIpPacket 列表保存为 pcap 文件。"""
    raw_list = []
    for p in packets:
        try:
            raw_list.append(p.to_bytes())
        except Exception:
            pass
    save_raw_pcap(raw_list, path)


def save_raw_pcap(
    raw_packets: list[bytes],
    path: str | Path,
    dst_ip: str = "127.0.0.1",
    dst_port: int = 30509,
    src_ip: str = "127.0.0.1",
) -> None:
    """将原始字节列表保存为 pcap 文件（使用实际目标 IP/端口）。

    自动截断超过 UDP 最大载荷（65507 字节）的包，跳过无法构建的包。
    """
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether

    _MAX_UDP_PAYLOAD = 65507  # 65535 - 20(IP header) - 8(UDP header)

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    scapy_pkts = []
    skipped = 0
    for raw in raw_packets:
        try:
            if len(raw) > _MAX_UDP_PAYLOAD:
                raw = raw[:_MAX_UDP_PAYLOAD]
            pkt = (
                Ether()
                / IP(src=src_ip, dst=dst_ip)
                / UDP(sport=12345, dport=dst_port)
                / raw
            )
            scapy_pkts.append(pkt)
        except Exception:
            skipped += 1

    wrpcap(str(path), scapy_pkts)
    logger.info(
        f"Saved {len(scapy_pkts)} packets to {path}"
        + (f" (skipped {skipped})" if skipped else "")
    )

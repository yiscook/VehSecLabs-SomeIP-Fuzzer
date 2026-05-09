"""SOME/IP 协议报文构造、解析、服务发现 (SD) 构造、SOME/IP-TP 分段。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from scapy.contrib.automotive.someip import (
    SD,
    SOMEIP,
    SDEntry_EventGroup,
    SDEntry_Service,
    SDOption_IP4_EndPoint,
    SDOption_IP4_Multicast,
)
from scapy.packet import Raw

# SD service 固定地址
SD_SERVICE_ID: int = 0xFFFF
SD_METHOD_ID: int = 0x8100

# 注册 SD 层，使 scapy 能自动解析 SOME/IP-SD 报文
SOMEIP.payload_cls_by_srv_id[SD_SERVICE_ID] = SD  # type: ignore[assignment]


class MessageType(IntEnum):
    REQUEST = 0x00
    REQUEST_NO_RETURN = 0x01
    NOTIFICATION = 0x02
    REQUEST_ACK = 0x40
    REQUEST_NO_RETURN_ACK = 0x41
    NOTIFICATION_ACK = 0x42
    RESPONSE = 0x80
    RESPONSE_ACK = 0xC0
    ERROR = 0x81
    ERROR_ACK = 0xC1
    TP_REQUEST = 0x20
    TP_REQUEST_NO_RETURN = 0x21
    TP_NOTIFICATION = 0x22
    TP_RESPONSE = 0xA0
    TP_ERROR = 0xA1


class ReturnCode(IntEnum):
    E_OK = 0x00
    E_NOT_OK = 0x01
    E_UNKNOWN_SERVICE = 0x02
    E_UNKNOWN_METHOD = 0x03
    E_NOT_READY = 0x04
    E_NOT_REACHABLE = 0x05
    E_TIMEOUT = 0x06
    E_WRONG_PROTOCOL_VERSION = 0x07
    E_WRONG_INTERFACE_VERSION = 0x08
    E_MALFORMED_MESSAGE = 0x09
    E_WRONG_MESSAGE_TYPE = 0x0A


@dataclass
class SomeIpPacket:
    """SOME/IP 报文数据类，封装 scapy SOMEIP 层，提供友好 API。"""

    service_id: int
    method_id: int
    client_id: int = 0
    session_id: int = 1
    protocol_version: int = 1
    interface_version: int = 1
    message_type: MessageType = MessageType.REQUEST
    return_code: ReturnCode = ReturnCode.E_OK
    payload: bytes = b""

    # 额外元数据（不序列化，用于 GUI 显示和调试）
    source_addr: tuple[str, int] | None = field(default=None, repr=False, compare=False)
    timestamp: float | None = field(default=None, repr=False, compare=False)

    def to_scapy(self) -> SOMEIP:
        """返回对应的 scapy SOMEIP 对象。"""
        pkt = SOMEIP(
            srv_id=self.service_id,
            sub_id=self.method_id,
            client_id=self.client_id,
            session_id=self.session_id,
            proto_ver=self.protocol_version,
            iface_ver=self.interface_version,
            msg_type=int(self.message_type),
            retcode=int(self.return_code),
        )
        if self.payload:
            pkt = pkt / Raw(self.payload)
        return pkt

    def to_bytes(self) -> bytes:
        """序列化为网络字节序。"""
        return bytes(self.to_scapy())

    @classmethod
    def from_bytes(cls, data: bytes, source_addr: tuple[str, int] | None = None) -> "SomeIpPacket":
        """从网络字节流反序列化。"""
        pkt = SOMEIP(data)
        payload = _extract_payload(pkt)
        return cls(
            service_id=pkt.srv_id,
            method_id=pkt.sub_id,
            client_id=pkt.client_id,
            session_id=pkt.session_id,
            protocol_version=pkt.proto_ver,
            interface_version=pkt.iface_ver,
            message_type=MessageType(pkt.msg_type),
            return_code=ReturnCode(pkt.retcode),
            payload=payload,
            source_addr=source_addr,
        )

    @classmethod
    def from_scapy(cls, pkt: SOMEIP, source_addr: tuple[str, int] | None = None) -> "SomeIpPacket":
        """从 scapy SOMEIP 对象创建。"""
        payload = _extract_payload(pkt)
        return cls(
            service_id=pkt.srv_id,
            method_id=pkt.sub_id,
            client_id=pkt.client_id,
            session_id=pkt.session_id,
            protocol_version=pkt.proto_ver,
            interface_version=pkt.iface_ver,
            message_type=MessageType(pkt.msg_type),
            return_code=ReturnCode(pkt.retcode),
            payload=payload,
            source_addr=source_addr,
        )

    # ── 工厂方法 ──────────────────────────────────────────────────────────────

    @classmethod
    def request(cls, service_id: int, method_id: int, payload: bytes = b"",
                client_id: int = 0, session_id: int = 1) -> "SomeIpPacket":
        return cls(service_id=service_id, method_id=method_id, payload=payload,
                   client_id=client_id, session_id=session_id,
                   message_type=MessageType.REQUEST, return_code=ReturnCode.E_OK)

    @classmethod
    def response(cls, service_id: int, method_id: int, payload: bytes = b"",
                 client_id: int = 0, session_id: int = 1,
                 return_code: ReturnCode = ReturnCode.E_OK) -> "SomeIpPacket":
        return cls(service_id=service_id, method_id=method_id, payload=payload,
                   client_id=client_id, session_id=session_id,
                   message_type=MessageType.RESPONSE, return_code=return_code)

    @classmethod
    def notification(cls, service_id: int, event_id: int, payload: bytes = b"",
                     session_id: int = 1) -> "SomeIpPacket":
        return cls(service_id=service_id, method_id=event_id, payload=payload,
                   session_id=session_id,
                   message_type=MessageType.NOTIFICATION, return_code=ReturnCode.E_OK)

    @classmethod
    def error(cls, service_id: int, method_id: int, payload: bytes = b"",
              client_id: int = 0, session_id: int = 1,
              return_code: ReturnCode = ReturnCode.E_NOT_OK) -> "SomeIpPacket":
        return cls(service_id=service_id, method_id=method_id, payload=payload,
                   client_id=client_id, session_id=session_id,
                   message_type=MessageType.ERROR, return_code=return_code)

    @classmethod
    def request_no_return(cls, service_id: int, method_id: int, payload: bytes = b"",
                          session_id: int = 1) -> "SomeIpPacket":
        return cls(service_id=service_id, method_id=method_id, payload=payload,
                   session_id=session_id,
                   message_type=MessageType.REQUEST_NO_RETURN, return_code=ReturnCode.E_OK)

    # ── SOME/IP-TP 分段 ───────────────────────────────────────────────────────

    def fragment_tp(self, mtu: int = 1400) -> list["SomeIpPacket"]:
        """将大 payload 拆分为 SOME/IP-TP 分段列表。

        TP 标志位（0x20）会被设置到 message_type 上。
        分段 header 额外占 4 字节（offset + more_seg），有效 payload 为 mtu - 4。
        """
        if len(self.payload) <= mtu:
            return [self]

        # 确定 TP message_type（原始类型 | 0x20）
        tp_type = int(self.message_type) | 0x20

        # 每段有效数据大小，offset 单位为 16 字节（类似 IP 分片）
        seg_size = (mtu // 16) * 16
        if seg_size == 0:
            seg_size = 16

        data = self.payload
        frags: list[SomeIpPacket] = []
        offset = 0
        while data:
            chunk = data[:seg_size]
            data = data[seg_size:]
            more = 1 if data else 0

            # 用 scapy 构造 TP 分段（含 offset 和 more_seg 字段）
            scapy_pkt = SOMEIP(
                srv_id=self.service_id,
                sub_id=self.method_id,
                client_id=self.client_id,
                session_id=self.session_id,
                proto_ver=self.protocol_version,
                iface_ver=self.interface_version,
                msg_type=tp_type,
                retcode=int(self.return_code),
                offset=offset,
                more_seg=more,
            )
            if chunk:
                scapy_pkt = scapy_pkt / Raw(chunk)

            frag = SomeIpPacket.from_scapy(scapy_pkt)
            frags.append(frag)
            offset += len(chunk) // 16

        return frags


# ── SD 构造器 ─────────────────────────────────────────────────────────────────

def build_sd_find(service_id: int, instance_id: int, session_id: int = 1) -> SomeIpPacket:
    """构造 SOME/IP-SD FindService 报文。"""
    entry = SDEntry_Service(
        type=0x00,  # FindService
        srv_id=service_id,
        inst_id=instance_id,
        major_ver=0xFF,  # any version
        ttl=3,
        minor_ver=0xFFFFFFFF,
    )
    sd = SD(entry_array=[entry], option_array=[])
    return _wrap_sd(sd, session_id)


def build_sd_offer(service_id: int, instance_id: int, addr: str, port: int,
                   ttl: int = 3, major_ver: int = 1, minor_ver: int = 0,
                   session_id: int = 1) -> SomeIpPacket:
    """构造 SOME/IP-SD OfferService 报文（含 IPv4 端点选项）。"""
    entry = SDEntry_Service(
        type=0x01,  # OfferService
        srv_id=service_id,
        inst_id=instance_id,
        major_ver=major_ver,
        ttl=ttl,
        minor_ver=minor_ver,
        index_1=0,
        n_opt_1=1,  # 关联第 0 个 option
    )
    option = SDOption_IP4_EndPoint(
        addr=addr,
        l4_proto=0x11,  # UDP
        port=port,
    )
    sd = SD(entry_array=[entry], option_array=[option])
    return _wrap_sd(sd, session_id)


def build_sd_stop_offer(service_id: int, instance_id: int,
                        major_ver: int = 1, minor_ver: int = 0,
                        session_id: int = 1) -> SomeIpPacket:
    """构造 SOME/IP-SD StopOfferService 报文（ttl=0）。"""
    entry = SDEntry_Service(
        type=0x01,  # OfferService with ttl=0 = StopOffer
        srv_id=service_id,
        inst_id=instance_id,
        major_ver=major_ver,
        ttl=0,
        minor_ver=minor_ver,
    )
    sd = SD(entry_array=[entry], option_array=[])
    return _wrap_sd(sd, session_id)


def build_sd_subscribe(service_id: int, instance_id: int, eventgroup_id: int,
                       addr: str, port: int, ttl: int = 3,
                       major_ver: int = 1, session_id: int = 1) -> SomeIpPacket:
    """构造 SOME/IP-SD SubscribeEventgroup 报文。"""
    entry = SDEntry_EventGroup(
        type=0x06,  # SubscribeEventgroup
        srv_id=service_id,
        inst_id=instance_id,
        major_ver=major_ver,
        ttl=ttl,
        eventgroup_id=eventgroup_id,
        index_1=0,
        n_opt_1=1,
    )
    option = SDOption_IP4_EndPoint(
        addr=addr,
        l4_proto=0x11,  # UDP
        port=port,
    )
    sd = SD(entry_array=[entry], option_array=[option])
    return _wrap_sd(sd, session_id)


def build_sd_subscribe_ack(service_id: int, instance_id: int, eventgroup_id: int,
                           major_ver: int = 1, session_id: int = 1) -> SomeIpPacket:
    """构造 SOME/IP-SD SubscribeEventgroupAck 报文。"""
    entry = SDEntry_EventGroup(
        type=0x07,  # SubscribeEventgroupAck
        srv_id=service_id,
        inst_id=instance_id,
        major_ver=major_ver,
        ttl=3,
        eventgroup_id=eventgroup_id,
    )
    sd = SD(entry_array=[entry], option_array=[])
    return _wrap_sd(sd, session_id)


def build_sd_subscribe_nack(service_id: int, instance_id: int, eventgroup_id: int,
                             major_ver: int = 1, session_id: int = 1) -> SomeIpPacket:
    """构造 SOME/IP-SD SubscribeEventgroupNack 报文（ttl=0）。"""
    entry = SDEntry_EventGroup(
        type=0x07,  # SubscribeEventgroupAck with ttl=0 = Nack
        srv_id=service_id,
        inst_id=instance_id,
        major_ver=major_ver,
        ttl=0,
        eventgroup_id=eventgroup_id,
    )
    sd = SD(entry_array=[entry], option_array=[])
    return _wrap_sd(sd, session_id)


# ── 内部工具 ──────────────────────────────────────────────────────────────────

def _extract_payload(pkt: SOMEIP) -> bytes:
    """从 scapy SOMEIP 对象提取原始 payload 字节。

    优先检查 scapy payload 链（SOMEIP(...) / Raw(data) 构造方式），
    再检查 PacketListField data（解析收到的报文时填充）。
    """
    # 优先：payload 链（自行构造的 SOMEIP() / Raw(data)）
    if pkt.payload and pkt.payload.__class__.__name__ not in ("NoPayload",):
        return bytes(pkt.payload)
    # 备选：PacketListField data（scapy 解析外来字节时使用）
    if pkt.data:
        data_bytes = b"".join(bytes(d) for d in pkt.data)
        if data_bytes:
            return data_bytes
    return b""


def _wrap_sd(sd: SD, session_id: int) -> SomeIpPacket:
    """将 SD 层包装为 SomeIpPacket，service_id=0xFFFF, method_id=0x8100。"""
    sd_bytes = bytes(sd)
    return SomeIpPacket(
        service_id=SD_SERVICE_ID,
        method_id=SD_METHOD_ID,
        client_id=0,
        session_id=session_id,
        protocol_version=1,
        interface_version=1,
        message_type=MessageType.NOTIFICATION,
        return_code=ReturnCode.E_OK,
        payload=sd_bytes,
    )

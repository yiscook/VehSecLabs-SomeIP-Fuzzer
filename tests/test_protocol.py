"""协议层单元测试（无网络依赖）。"""

import pytest

from someip_fuzzer.core.protocol import (
    MessageType,
    ReturnCode,
    SomeIpPacket,
    build_sd_find,
    build_sd_offer,
    build_sd_stop_offer,
    build_sd_subscribe,
    build_sd_subscribe_ack,
    build_sd_subscribe_nack,
)


class TestSomeIpPacketSerialize:
    def test_serialize_min_size(self):
        """序列化后至少 16 字节（固定 header）。"""
        p = SomeIpPacket.request(0x1234, 0x5678)
        assert len(p.to_bytes()) >= 16

    def test_serialize_with_payload(self):
        p = SomeIpPacket.request(0x1234, 0x5678, b"hello")
        raw = p.to_bytes()
        assert len(raw) == 16 + 5  # 16 header + 5 payload

    def test_roundtrip_fields(self):
        """序列化 → 反序列化，核心字段一致。"""
        p1 = SomeIpPacket.request(0x1234, 0x5678, b"world",
                                   client_id=0xABCD, session_id=42)
        p2 = SomeIpPacket.from_bytes(p1.to_bytes())
        assert p2.service_id == 0x1234
        assert p2.method_id == 0x5678
        assert p2.client_id == 0xABCD
        assert p2.session_id == 42
        assert p2.payload == b"world"

    def test_roundtrip_empty_payload(self):
        p1 = SomeIpPacket.request(0xFFFF, 0x0000)
        p2 = SomeIpPacket.from_bytes(p1.to_bytes())
        assert p2.payload == b""

    def test_to_scapy_returns_someip(self):
        from scapy.contrib.automotive.someip import SOMEIP
        p = SomeIpPacket.request(0x1234, 0x5678)
        scapy_pkt = p.to_scapy()
        assert isinstance(scapy_pkt, SOMEIP)
        assert scapy_pkt.srv_id == 0x1234

    def test_length_field_correct(self):
        """SOME/IP length 字段 = 8 + len(payload)。"""
        p = SomeIpPacket.request(0x1234, 0x5678, b"X" * 100)
        raw = p.to_bytes()
        length_field = int.from_bytes(raw[4:8], "big")
        assert length_field == 8 + 100


class TestSomeIpPacketFactoryMethods:
    def test_request_msg_type(self):
        p = SomeIpPacket.request(0x1234, 0x5678)
        assert p.message_type == MessageType.REQUEST

    def test_response_msg_type(self):
        p = SomeIpPacket.response(0x1234, 0x5678)
        assert p.message_type == MessageType.RESPONSE

    def test_notification_msg_type(self):
        p = SomeIpPacket.notification(0x1234, 0x0100)
        assert p.message_type == MessageType.NOTIFICATION

    def test_error_msg_type(self):
        p = SomeIpPacket.error(0x1234, 0x5678)
        assert p.message_type == MessageType.ERROR
        assert p.return_code == ReturnCode.E_NOT_OK

    def test_request_no_return_msg_type(self):
        p = SomeIpPacket.request_no_return(0x1234, 0x5678)
        assert p.message_type == MessageType.REQUEST_NO_RETURN

    def test_all_five_factory_methods_serialize(self):
        """5 种工厂方法生成的报文都能序列化并至少 16 字节。"""
        factories = [
            SomeIpPacket.request(0x1234, 0x5678),
            SomeIpPacket.response(0x1234, 0x5678),
            SomeIpPacket.notification(0x1234, 0x0100),
            SomeIpPacket.error(0x1234, 0x5678),
            SomeIpPacket.request_no_return(0x1234, 0x5678),
        ]
        for p in factories:
            assert len(p.to_bytes()) >= 16


class TestSomeIpSdPackets:
    def test_sd_find_service_id(self):
        sd = build_sd_find(0x1234, 0x0001)
        assert sd.service_id == 0xFFFF
        assert sd.method_id == 0x8100
        assert sd.message_type == MessageType.NOTIFICATION

    def test_sd_offer_structure(self):
        """OfferService 报文：SD payload 非空，entry type=0x01。"""
        sd = build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509)
        assert sd.service_id == 0xFFFF
        assert len(sd.payload) > 0

        # 验证 SD entry_array 中第一个 entry 的 type 字段
        from scapy.contrib.automotive.someip import SD
        inner_sd = SD(sd.payload)
        assert len(inner_sd.entry_array) > 0
        assert inner_sd.entry_array[0].type == 0x01  # OfferService

    def test_sd_subscribe_structure(self):
        """SubscribeEventgroup 报文：entry type=0x06。"""
        sd = build_sd_subscribe(0x1234, 0x0001, 0x0100, "192.168.1.100", 40000)
        from scapy.contrib.automotive.someip import SD
        inner_sd = SD(sd.payload)
        assert inner_sd.entry_array[0].type == 0x06  # SubscribeEventgroup

    def test_sd_subscribe_ack_structure(self):
        sd = build_sd_subscribe_ack(0x1234, 0x0001, 0x0100)
        from scapy.contrib.automotive.someip import SD
        inner_sd = SD(sd.payload)
        assert inner_sd.entry_array[0].type == 0x07  # SubscribeAck

    def test_sd_stop_offer_ttl_zero(self):
        sd = build_sd_stop_offer(0x1234, 0x0001)
        from scapy.contrib.automotive.someip import SD
        inner_sd = SD(sd.payload)
        assert inner_sd.entry_array[0].ttl == 0

    def test_sd_subscribe_nack_ttl_zero(self):
        sd = build_sd_subscribe_nack(0x1234, 0x0001, 0x0100)
        from scapy.contrib.automotive.someip import SD
        inner_sd = SD(sd.payload)
        assert inner_sd.entry_array[0].ttl == 0

    def test_sd_serializes(self):
        """SD 报文能序列化，总长度合理。"""
        sd = build_sd_offer(0xA994, 0x0001, "10.0.0.1", 30509, ttl=10)
        raw = sd.to_bytes()
        assert len(raw) > 16  # header + SD payload


class TestSomeIpTp:
    def test_tp_fragment_large_payload(self):
        """5000 字节 payload 以 mtu=1400 分段，必须 > 1 个分段。"""
        p = SomeIpPacket.request(0x1234, 0x5678, b"X" * 5000)
        frags = p.fragment_tp(mtu=1400)
        assert len(frags) > 1

    def test_tp_fragment_small_payload_no_fragment(self):
        """小于 mtu 的报文不分段，原样返回。"""
        p = SomeIpPacket.request(0x1234, 0x5678, b"hello")
        frags = p.fragment_tp(mtu=1400)
        assert len(frags) == 1
        assert frags[0] is p  # 原始对象

    def test_tp_fragment_msg_type_has_tp_bit(self):
        """分段后 msg_type 必须含 TP bit (0x20)。"""
        p = SomeIpPacket.request(0x1234, 0x5678, b"Z" * 5000)
        frags = p.fragment_tp(mtu=1400)
        for frag in frags:
            assert int(frag.message_type) & 0x20, \
                f"TP bit missing: {hex(frag.message_type)}"

    def test_tp_fragment_service_id_preserved(self):
        p = SomeIpPacket.request(0x1234, 0x5678, b"A" * 3000)
        frags = p.fragment_tp()
        for frag in frags:
            assert frag.service_id == 0x1234
            assert frag.method_id == 0x5678

    def test_tp_fragment_total_data_preserved(self):
        """所有分段 payload 合计长度 = 原始 payload。"""
        original = b"D" * 4000
        p = SomeIpPacket.request(0x1234, 0x5678, original)
        frags = p.fragment_tp(mtu=1400)
        total = sum(len(f.payload) for f in frags)
        assert total == len(original)


class TestEnums:
    def test_message_type_values(self):
        assert int(MessageType.REQUEST) == 0x00
        assert int(MessageType.RESPONSE) == 0x80
        assert int(MessageType.ERROR) == 0x81
        assert int(MessageType.TP_REQUEST) == 0x20

    def test_return_code_values(self):
        assert int(ReturnCode.E_OK) == 0x00
        assert int(ReturnCode.E_NOT_OK) == 0x01

    def test_enum_roundtrip(self):
        assert MessageType(0x80) == MessageType.RESPONSE
        assert ReturnCode(0x02) == ReturnCode.E_UNKNOWN_SERVICE


class TestConfig:
    def test_load_config(self, tmp_path):
        cfg_content = """
[target]
name = "test"
ip = "10.0.0.1"
port = 30509
transport = "udp"

[sd]
multicast = "224.224.224.245"
port = 30490

[[services]]
service_id = 0x1234
instance_id = 0x0001
major_version = 1
minor_version = 0
methods = [0x8001]
events = [0x0100]
"""
        cfg_file = tmp_path / "test.toml"
        cfg_file.write_text(cfg_content, encoding="utf-8")

        from someip_fuzzer.utils.config import load_config
        cfg = load_config(cfg_file)
        assert cfg.target.ip == "10.0.0.1"
        assert cfg.target.port == 30509
        assert len(cfg.services) == 1
        assert cfg.services[0].service_id == 0x1234

    def test_save_load_roundtrip(self, tmp_path):
        from someip_fuzzer.utils.config import AppConfig, ServiceDef, TargetConfig, load_config, save_config
        original = AppConfig(
            target=TargetConfig(name="rt", ip="192.168.1.1", port=9999),
            services=[ServiceDef(service_id=0xABCD, instance_id=0x0001)],
        )
        path = tmp_path / "rt.toml"
        save_config(original, path)
        loaded = load_config(path)
        assert loaded.target.ip == "192.168.1.1"
        assert loaded.services[0].service_id == 0xABCD

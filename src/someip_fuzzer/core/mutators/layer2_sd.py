"""Layer 2.6：SOME/IP-SD Entry/Option 语义变异器（8 种）。

涵盖 SPEC §2.3 task 2.14 的 L2-SD01~SD08 全部策略，针对
SOME/IP Service Discovery 报文（service_id=0xFFFF, method_id=0x8100）
的 payload 结构进行语义级变异。

SD payload 结构（简化）：
  Flags(1B) + Reserved(3B)
  + Entry Array Length(4B big-endian)
  + [Entry * N]（每 Entry 16B）
  + Option Array Length(4B big-endian)
  + [Option * M]（每 Option 长度可变）

所有变异器使用 _make_raw_result()（SD 报文 payload 结构复杂，
直接操作字节比回填 dataclass 更可靠）。
"""

from __future__ import annotations

import random
import struct

from someip_fuzzer.core.mutator import BaseMutator, MutationResult, register_mutator
from someip_fuzzer.core.protocol import (
    SomeIpPacket,
    build_sd_offer,
    build_sd_find,
    SD_SERVICE_ID,
    SD_METHOD_ID,
)

# ── SD payload 字节偏移常量 ────────────────────────────────────────────────────
# SD payload = SOME/IP payload（从 SOME/IP header 后 16 字节开始）
SD_FLAGS_OFFSET = 0          # 1 字节 Flags（reboot flag 等）
SD_RESERVED_LEN = 3          # 保留字节数
SD_ENTRY_ARRAY_LEN_OFFSET = 4   # 4 字节 big-endian，Entry Array 的总字节数
SD_OPTION_ARRAY_LEN_OFFSET = 8  # 位置在 Flags(1)+Reserved(3)+EntryArrayLen(4) = 8 字节后
                                 # 但 option array length 实际位置依赖 entry array 大小，
                                 # 这里仅作"假设只有1个entry"时的固定偏移参考

SD_PAYLOAD_HEADER_LEN = 12   # Flags(1)+Reserved(3)+EntryArrayLen(4)+OptionArrayLen(4) = 12
# 但实际上 Option Array Length 紧跟在 Entry Array 之后，
# 所以当 entry array 不为 12 字节时需动态计算。

SD_ENTRY_LEN = 16            # 每个 Entry 固定 16 字节
SD_TYPE_OFFSET = 0           # Entry 内 Type 字节偏移（Entry 相对偏移）
SD_INDEX1_OFFSET = 2         # Entry 内 Index 1st Option
SD_INDEX2_OFFSET = 3         # Entry 内 Index 2nd Option
SD_TTL_OFFSET = 5            # Entry 内 TTL 的第 1 字节（TTL 占 3 字节: bytes 5-7）
SD_MAJOR_VER_OFFSET = 4      # Entry 内 Major Version 字节

# Endpoint Option 结构（IPv4，固定 12 字节）：
# Length(2B)+Type(1B=0x04)+Reserved(1B)+IP(4B)+Reserved(1B)+Proto(1B)+Port(2B)
SD_OPT_IPV4_ENDPOINT_TYPE = 0x04
SD_OPT_IPV4_LEN = 12
SD_OPT_IP_OFFSET = 4         # Option 内 IP 字段偏移
SD_OPT_PORT_OFFSET = 10      # Option 内 Port 字段偏移（2 字节）


def _make_base_sd_raw(rng: random.Random) -> bytes:
    """构造一个合法的 OfferService SD 报文字节流，供后续变异。

    使用随机但语义合法的 service_id / instance_id / addr / port。
    """
    pkt = build_sd_offer(
        service_id=rng.randint(0x0001, 0xFFFE),
        instance_id=rng.randint(0x0001, 0xFFFE),
        addr="192.168.1.1",
        port=30509,
    )
    return pkt.to_bytes()


def _sd_payload_offset() -> int:
    """返回 SD payload 在完整 SOME/IP 字节流中的起始位置（固定 16 字节 header 后）。"""
    return 16  # SOME/IP header = 16 bytes


# ─────────────────────────────────────────────────────────────────────────────


@register_mutator
class SdInvalidEntryTypeMutator(BaseMutator):
    """L2-SD01：将 SD Entry 的 Type 字节改为保留/未定义值。

    SOME/IP-SD 规范定义的合法 Entry Type：
    - 0x00: FindService，0x01: OfferService（Service Entry）
    - 0x06: SubscribeEventgroup，0x07: SubscribeEventgroupAck（EventGroup Entry）
    保留值（如 0x03, 0x07, 0xFF）触发服务端 dispatch 的 default 分支或崩溃。
    """

    name = "L2-SD01.invalid_entry_type"
    layer = 2
    target_field = "sd_entry_type"
    strategy = "invalid_entry_type"

    _INVALID_TYPES = [0x02, 0x03, 0x04, 0x05, 0x08, 0x7F, 0xFF]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        raw = bytearray(_make_base_sd_raw(rng))
        pay_off = _sd_payload_offset()
        # Entry Array 从 SD payload 第 8 字节开始（Flags 1 + Reserved 3 + EntryArrayLen 4）
        entry_start = pay_off + 8
        if len(raw) >= entry_start + SD_ENTRY_LEN:
            invalid_type = rng.choice(self._INVALID_TYPES)
            raw[entry_start + SD_TYPE_OFFSET] = invalid_type
            return self._make_raw_result(bytes(raw), invalid_type=invalid_type)
        return self._make_raw_result(bytes(raw), skipped=True)


@register_mutator
class SdConflictingEntriesMutator(BaseMutator):
    """L2-SD02：同一 SD 报文中同时包含 OfferService 和 StopOfferService Entry。

    OfferService（Type=0x01, TTL>0）和 StopOfferService（Type=0x01, TTL=0）
    同时出现在 Entry Array 中，形成语义矛盾：服务同时宣告"存在"和"停止"。
    触发服务注册表的并发更新竞争或状态不一致。
    """

    name = "L2-SD02.conflicting_entries"
    layer = 2
    target_field = "sd_entries"
    strategy = "conflicting_entries"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        srv_id = rng.randint(0x0001, 0xFFFE)
        inst_id = rng.randint(0x0001, 0xFFFE)
        major = 1
        minor = 0

        # OfferService Entry（16 字节）：Type=0x01, TTL=3（3 字节）, Major=1, Minor=0
        offer_entry = struct.pack(
            ">BBBB",
            0x01,    # Type: OfferService
            0x00,    # Index 1st option
            0x00,    # Index 2nd option
            0x00,    # n_opt_1/n_opt_2
        ) + struct.pack(">H", srv_id) + struct.pack(">H", inst_id) + struct.pack(">B", major)
        offer_entry += b"\x00\x00\x03"  # TTL = 3 (3 bytes)
        offer_entry += struct.pack(">I", minor)  # Minor version (4 bytes)

        # StopOfferService Entry（16 字节）：Type=0x01, TTL=0
        stop_entry = struct.pack(
            ">BBBB",
            0x01,    # Type: OfferService (TTL=0 means StopOffer)
            0x00, 0x00, 0x00,
        ) + struct.pack(">H", srv_id) + struct.pack(">H", inst_id) + struct.pack(">B", major)
        stop_entry += b"\x00\x00\x00"   # TTL = 0
        stop_entry += struct.pack(">I", minor)

        entry_array = offer_entry + stop_entry
        entry_array_len = len(entry_array)

        # 构造 SD payload：Flags(1)+Reserved(3)+EntryArrayLen(4)+entries+OptionArrayLen(4)
        sd_payload = struct.pack(
            ">BBBBI",
            0xC0, 0x00, 0x00, 0x00,    # Flags + Reserved
            entry_array_len,
        ) + entry_array + struct.pack(">I", 0)  # no options

        # 包装成完整 SOME/IP 字节流
        someip_len = 8 + len(sd_payload)
        raw = struct.pack(
            ">HHIBBBB",
            SD_SERVICE_ID, SD_METHOD_ID,
            someip_len,
            0x00, 0x01,    # client_id
            rng.randint(0, 0xFF), rng.randint(0, 0xFF),  # session_id
        ) + bytes([0x01, 0x01, 0x02, 0x00]) + sd_payload  # proto/iface/type/rc + SD payload

        return self._make_raw_result(
            raw,
            service_id=srv_id, instance_id=inst_id, entries=2,
        )


@register_mutator
class SdExcessiveEntriesMutator(BaseMutator):
    """L2-SD03：构造包含大量重复 Entry 的 SD 报文（Entry Array 膨胀攻击）。

    正常 SD 报文包含 1-5 个 Entry；此变异器发送 50-200 个相同 Entry，
    触发接收方的 Entry 处理循环性能退化（O(n) 内存分配 / 日志打印），
    模拟 SD 层的 DoS 攻击。
    """

    name = "L2-SD03.excessive_entries"
    layer = 2
    target_field = "sd_entries"
    strategy = "excessive_entries"
    weight = 0.8  # payload 较大，略降权避免阻塞测试

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        n = rng.randint(50, 200)
        srv_id = rng.randint(0x0001, 0xFFFE)
        inst_id = rng.randint(0x0001, 0xFFFE)

        # 单个 FindService Entry（16 字节）
        single_entry = struct.pack(
            ">BBBBHH",
            0x00,   # FindService
            0x00, 0x00, 0x00,  # Index/Num opts
            srv_id, inst_id,
        ) + b"\xFF\x00\xFF\xFF" + b"\xFF\xFF\xFF\xFF"  # major/ttl + minor (any version)

        entry_array = single_entry * n
        entry_array_len = len(entry_array)

        sd_payload = struct.pack(
            ">BBBBI",
            0xC0, 0x00, 0x00, 0x00,
            entry_array_len,
        ) + entry_array + struct.pack(">I", 0)

        someip_len = 8 + len(sd_payload)
        raw = struct.pack(
            ">HHIBBBBBBBB",
            SD_SERVICE_ID, SD_METHOD_ID,
            someip_len,
            0x00, 0x01,    # client_id
            0x00, 0x01,    # session_id
            0x01, 0x01, 0x02, 0x00,  # proto/iface/type/rc
        ) + sd_payload

        return self._make_raw_result(raw, entry_count=n, payload_size=len(raw))


@register_mutator
class SdOptionIndexOobMutator(BaseMutator):
    """L2-SD04：将 Entry 的 Option Index 字段设为越界值。

    SD Entry 中的 Index 1st/2nd Option 字段指向 Option Array 的索引；
    若索引超出 Option Array 实际元素数，触发越界访问。
    """

    name = "L2-SD04.option_index_oob"
    layer = 2
    target_field = "sd_option_index"
    strategy = "option_index_oob"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        raw = bytearray(_make_base_sd_raw(rng))
        pay_off = _sd_payload_offset()
        entry_start = pay_off + 8
        if len(raw) >= entry_start + SD_ENTRY_LEN:
            # Index 1st option (byte 2) = 越界值（Option Array 通常只有 0-3 个 option）
            oob_index = rng.randint(10, 0xFF)
            raw[entry_start + SD_INDEX1_OFFSET] = oob_index
            raw[entry_start + SD_INDEX2_OFFSET] = oob_index
            return self._make_raw_result(bytes(raw), oob_index=oob_index)
        return self._make_raw_result(bytes(raw), skipped=True)


@register_mutator
class SdEndpointInvalidIpMutator(BaseMutator):
    """L2-SD05：将 SD Endpoint Option 中的 IP 地址改为无效值。

    合法的 Endpoint Option IP 地址应是单播地址；
    改为 0.0.0.0（未指定地址）或 255.255.255.255（广播）
    触发连接建立失败或路由异常。
    """

    name = "L2-SD05.endpoint_invalid_ip"
    layer = 2
    target_field = "sd_endpoint_ip"
    strategy = "endpoint_invalid_ip"

    _INVALID_IPS = [
        b"\x00\x00\x00\x00",    # 0.0.0.0（未指定地址）
        b"\xff\xff\xff\xff",    # 255.255.255.255（受限广播）
        b"\x7f\x00\x00\x01",   # 127.0.0.1（loopback，跨机不可达）
        b"\xe0\x00\x00\x01",   # 224.0.0.1（多播地址）
    ]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        raw = bytearray(_make_base_sd_raw(rng))
        pay_off = _sd_payload_offset()

        # 找到 Option Array 起始位置
        # Entry Array Length 在 SD payload 偏移 4 处
        if len(raw) < pay_off + 8:
            return self._make_raw_result(bytes(raw), skipped=True)
        entry_array_len = struct.unpack(">I", raw[pay_off + 4:pay_off + 8])[0]
        opt_array_start = pay_off + 8 + entry_array_len + 4  # +4: skip option array length field

        if len(raw) >= opt_array_start + SD_OPT_IP_OFFSET + 4:
            invalid_ip = rng.choice(self._INVALID_IPS)
            raw[opt_array_start + SD_OPT_IP_OFFSET:opt_array_start + SD_OPT_IP_OFFSET + 4] = invalid_ip
            return self._make_raw_result(bytes(raw), invalid_ip=".".join(str(b) for b in invalid_ip))
        return self._make_raw_result(bytes(raw), skipped=True)


@register_mutator
class SdEndpointPortZeroMutator(BaseMutator):
    """L2-SD06：将 SD Endpoint Option 中的端口号改为 0。

    TCP/UDP 端口 0 通常由 OS 动态分配，不可用于监听；
    服务端尝试连接端口 0 的端点会立即失败，测试错误处理路径。
    """

    name = "L2-SD06.endpoint_port_zero"
    layer = 2
    target_field = "sd_endpoint_port"
    strategy = "endpoint_port_zero"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        raw = bytearray(_make_base_sd_raw(rng))
        pay_off = _sd_payload_offset()

        if len(raw) < pay_off + 8:
            return self._make_raw_result(bytes(raw), skipped=True)
        entry_array_len = struct.unpack(">I", raw[pay_off + 4:pay_off + 8])[0]
        opt_array_start = pay_off + 8 + entry_array_len + 4

        if len(raw) >= opt_array_start + SD_OPT_PORT_OFFSET + 2:
            raw[opt_array_start + SD_OPT_PORT_OFFSET:opt_array_start + SD_OPT_PORT_OFFSET + 2] = b"\x00\x00"
            return self._make_raw_result(bytes(raw), port=0)
        return self._make_raw_result(bytes(raw), skipped=True)


@register_mutator
class SdTtlOverflowMutator(BaseMutator):
    """L2-SD07：将 SD Entry 的 TTL 字段（3 字节 big-endian）改为最大值 0xFFFFFF。

    TTL 表示 SD 条目的有效期（秒）；0xFFFFFF 约等于 194 天，
    触发服务生命周期管理中的整数溢出或 wrap-around 判断错误。
    """

    name = "L2-SD07.ttl_overflow"
    layer = 2
    target_field = "sd_ttl"
    strategy = "ttl_overflow"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        raw = bytearray(_make_base_sd_raw(rng))
        pay_off = _sd_payload_offset()
        entry_start = pay_off + 8
        # TTL 在 Entry 第 5、6、7 字节（偏移 4 后的大端 3 字节）
        # Entry 结构：Type(1)+Index1(1)+Index2(1)+Num1Num2(1)+SrvId(2)+InstId(2)+MajorVer(1)+TTL(3)+Minor(4)
        ttl_offset = entry_start + 9  # 1+1+1+1+2+2+1 = 9
        if len(raw) >= ttl_offset + 3:
            raw[ttl_offset:ttl_offset + 3] = b"\xFF\xFF\xFF"
            return self._make_raw_result(bytes(raw), ttl=0xFFFFFF)
        return self._make_raw_result(bytes(raw), skipped=True)


@register_mutator
class SdMajorMinorSwapMutator(BaseMutator):
    """L2-SD08：交换 SD Entry 中的 Major Version 和 Minor Version 字节内容。

    Major Version (1B) 和 Minor Version (4B little-endian) 的语义完全不同；
    互换后服务端版本匹配逻辑看到错误的版本号，触发版本不兼容拒绝或降级处理。
    """

    name = "L2-SD08.major_minor_swap"
    layer = 2
    target_field = "sd_version"
    strategy = "major_minor_swap"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        raw = bytearray(_make_base_sd_raw(rng))
        pay_off = _sd_payload_offset()
        entry_start = pay_off + 8
        # Entry 结构：Type(1)+Idx1(1)+Idx2(1)+N(1)+SrvId(2)+InstId(2)+MajorVer(1)+TTL(3)+MinorVer(4)
        # MajorVer: entry_start + 8
        # TTL:      entry_start + 9~11
        # MinorVer: entry_start + 12~15
        major_off = entry_start + 8
        minor_off = entry_start + 12
        if len(raw) >= minor_off + 4:
            orig_major = raw[major_off]
            orig_minor = raw[minor_off:minor_off + 4]
            # 将 Major(1B) 替换为 Minor 的第 1 字节，Minor 替换为 Major 扩展的 4 字节
            raw[major_off] = orig_minor[0]
            raw[minor_off:minor_off + 4] = bytes([orig_major, 0x00, 0x00, 0x00])
            return self._make_raw_result(
                bytes(raw),
                original_major=orig_major,
                original_minor=int.from_bytes(orig_minor, "little"),
            )
        return self._make_raw_result(bytes(raw), skipped=True)

"""Layer 1.8 Payload 变异器（12 种）。

对 SOME/IP 报文的 payload 字段进行变异，覆盖随机 / 翻转 / 边界填充 /
溢出 / 截断 / 魔数 / 嵌套 / 编码混合等典型攻击向量。

所有变异器均使用 ``_make_result()`` 构造：payload 变更后仍是合法 SomeIpPacket，
scapy 会自动重算 Length，无需走字节级路径。

设计原则：
- L1-P05 overflow_huge 设 1MB 上限防止靶机 OOM（超出则截到 1MB）。
- 空 payload 种子统一处理：能生成则生成，不能则操作空字节串（不 crash）。
"""

from __future__ import annotations

import dataclasses
import random
import struct

from someip_fuzzer.core.mutator import BaseMutator, MutationResult, register_mutator
from someip_fuzzer.core.protocol import SomeIpPacket

# 1MB 上限（防靶机 OOM）
MAX_PAYLOAD_BYTES = 1024 * 1024

# 已知可触发崩溃的魔数序列（FSB、堆溢出、整数溢出常见前置值）
_KNOWN_MAGIC = [
    b"\xde\xad\xbe\xef",
    b"\xca\xfe\xba\xbe",
    b"\xff\xff\xff\xff",
    b"\x00\x00\x00\x00",
    b"\x41\x41\x41\x41",   # AAAA（经典栈溢出 canary）
    b"\x7f\x45\x4c\x46",   # ELF magic
    b"%n%n%n%n",            # format string
    b"\x00" * 8,
    b"\xff" * 8,
]


# ── L1-P01 ~ L1-P12：Payload 变异 ────────────────────────────────────────────


@register_mutator
class PayloadRandomBytesMutator(BaseMutator):
    """L1-P01：用完全随机字节替换 payload（广撒网）。

    长度与原 payload 一致；若原长度为 0 则生成 16 字节随机数据。
    """

    name = "L1-P01.random_bytes"
    layer = 1
    target_field = "payload"
    strategy = "random_bytes"
    weight = 0.5

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        n = max(len(seed.payload), 16)
        new_payload = bytes(rng.randint(0, 255) for _ in range(n))
        return self._make_result(dataclasses.replace(seed, payload=new_payload))


@register_mutator
class PayloadBitFlip1Mutator(BaseMutator):
    """L1-P02：翻转 payload 内 1 个随机 bit（邻近变异）。

    若 payload 为空则注入 1 字节随机数据再翻 bit。
    """

    name = "L1-P02.bit_flip_1"
    layer = 1
    target_field = "payload"
    strategy = "bit_flip_1"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        payload = seed.payload if seed.payload else bytes([rng.randint(0, 255)])
        ba = bytearray(payload)
        byte_idx = rng.randint(0, len(ba) - 1)
        bit_idx = rng.randint(0, 7)
        ba[byte_idx] ^= 1 << bit_idx
        return self._make_result(
            dataclasses.replace(seed, payload=bytes(ba)),
            flipped_byte=byte_idx, flipped_bit=bit_idx,
        )


@register_mutator
class PayloadBitFlipNMutator(BaseMutator):
    """L1-P03：翻转 payload 内 2~8 个随机 bit（大幅变异）。

    若 payload 为空则注入 4 字节随机数据。
    """

    name = "L1-P03.bit_flip_n"
    layer = 1
    target_field = "payload"
    strategy = "bit_flip_n"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        payload = seed.payload if seed.payload else bytes([rng.randint(0, 255)] * 4)
        ba = bytearray(payload)
        n = rng.randint(2, min(8, len(ba) * 8))
        positions = rng.sample(range(len(ba) * 8), n)
        for pos in positions:
            ba[pos // 8] ^= 1 << (pos % 8)
        return self._make_result(
            dataclasses.replace(seed, payload=bytes(ba)),
            flipped_count=n,
        )


@register_mutator
class PayloadByteBoundaryMutator(BaseMutator):
    """L1-P04：用边界字节（0x00/0xFF/0x7F/0x80）填充 payload 随机选中的区段。

    边界字节组合常触发整数比较/符号扩展边界条件。
    """

    name = "L1-P04.byte_boundary"
    layer = 1
    target_field = "payload"
    strategy = "byte_boundary"

    _BOUNDARY_BYTES = [0x00, 0xFF, 0x7F, 0x80]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        n = max(len(seed.payload), 8)
        fill_byte = rng.choice(self._BOUNDARY_BYTES)
        new_payload = bytes([fill_byte] * n)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            fill_byte=fill_byte, length=n,
        )


@register_mutator
class PayloadOverflowHugeMutator(BaseMutator):
    """L1-P05：超大 payload（1MB），测试靶机缓冲区分配上限。

    上限 ``MAX_PAYLOAD_BYTES=1MB``，避免本机 / 靶机 OOM。
    用随机字节填充，兼测解析器循环逃逸能力。
    """

    name = "L1-P05.overflow_huge"
    layer = 1
    target_field = "payload"
    strategy = "overflow_huge"
    weight = 0.3  # 超大包降权，防止一次测试长时间阻塞

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        size = min(MAX_PAYLOAD_BYTES, rng.randint(65536, MAX_PAYLOAD_BYTES))
        # 用随机字节前 256B + 重复填充，减少生成耗时
        chunk = bytes(rng.randint(0, 255) for _ in range(256))
        new_payload = (chunk * (size // 256 + 1))[:size]
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            payload_size=size,
        )


@register_mutator
class PayloadTruncateZeroMutator(BaseMutator):
    """L1-P06：截断为空 payload（0 字节）。

    空 payload 触发服务端"零长度数据"处理分支，常见空指针或除零漏洞。
    """

    name = "L1-P06.truncate_zero"
    layer = 1
    target_field = "payload"
    strategy = "truncate_zero"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        return self._make_result(
            dataclasses.replace(seed, payload=b""),
            original_len=len(seed.payload),
        )


@register_mutator
class PayloadTruncatePartialMutator(BaseMutator):
    """L1-P07：截断到原始长度的约 1/2（不完整数据攻击）。

    服务端若按固定偏移读取 payload 字段，截断后会访问越界。
    若原长度 ≤ 2 字节则截断到 0 字节。
    """

    name = "L1-P07.truncate_partial"
    layer = 1
    target_field = "payload"
    strategy = "truncate_partial"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        half = len(seed.payload) // 2
        new_payload = seed.payload[:half]
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            original_len=len(seed.payload), truncated_len=half,
        )


@register_mutator
class PayloadKnownMagicMutator(BaseMutator):
    """L1-P08：注入已知可触发崩溃的魔数序列（覆盖或追加到 payload 头部）。

    魔数来源：格式串攻击 / ELF magic / 栈溢出 canary / 堆损坏模式等。
    """

    name = "L1-P08.known_magic"
    layer = 1
    target_field = "payload"
    strategy = "known_magic"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        magic = rng.choice(_KNOWN_MAGIC)
        # 用魔数替换 payload 前若干字节（不足则全部替换）
        if len(seed.payload) >= len(magic):
            new_payload = magic + seed.payload[len(magic):]
        else:
            new_payload = magic
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            magic=magic.hex(),
        )


@register_mutator
class PayloadRepeatedPatternMutator(BaseMutator):
    """L1-P09：用重复字节模式（如 AAAA...）填充 payload。

    重复模式触发解析器"连续字节"边界，常用于验证偏移量计算
    与栈/堆溢出检测（金丝雀污染）。
    """

    name = "L1-P09.repeated_pattern"
    layer = 1
    target_field = "payload"
    strategy = "repeated_pattern"

    _PATTERNS = [b"\xAA", b"\xBB", b"\xCC", b"\xDD\xEE", b"\x41\x42\x43\x44"]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        n = max(len(seed.payload), 16)
        pat = rng.choice(self._PATTERNS)
        new_payload = (pat * (n // len(pat) + 1))[:n]
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            pattern=pat.hex(), length=n,
        )


@register_mutator
class PayloadNestedStructureMutator(BaseMutator):
    """L1-P10：在 payload 头部嵌套一个合法 SOME/IP header（结构嵌套破坏）。

    若服务端对 payload 做递归解析（如 SOME/IP over SOME/IP 通道），
    嵌套的合法 header 可欺骗解析器进入错误分支；
    若不处理则 payload 前 16 字节被误解析为协议头。
    """

    name = "L1-P10.nested_structure"
    layer = 1
    target_field = "payload"
    strategy = "nested_structure"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        # 构造一个内层 SOME/IP header（service_id 随机，payload 空）
        inner_sid = rng.randint(0, 0xFFFF)
        inner_mid = rng.randint(0, 0x7FFF)
        inner_hdr = struct.pack(
            ">HHIBBBB",
            inner_sid, inner_mid,  # service_id, method_id
            8,                      # length（无 payload）
            0, 1,                   # client_id hi/lo
            0, 1,                   # session_id hi/lo
        ) + bytes([0x01, 0x01, 0x00, 0x00])  # proto_ver, iface_ver, msg_type, retcode
        new_payload = inner_hdr + seed.payload
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            inner_service=inner_sid, inner_method=inner_mid,
        )


@register_mutator
class PayloadEncodingMixMutator(BaseMutator):
    """L1-P11：在 payload 中注入多种编码的混合字节序列。

    混合编码包含 UTF-8 BOM、Latin-1 高字节、UTF-16 代理对字节等，
    触发服务端字符串处理时的编码检测/转换错误或异常未捕获。
    """

    name = "L1-P11.encoding_mix"
    layer = 1
    target_field = "payload"
    strategy = "encoding_mix"

    _MIX = (
        b"\xef\xbb\xbf"          # UTF-8 BOM
        + b"\xff\xfe"             # UTF-16 LE BOM
        + b"\x00\x00\xfe\xff"     # UTF-32 BE BOM
        + b"\xc0\x80"             # overlong null in CESU-8
        + b"\xed\xa0\x80"         # surrogate U+D800 in UTF-8
        + b"\x80\x81\x82\x83"     # Latin-1 high bytes
        + b"\x00" * 4             # embedded nulls
    )

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        mix_offset = rng.randint(0, max(0, len(seed.payload)))
        new_payload = seed.payload[:mix_offset] + self._MIX + seed.payload[mix_offset:]
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            inject_offset=mix_offset,
        )


@register_mutator
class PayloadSequentialBytesMutator(BaseMutator):
    """L1-P12：用顺序递增字节序列（0x00, 0x01, 0x02...）填充 payload。

    顺序序列便于定位崩溃偏移（类似 cyclic pattern），同时测试
    "非随机数据"路径下的解析器行为。
    """

    name = "L1-P12.sequential_bytes"
    layer = 1
    target_field = "payload"
    strategy = "sequential_bytes"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        n = max(len(seed.payload), 16)
        start = rng.randint(0, 0xFF)
        new_payload = bytes((start + i) & 0xFF for i in range(n))
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            start_byte=start, length=n,
        )

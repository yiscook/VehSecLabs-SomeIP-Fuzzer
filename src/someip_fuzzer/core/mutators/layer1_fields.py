"""Layer 1 字段级变异器：SOME/IP header 各字段的边界 / 随机 / 翻转 / 交换变异。

涵盖 SPEC §2.3 的 Layer 1.1-1.7（共 53 - 12 = 41 种 = Service ID 8 + Method ID 6 +
Length 7 + Client/Session 5 + Version 4 + MsgType 6 + RetCode 5）。

────────────────────────────────────────────────────────────────────────────────
代码模板（后续所有 Layer 1 变异器都遵守）：

1. 类名：``<TargetField><Strategy>Mutator``，例如 ``ServiceIdBoundaryMinMutator``
2. 装饰器：``@register_mutator``，写在 class 行上方
3. ClassVar 顺序固定：``name`` / ``layer`` / ``target_field`` / ``strategy``
   （可选 ``weight``，默认 1.0；高/低危值在 configs/strategies.toml 调整即可）
4. ``name`` 格式：``L<layer>-<abbr><NN>.<strategy>``
   - 缩写：S=Service, M=Method, L=Length, C=Client/Session, V=Version,
     T=MsgType, R=RetCode, P=Payload；后续 Layer 2 用：T=Type, V=TLV,
     S=String, E=Endian, C=Constraint, SD=Service Discovery
   - 编号：组内从 01 递增，与 SPEC §2.3 表格一致
   - strategy 字段值与 ``name`` 末段保持一致（避免不同步）
5. ``mutate(self, seed, rng)`` 实现：
   - 用 ``dataclasses.replace(seed, ...)`` 浅拷贝改字段（不要直接改 seed）
   - 用 ``rng`` 而非全局 ``random``（确保可重放）
   - 通过 ``self._make_result(new)`` 返回（合法变异）
   - 字节级变异（如 Length 溢出）用 ``self._make_raw_result(raw_bytes)``
6. docstring 必须说明：变异内容 + 预期触发什么类型的服务端缺陷
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import dataclasses
import random

from someip_fuzzer.core.mutator import BaseMutator, MutationResult, register_mutator
from someip_fuzzer.core.protocol import SomeIpPacket

# ── 常量 ─────────────────────────────────────────────────────────────────────

# Service ID 取值范围（来自 SOME/IP 规范 ISO 17215-2 / AUTOSAR PRS_SOMEIPProtocol）
SERVICE_ID_MIN = 0x0000
SERVICE_ID_MAX = 0xFFFF
SERVICE_ID_RESERVED_LO = 0xFF00  # 0xFF00-0xFFFE 为协议保留域
SERVICE_ID_RESERVED_HI = 0xFFFE
SERVICE_ID_BITS = 16


# ── L1-S01 ~ L1-S08：Service ID 变异（8 种） ─────────────────────────────────


@register_mutator
class ServiceIdBoundaryMinMutator(BaseMutator):
    """L1-S01：Service ID 设为最小边界值 0x0000。

    预期触发：服务路由对 ID=0 的特殊处理分支、未初始化字段检查、整数溢出前置条件。
    """

    name = "L1-S01.boundary_min"
    layer = 1
    target_field = "service_id"
    strategy = "boundary_min"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, service_id=SERVICE_ID_MIN)
        return self._make_result(new)


@register_mutator
class ServiceIdBoundaryMaxMutator(BaseMutator):
    """L1-S02：Service ID 设为最大边界值 0xFFFF。

    预期触发：服务表越界、uint16 溢出、保留域校验缺失。
    """

    name = "L1-S02.boundary_max"
    layer = 1
    target_field = "service_id"
    strategy = "boundary_max"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, service_id=SERVICE_ID_MAX)
        return self._make_result(new)


@register_mutator
class ServiceIdBoundaryMaxMinus1Mutator(BaseMutator):
    """L1-S03：Service ID 设为 0xFFFE（最大-1）。

    用于探测"最后一个有效 ID"边界条件，常被 off-by-one 错误命中。
    """

    name = "L1-S03.boundary_max_minus_1"
    layer = 1
    target_field = "service_id"
    strategy = "boundary_max_minus_1"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, service_id=SERVICE_ID_MAX - 1)
        return self._make_result(new)


@register_mutator
class ServiceIdReservedRangeMutator(BaseMutator):
    """L1-S04：Service ID 取协议保留域 [0xFF00, 0xFFFE] 内的随机值。

    SOME/IP 规范保留 0xFF00-0xFFFF；多数实现应拒绝处理，未拒绝即为缺陷。
    """

    name = "L1-S04.reserved_range"
    layer = 1
    target_field = "service_id"
    strategy = "reserved_range"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = rng.randint(SERVICE_ID_RESERVED_LO, SERVICE_ID_RESERVED_HI)
        new = dataclasses.replace(seed, service_id=new_id)
        return self._make_result(new, chosen_value=new_id)


@register_mutator
class ServiceIdRandomUniformMutator(BaseMutator):
    """L1-S05：Service ID 取 [0x0000, 0xFFFF] 内的均匀随机值（广撒网）。

    权重默认降至 0.5，避免淹没定向边界变异；可在 strategies.toml 调整。
    """

    name = "L1-S05.random_uniform"
    layer = 1
    target_field = "service_id"
    strategy = "random_uniform"
    weight = 0.5

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = rng.randint(SERVICE_ID_MIN, SERVICE_ID_MAX)
        new = dataclasses.replace(seed, service_id=new_id)
        return self._make_result(new, chosen_value=new_id)


@register_mutator
class ServiceIdBitFlipSingleMutator(BaseMutator):
    """L1-S06：单 bit 翻转 — 随机翻转 service_id 的 1 个 bit。

    适合"邻近变异"：与原 ID 仅差 1 bit，常用于配合崩溃用例最小化。
    """

    name = "L1-S06.bit_flip_single"
    layer = 1
    target_field = "service_id"
    strategy = "bit_flip_single"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        bit = rng.randint(0, SERVICE_ID_BITS - 1)
        new_id = (seed.service_id ^ (1 << bit)) & SERVICE_ID_MAX
        new = dataclasses.replace(seed, service_id=new_id)
        return self._make_result(new, flipped_bit=bit)


@register_mutator
class ServiceIdBitFlipMultipleMutator(BaseMutator):
    """L1-S07：多 bit 翻转 — 同时翻转 service_id 的 2~5 个不同 bit（大幅变异）。

    与 S06 互补：覆盖更大的 ID 空间扰动，触发"远距离"邻近缺陷。
    """

    name = "L1-S07.bit_flip_multiple"
    layer = 1
    target_field = "service_id"
    strategy = "bit_flip_multiple"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        n = rng.randint(2, 5)
        bits = rng.sample(range(SERVICE_ID_BITS), n)
        mask = 0
        for b in bits:
            mask |= 1 << b
        new_id = (seed.service_id ^ mask) & SERVICE_ID_MAX
        new = dataclasses.replace(seed, service_id=new_id)
        return self._make_result(new, flipped_bits=tuple(sorted(bits)))


@register_mutator
class ServiceIdSwapWithMethodIdMutator(BaseMutator):
    """L1-S08：Service ID ↔ Method ID 互换（字段混淆攻击）。

    部分实现把 (service_id, method_id) 合并成 32-bit message_id 处理；
    互换后 message_id 仍合法，但 (service, method) 解析会进入错误分支。
    """

    name = "L1-S08.swap_with_method_id"
    layer = 1
    target_field = "service_id"
    strategy = "swap_with_method_id"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(
            seed,
            service_id=seed.method_id & SERVICE_ID_MAX,
            method_id=seed.service_id & SERVICE_ID_MAX,
        )
        return self._make_result(
            new,
            original_service=seed.service_id,
            original_method=seed.method_id,
        )


# ── L1-M01 ~ L1-M06：Method/Event ID 变异（6 种） ────────────────────────────
# SOME/IP 规范：method_id bit15=0 表示方法(Method)，bit15=1 表示事件(Event)
# Method 范围：0x0001-0x7FFF；Event 范围：0x8001-0xFFFF

METHOD_ID_MAX = 0xFFFF
METHOD_ID_METHOD_MAX = 0x7FFF    # Method 上边界
METHOD_ID_EVENT_MIN = 0x8000    # Event 下边界
METHOD_ID_RESERVED_METHOD_LO = 0x7F00  # 方法 ID 保留段低端
METHOD_ID_TP_BIT = 0x8000       # bit15：0=方法 / 1=事件


@register_mutator
class MethodIdFlipEventMethodBitMutator(BaseMutator):
    """L1-M01：翻转 method_id 的 bit15（Method ↔ Event 类型互换）。

    将方法报文伪装成事件报文（或相反），触发服务端类型判断逻辑错误。
    """

    name = "L1-M01.flip_event_method_bit"
    layer = 1
    target_field = "method_id"
    strategy = "flip_event_method_bit"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = (seed.method_id ^ METHOD_ID_TP_BIT) & METHOD_ID_MAX
        new = dataclasses.replace(seed, method_id=new_id)
        return self._make_result(new, original_method=seed.method_id, flipped_id=new_id)


@register_mutator
class MethodIdBoundaryMethodMutator(BaseMutator):
    """L1-M02：Method ID 设为方法域边界值（0x0000 或 0x7FFF，随机选一）。"""

    name = "L1-M02.boundary_method"
    layer = 1
    target_field = "method_id"
    strategy = "boundary_method"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = rng.choice([0x0000, METHOD_ID_METHOD_MAX])
        return self._make_result(dataclasses.replace(seed, method_id=new_id), chosen=new_id)


@register_mutator
class MethodIdBoundaryEventMutator(BaseMutator):
    """L1-M03：Method ID 设为事件域边界值（0x8000 或 0xFFFF，随机选一）。"""

    name = "L1-M03.boundary_event"
    layer = 1
    target_field = "method_id"
    strategy = "boundary_event"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = rng.choice([METHOD_ID_EVENT_MIN, METHOD_ID_MAX])
        return self._make_result(dataclasses.replace(seed, method_id=new_id), chosen=new_id)


@register_mutator
class MethodIdRandomMethodMutator(BaseMutator):
    """L1-M04：Method ID 取方法域 [0x0001, 0x7FFF] 内随机值（广撒网）。"""

    name = "L1-M04.random_method"
    layer = 1
    target_field = "method_id"
    strategy = "random_method"
    weight = 0.5

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = rng.randint(0x0001, METHOD_ID_METHOD_MAX)
        return self._make_result(dataclasses.replace(seed, method_id=new_id), chosen=new_id)


@register_mutator
class MethodIdRandomEventMutator(BaseMutator):
    """L1-M05：Method ID 取事件域 [0x8001, 0xFFFF] 内随机值（广撒网）。"""

    name = "L1-M05.random_event"
    layer = 1
    target_field = "method_id"
    strategy = "random_event"
    weight = 0.5

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = rng.randint(METHOD_ID_EVENT_MIN + 1, METHOD_ID_MAX)
        return self._make_result(dataclasses.replace(seed, method_id=new_id), chosen=new_id)


@register_mutator
class MethodIdReservedRangeMutator(BaseMutator):
    """L1-M06：Method ID 取保留段 [0x7F00, 0x7FFF] 内随机值。

    该区段在 SOME/IP 规范中标注为保留/供应商自定义；多数实现应拒绝。
    """

    name = "L1-M06.reserved_range"
    layer = 1
    target_field = "method_id"
    strategy = "reserved_range"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = rng.randint(METHOD_ID_RESERVED_METHOD_LO, METHOD_ID_METHOD_MAX)
        return self._make_result(dataclasses.replace(seed, method_id=new_id), chosen=new_id)


# ── L1-C01 ~ L1-C05：Client/Session ID 变异（5 种） ──────────────────────────

SESSION_ID_MAX = 0xFFFF
CLIENT_ID_MAX = 0xFFFF


@register_mutator
class SessionIdReplayMutator(BaseMutator):
    """L1-C01：Session ID 重放 — 将 session_id 重置为 1（模拟重放攻击）。

    SOME/IP 规范要求 Request/Response 对的 session_id 必须匹配；
    重放 session_id=1 会触发旧请求/响应混淆漏洞。
    """

    name = "L1-C01.session_replay"
    layer = 1
    target_field = "session_id"
    strategy = "session_replay"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, session_id=1)
        return self._make_result(new, original_session=seed.session_id)


@register_mutator
class SessionIdSkipMutator(BaseMutator):
    """L1-C02：Session ID 跳跃 — 将 session_id 向前大幅跳跃（模拟序列号预测）。

    大幅跳跃的 session_id 可触发服务端序列号验证绕过或计数器溢出。
    """

    name = "L1-C02.session_skip"
    layer = 1
    target_field = "session_id"
    strategy = "session_skip"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        skip = rng.randint(100, 10000)
        new_id = (seed.session_id + skip) & SESSION_ID_MAX
        new = dataclasses.replace(seed, session_id=new_id)
        return self._make_result(new, original_session=seed.session_id, skip=skip)


@register_mutator
class SessionIdZeroMutator(BaseMutator):
    """L1-C03：Session ID 设为 0。

    SOME/IP 规范规定 session_id=0 为无效值（Request/Response 必须 ≥ 1）；
    多数实现对此缺乏校验。
    """

    name = "L1-C03.session_zero"
    layer = 1
    target_field = "session_id"
    strategy = "session_zero"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, session_id=0)
        return self._make_result(new)


@register_mutator
class ClientIdRandomMutator(BaseMutator):
    """L1-C04：Client ID 随机化 — 取 [0, 0xFFFF] 内随机值。

    触发服务端客户端权限/路由表查询错误分支。
    """

    name = "L1-C04.client_random"
    layer = 1
    target_field = "client_id"
    strategy = "client_random"
    weight = 0.5

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = rng.randint(0, CLIENT_ID_MAX)
        new = dataclasses.replace(seed, client_id=new_id)
        return self._make_result(new, chosen=new_id)


@register_mutator
class ClientIdCollisionMutator(BaseMutator):
    """L1-C05：Client ID 碰撞 — 将 client_id 设为广播值 0xFFFF（模拟 ID 冲突）。

    0xFFFF 有时被用作广播/通配 client_id；触发多客户端场景下的路由冲突。
    """

    name = "L1-C05.client_collision"
    layer = 1
    target_field = "client_id"
    strategy = "client_collision"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, client_id=CLIENT_ID_MAX)
        return self._make_result(new, original_client=seed.client_id)


# ── L1-V01 ~ L1-V04：Protocol/Interface Version 变异（4 种） ─────────────────


@register_mutator
class ProtoVersionZeroMutator(BaseMutator):
    """L1-V01：Protocol Version 设为 0x00（无效版本号）。

    SOME/IP 规范要求 Protocol Version = 0x01；0x00 应触发版本校验拒绝。
    """

    name = "L1-V01.proto_zero"
    layer = 1
    target_field = "protocol_version"
    strategy = "proto_zero"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, protocol_version=0x00)
        return self._make_result(new)


@register_mutator
class ProtoVersionMaxMutator(BaseMutator):
    """L1-V02：Protocol Version 设为 0xFF（超出规范最大值）。

    触发版本比较越界或未来版本协商逻辑缺陷。
    """

    name = "L1-V02.proto_max"
    layer = 1
    target_field = "protocol_version"
    strategy = "proto_max"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, protocol_version=0xFF)
        return self._make_result(new)


@register_mutator
class IfaceVersionMismatchMutator(BaseMutator):
    """L1-V03：Interface Version 与 Protocol Version 不匹配（随机错误版本）。

    interface_version 是服务特定的；设错版本触发版本协商失败或静默丢包。
    """

    name = "L1-V03.iface_mismatch"
    layer = 1
    target_field = "interface_version"
    strategy = "iface_mismatch"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        # 选一个与当前不同的版本值
        orig = seed.interface_version
        candidates = [v for v in [0x00, 0x02, 0x7F, 0xFF] if v != orig]
        new_ver = rng.choice(candidates) if candidates else (orig ^ 0xFF) & 0xFF
        new = dataclasses.replace(seed, interface_version=new_ver)
        return self._make_result(new, original_iface=orig, chosen=new_ver)


@register_mutator
class BothVersionsRandomMutator(BaseMutator):
    """L1-V04：Protocol Version 和 Interface Version 同时随机化。

    双版本同时错误，绕过只检查一个字段的实现。
    """

    name = "L1-V04.both_random"
    layer = 1
    target_field = "protocol_version"
    strategy = "both_random"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pv = rng.randint(0, 0xFF)
        iv = rng.randint(0, 0xFF)
        new = dataclasses.replace(seed, protocol_version=pv, interface_version=iv)
        return self._make_result(new, proto=pv, iface=iv)


# ── L1-T01 ~ L1-T06：Message Type 变异（6 种） ───────────────────────────────
# 合法值：0x00 REQUEST / 0x01 REQUEST_NO_RETURN / 0x02 NOTIFICATION /
#         0x20 TP_REQUEST / 0x40 REQUEST_ACK / 0x41 REQUEST_NO_RETURN_ACK /
#         0x42 NOTIFICATION_ACK / 0x80 RESPONSE / 0x81 ERROR / 0xA0 TP_RESPONSE
# 其余均未定义

_UNDEFINED_MSG_TYPES = [0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x30, 0x50, 0x60, 0x70,
                         0x82, 0x90, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0]
_TP_BIT = 0x20  # TP 分段标志位


@register_mutator
class MsgTypeInvalidMutator(BaseMutator):
    """L1-T01：Message Type 设为未定义值（如 0x07、0x10）。

    触发服务端消息类型 switch 的 default/unknown 分支，暴露未处理情况下的资源泄露。
    """

    name = "L1-T01.invalid_type"
    layer = 1
    target_field = "message_type"
    strategy = "invalid_type"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_type = rng.choice(_UNDEFINED_MSG_TYPES)
        new = dataclasses.replace(seed, message_type=new_type)
        return self._make_result(new, chosen_type=new_type)


@register_mutator
class MsgTypeRetcodeMismatchMutator(BaseMutator):
    """L1-T02：Request 类型配 Error 返回码（语义矛盾）。

    SOME/IP 规范要求 Request 的 return_code = E_OK (0x00)；
    填 E_NOT_OK (0x01) 会触发返回码与消息类型联合校验缺失的实现漏洞。
    """

    name = "L1-T02.type_retcode_mismatch"
    layer = 1
    target_field = "message_type"
    strategy = "type_retcode_mismatch"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, message_type=0x00, return_code=0x01)  # REQUEST + E_NOT_OK
        return self._make_result(new)


@register_mutator
class MsgTypeTpFlagInjectMutator(BaseMutator):
    """L1-T03：向 message_type 注入 TP 分段位（0x20）。

    对非 TP 报文的 message_type OR 0x20 得到伪 TP 报文，
    触发 TP 解析器误入 TP 分支导致的缓冲区操作异常。
    """

    name = "L1-T03.tp_flag_inject"
    layer = 1
    target_field = "message_type"
    strategy = "tp_flag_inject"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_type = (int(seed.message_type) | _TP_BIT) & 0xFF
        new = dataclasses.replace(seed, message_type=new_type)
        return self._make_result(new, original_type=int(seed.message_type))


@register_mutator
class MsgTypeAckWithoutRequestMutator(BaseMutator):
    """L1-T04：发送无前置请求的 ACK（REQUEST_ACK = 0x40）。

    触发服务端 ACK 状态机"未找到对应请求"的异常处理路径。
    """

    name = "L1-T04.ack_without_request"
    layer = 1
    target_field = "message_type"
    strategy = "ack_without_request"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, message_type=0x40)  # REQUEST_ACK
        return self._make_result(new)


@register_mutator
class MsgTypeForceErrorMutator(BaseMutator):
    """L1-T05：强制 message_type = ERROR（0x81）。

    模拟服务端误收客户端发出的 ERROR 报文，触发双方状态机混乱。
    """

    name = "L1-T05.error_type"
    layer = 1
    target_field = "message_type"
    strategy = "error_type"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, message_type=0x81)  # ERROR
        return self._make_result(new)


@register_mutator
class MsgTypeRandomByteMutator(BaseMutator):
    """L1-T06：message_type 设为 [0x00, 0xFF] 内随机字节。"""

    name = "L1-T06.random_byte"
    layer = 1
    target_field = "message_type"
    strategy = "random_byte"
    weight = 0.5

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_type = rng.randint(0x00, 0xFF)
        new = dataclasses.replace(seed, message_type=new_type)
        return self._make_result(new, chosen_type=new_type)


# ── L1-R01 ~ L1-R05：Return Code 变异（5 种） ────────────────────────────────
# SOME/IP 规范返回码：E_OK=0x00, E_NOT_OK=0x01, E_UNKNOWN_SERVICE=0x02,
# E_UNKNOWN_METHOD=0x03, E_NOT_READY=0x04, 0x05 vendor-specific,
# 0x06-0x1F 保留，0x20+ 未定义

_RETCODE_RESERVED_LO = 0x06
_RETCODE_RESERVED_HI = 0x1F
_RETCODE_UNDEFINED_LO = 0x20


@register_mutator
class RetCodeReservedMutator(BaseMutator):
    """L1-R01：Return Code 设为规范保留段 [0x06, 0x1F] 内的随机值。

    保留码应被接收方拒绝或记录告警；未校验则暴露实现遗漏。
    """

    name = "L1-R01.reserved_code"
    layer = 1
    target_field = "return_code"
    strategy = "reserved_code"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        code = rng.randint(_RETCODE_RESERVED_LO, _RETCODE_RESERVED_HI)
        new = dataclasses.replace(seed, return_code=code)
        return self._make_result(new, chosen_code=code)


@register_mutator
class RetCodeUndefinedMutator(BaseMutator):
    """L1-R02：Return Code 设为完全未定义值（[0x20, 0xFF] 随机）。

    0x20 以上在 SOME/IP 基础规范中未定义，触发返回码处理逻辑的 default 分支。
    """

    name = "L1-R02.undefined_code"
    layer = 1
    target_field = "return_code"
    strategy = "undefined_code"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        code = rng.randint(_RETCODE_UNDEFINED_LO, 0xFF)
        new = dataclasses.replace(seed, return_code=code)
        return self._make_result(new, chosen_code=code)


@register_mutator
class RetCodeErrorWhenRequestMutator(BaseMutator):
    """L1-R03：Request 消息中携带错误码（message_type=REQUEST + return_code=E_NOT_OK）。

    语义矛盾：请求报文不应携带非 E_OK 的返回码；
    服务端若不校验则会把正常请求误判为已失败状态。
    """

    name = "L1-R03.error_when_request"
    layer = 1
    target_field = "return_code"
    strategy = "error_when_request"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, message_type=0x00, return_code=0x01)
        return self._make_result(new)


@register_mutator
class RetCodeRandomMutator(BaseMutator):
    """L1-R04：Return Code 设为 [0x00, 0xFF] 内随机值（广撒网）。"""

    name = "L1-R04.random"
    layer = 1
    target_field = "return_code"
    strategy = "random"
    weight = 0.5

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        code = rng.randint(0x00, 0xFF)
        new = dataclasses.replace(seed, return_code=code)
        return self._make_result(new, chosen_code=code)


@register_mutator
class RetCodeOkWhenErrorTypeMutator(BaseMutator):
    """L1-R05：ERROR 类型消息中携带 E_OK 返回码（语义反转）。

    ERROR 消息应携带非 E_OK 的返回码；携带 E_OK 违反规范，
    触发"成功错误"场景下的状态机混乱。
    """

    name = "L1-R05.ok_when_error_type"
    layer = 1
    target_field = "return_code"
    strategy = "ok_when_error_type"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, message_type=0x81, return_code=0x00)  # ERROR + E_OK
        return self._make_result(new)

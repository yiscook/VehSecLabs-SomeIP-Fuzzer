"""Layer 3 状态感知变异器（12 种）。

基于服务状态机的当前状态，生成违背 SOME/IP 协议状态约束的报文。
每种变异器代表一类状态违规攻击面：跳过握手、状态回退、Session 冲突等。

所有变异器遵循 BaseMutator 接口（layer=3）。
L3 变异器的 seed 用于提取 service_id / instance_id / payload 等上下文；
生成的报文是"在当前状态下发送的非法报文"，而非对 seed 的字节级修改。
"""

from __future__ import annotations

import dataclasses
import random

from someip_fuzzer.core.mutator import BaseMutator, MutationResult, register_mutator
from someip_fuzzer.core.protocol import (
    SomeIpPacket,
    build_sd_find,
    build_sd_offer,
    build_sd_stop_offer,
    build_sd_subscribe,
)


# ─────────────────────────────────────────────────────────────────────────────
# L3-01：跳过 Offer，直接 Subscribe（skip_offer_subscribe）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class SkipOfferSubscribeMutator(BaseMutator):
    """L3-01：不等待 OfferService，直接发送 SubscribeEventgroup。

    合规流程：FindService → OfferService → Subscribe。
    此变异跳过 Offer 步骤，测试服务端在 DISCOVERED/UNKNOWN 状态收到
    Subscribe 时的行为（应拒绝，但可能触发状态机崩溃）。
    """

    name = "L3-01.skip_offer_subscribe"
    layer = 3
    target_field = "state"
    strategy = "skip_offer_subscribe"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pkt = build_sd_subscribe(
            service_id=seed.service_id,
            instance_id=seed.client_id or 0x0001,
            eventgroup_id=rng.randint(0x0001, 0x00FF),
            addr="127.0.0.1",
            port=rng.randint(30000, 40000),
        )
        return self._make_result(
            pkt, violated_state="DISCOVERED", skipped_step="OfferService"
        )


# ─────────────────────────────────────────────────────────────────────────────
# L3-02：在非 READY 状态下发送 RPC 请求（rpc_before_ready）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class RpcBeforeReadyMutator(BaseMutator):
    """L3-02：服务尚未 READY 时发送 RPC 请求。

    服务端在处理尚未完成服务注册的客户端请求时，
    可能触发 E_NOT_READY 以外的异常路径（空指针、未初始化资源）。
    """

    name = "L3-02.rpc_before_ready"
    layer = 3
    target_field = "state"
    strategy = "rpc_before_ready"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pkt = SomeIpPacket.request(
            service_id=seed.service_id,
            method_id=seed.method_id & 0x7FFF,  # 确保是 Method ID（非 Event）
            payload=seed.payload or b"\x00\x00\x00\x00",
            client_id=rng.randint(0x0001, 0xFFFE),
            session_id=rng.randint(0x0001, 0xFFFE),
        )
        return self._make_result(
            pkt, violated_state="UNKNOWN/DISCOVERED", expected_state="READY"
        )


# ─────────────────────────────────────────────────────────────────────────────
# L3-03：重复 Offer 同一服务实例（duplicate_offer）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class DuplicateOfferMutator(BaseMutator):
    """L3-03：对同一服务实例重复发送 OfferService 报文。

    AUTOSAR 规范要求重复 Offer 应幂等处理，但实现可能触发
    重复注册（内存泄漏）或并发写入竞争。
    """

    name = "L3-03.duplicate_offer"
    layer = 3
    target_field = "state"
    strategy = "duplicate_offer"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pkt = build_sd_offer(
            service_id=seed.service_id,
            instance_id=seed.client_id or 0x0001,
            addr="192.168.1.1",
            port=30509,
            ttl=3,
        )
        return self._make_result(pkt, repeat_count=rng.randint(2, 10))


# ─────────────────────────────────────────────────────────────────────────────
# L3-04：StopOffer 后立即重新 Offer（offer_after_stop）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class OfferAfterStopMutator(BaseMutator):
    """L3-04：发送 StopOfferService 后立刻重新 OfferService（不等待 TTL 清理）。

    测试服务端清理/重注册路径上的竞争条件（Race Condition），
    尤其是旧实例资源未完全释放时的重叠注册。
    """

    name = "L3-04.offer_after_stop"
    layer = 3
    target_field = "state"
    strategy = "offer_after_stop"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        # 生成 StopOffer（TTL=0）后立即 Offer，取 Offer 作为最终发包
        pkt = build_sd_offer(
            service_id=seed.service_id,
            instance_id=seed.client_id or 0x0001,
            addr="192.168.1.1",
            port=30509,
            ttl=1,   # 极短 TTL，模拟快速过期后重注册
        )
        return self._make_result(
            pkt, preceded_by="StopOfferService", delay_ms=0
        )


# ─────────────────────────────────────────────────────────────────────────────
# L3-05：高频订阅/退订循环（rapid_subscribe_unsubscribe）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class RapidSubUnsubMutator(BaseMutator):
    """L3-05：快速交替发送 Subscribe 和 StopSubscribe（TTL=0 的 Subscribe）。

    模拟"订阅风暴"中的节点行为，测试服务端事件组状态表的并发更新稳定性。
    本变异器生成 Subscribe 报文，metadata 中标注循环次数供引擎重复调用。
    """

    name = "L3-05.rapid_subscribe_unsubscribe"
    layer = 3
    target_field = "state"
    strategy = "rapid_subscribe_unsubscribe"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pkt = build_sd_subscribe(
            service_id=seed.service_id,
            instance_id=seed.client_id or 0x0001,
            eventgroup_id=rng.randint(0x0001, 0x00FF),
            addr="127.0.0.1",
            port=rng.randint(30000, 40000),
        )
        return self._make_result(pkt, rapid_cycles=rng.randint(50, 200))


# ─────────────────────────────────────────────────────────────────────────────
# L3-06：订阅不存在的 EventGroup（subscribe_unknown_event）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class SubscribeUnknownEventMutator(BaseMutator):
    """L3-06：订阅服务未定义的 EventGroup ID。

    eventgroup_id 选用高值范围（0x8000-0xFFFF），触发服务端事件路由表
    的越界查找或 default 分支异常处理。
    """

    name = "L3-06.subscribe_unknown_event"
    layer = 3
    target_field = "state"
    strategy = "subscribe_unknown_event"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        unknown_eventgroup = rng.randint(0x8000, 0xFFFF)
        pkt = build_sd_subscribe(
            service_id=seed.service_id,
            instance_id=seed.client_id or 0x0001,
            eventgroup_id=unknown_eventgroup,
            addr="127.0.0.1",
            port=rng.randint(30000, 40000),
        )
        return self._make_result(pkt, unknown_eventgroup=unknown_eventgroup)


# ─────────────────────────────────────────────────────────────────────────────
# L3-07：强制非法状态迁移（invalid_state_transition）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class InvalidStateTransitionMutator(BaseMutator):
    """L3-07：在 EXPIRED/UNKNOWN 状态下强制发送 Notification（事件推送）。

    Notification 应仅在 SUBSCRIBED → RUNNING 路径上合法出现；
    在非法状态下推送事件测试服务端的防御性检查。
    使用 _make_raw_result() 因为直接构造 Notification 字节，不走 SD 路径。
    """

    name = "L3-07.invalid_state_transition"
    layer = 3
    target_field = "state"
    strategy = "invalid_state_transition"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pkt = SomeIpPacket.notification(
            service_id=seed.service_id,
            event_id=rng.randint(0x8001, 0x8FFF),
            payload=bytes(rng.randint(0, 0xFF) for _ in range(rng.randint(4, 16))),
        )
        return self._make_raw_result(
            pkt.to_bytes(),
            violated_precondition="SUBSCRIBED",
            actual_state="EXPIRED/UNKNOWN",
        )


# ─────────────────────────────────────────────────────────────────────────────
# L3-08：多客户端使用相同 Session ID（concurrent_clients_same_session）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class ConcurrentSameSessionMutator(BaseMutator):
    """L3-08：多个不同 client_id 使用相同的 session_id 发送请求。

    SOME/IP 规范中 session_id 用于去重/防重放；多客户端共用 session_id
    测试服务端去重逻辑是否按 (client_id, session_id) 联合键判断。
    使用固定 session_id=0x0001（最小值），最大碰撞概率。
    """

    name = "L3-08.concurrent_clients_same_session"
    layer = 3
    target_field = "session_id"
    strategy = "concurrent_clients_same_session"
    weight = 0.8  # payload 语义较复杂，略降权

    _FIXED_SESSION = 0x0001

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pkt = dataclasses.replace(
            seed,
            client_id=rng.randint(0x0001, 0xFFFE),
            session_id=self._FIXED_SESSION,
        )
        return self._make_raw_result(
            pkt.to_bytes(),
            fixed_session_id=self._FIXED_SESSION,
            client_id=pkt.client_id,
        )


# ─────────────────────────────────────────────────────────────────────────────
# L3-09：未订阅直接推送 Notification（event_without_subscription）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class EventWithoutSubscriptionMutator(BaseMutator):
    """L3-09：在目标未订阅的情况下向其推送 Notification 事件。

    模拟"流氓事件发布者"：绕过订阅机制直接推送，测试接收端的
    未请求事件过滤逻辑（是否丢弃、是否触发异常处理路径）。
    """

    name = "L3-09.event_without_subscription"
    layer = 3
    target_field = "state"
    strategy = "event_without_subscription"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pkt = SomeIpPacket.notification(
            service_id=seed.service_id,
            event_id=rng.randint(0x8001, 0x80FF),
            payload=seed.payload or bytes(rng.randint(0, 0xFF) for _ in range(8)),
        )
        return self._make_result(pkt, no_prior_subscribe=True)


# ─────────────────────────────────────────────────────────────────────────────
# L3-10：重启不清理状态（restart_without_cleanup）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class RestartWithoutCleanupMutator(BaseMutator):
    """L3-10：在 RUNNING 状态下直接重新 Offer 同一实例（不先 StopOffer）。

    模拟服务端崩溃后强制重启：跳过正常的 StopOffer 流程，
    直接再次 Offer，测试接收端的重叠实例处理（旧状态是否被清理）。
    """

    name = "L3-10.restart_without_cleanup"
    layer = 3
    target_field = "state"
    strategy = "restart_without_cleanup"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pkt = build_sd_offer(
            service_id=seed.service_id,
            instance_id=seed.client_id or 0x0001,
            addr="192.168.1.1",
            port=30509,
            major_ver=rng.randint(1, 3),  # 版本可能变化（重启后版本号更新）
            ttl=3,
        )
        return self._make_result(
            pkt, skipped_cleanup="StopOfferService", previous_state="RUNNING"
        )


# ─────────────────────────────────────────────────────────────────────────────
# L3-11：Session ID 触发回绕（session_id_overflow）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class SessionIdOverflowMutator(BaseMutator):
    """L3-11：将 session_id 设为 0xFFFF，触发回绕后的 0x0000/0x0001 冲突。

    SOME/IP 规范 session_id 从 1 开始单调递增，到 0xFFFF 回绕到 1。
    将 session_id 直接设为 0xFFFF 测试回绕边界的去重逻辑和防重放窗口。
    """

    name = "L3-11.session_id_overflow"
    layer = 3
    target_field = "session_id"
    strategy = "session_id_overflow"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pkt = dataclasses.replace(seed, session_id=0xFFFF)
        return self._make_result(pkt, overflow_value=0xFFFF, wrap_to=0x0001)


# ─────────────────────────────────────────────────────────────────────────────
# L3-12：TTL=0 的 OfferService（ttl_zero_offer）
# ─────────────────────────────────────────────────────────────────────────────

@register_mutator
class TtlZeroOfferMutator(BaseMutator):
    """L3-12：发送 TTL=0 的 OfferService（等价于 StopOfferService）。

    SOME/IP-SD 规范：type=0x01 且 TTL=0 表示 StopOfferService。
    此变异测试接收端是否正确区分 TTL=0 的 Offer（停止）和 TTL>0 的 Offer（提供）。
    某些实现直接按 type=Offer 处理而不检查 TTL，导致服务被"停止 Offer"后
    仍被误认为"可用"。
    """

    name = "L3-12.ttl_zero_offer"
    layer = 3
    target_field = "state"
    strategy = "ttl_zero_offer"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pkt = build_sd_stop_offer(
            service_id=seed.service_id,
            instance_id=seed.client_id or 0x0001,
        )
        return self._make_result(pkt, ttl=0, ambiguous_type=0x01)

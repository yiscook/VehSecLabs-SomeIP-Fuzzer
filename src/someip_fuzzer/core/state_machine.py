"""SOME/IP 服务生命周期状态机（创新点 C2）。

实时跟踪服务实例的发现 → 就绪 → 订阅 → 运行 → 过期 生命周期，
并基于当前状态提供"非法动作列表"，驱动 Layer 3 状态感知变异器。

状态迁移图：
    UNKNOWN → DISCOVERED → READY → SUBSCRIBED → RUNNING
                  ↓           ↓         ↓            ↓
               UNKNOWN    EXPIRED   EXPIRED       EXPIRED
                           (StopOffer / TTL 到期)

设计要点：
- ServiceInstance (service_id, instance_id) 为状态机键，支持多服务并发跟踪。
- on_packet() 自动解析 SD 报文类型，驱动状态迁移；非 SD 报文不影响实例状态。
- 可选接入 SessionStorage 实现跨会话持久化；不传则纯内存运行。
- export_mermaid() 输出 Mermaid 状态图，供 GUI Tab2 渲染。
"""

from __future__ import annotations

import dataclasses
import uuid
from enum import Enum
from typing import TYPE_CHECKING

from someip_fuzzer.core.protocol import (
    MessageType,
    SomeIpPacket,
    SD_SERVICE_ID,
)

if TYPE_CHECKING:
    from someip_fuzzer.data.storage import SessionStorage


# ── 状态定义 ──────────────────────────────────────────────────────────────────


class ServiceState(Enum):
    """服务实例生命周期状态（SPEC §3.1）。"""
    UNKNOWN    = "unknown"     # 初始/未知状态
    DISCOVERED = "discovered"  # 收到 FindService，服务位置已知
    READY      = "ready"       # 收到 OfferService，服务可用
    SUBSCRIBED = "subscribed"  # 已发送 Subscribe
    RUNNING    = "running"     # 收到 Notification，事件流推送中
    EXPIRED    = "expired"     # TTL 过期 / StopOffer


@dataclasses.dataclass(frozen=True)
class ServiceInstance:
    """服务实例唯一标识（service_id + instance_id）。"""
    service_id: int
    instance_id: int

    def __str__(self) -> str:
        return f"0x{self.service_id:04X}/0x{self.instance_id:04X}"


# ── 转换规则 ──────────────────────────────────────────────────────────────────

# {当前状态集合: {触发动作名: 目标状态}}
_TRANSITIONS: dict[frozenset[ServiceState], dict[str, ServiceState]] = {
    frozenset({ServiceState.UNKNOWN}): {
        "FindService": ServiceState.DISCOVERED,
        "OfferService": ServiceState.READY,
    },
    frozenset({ServiceState.DISCOVERED}): {
        "OfferService": ServiceState.READY,
        "Subscribe": ServiceState.SUBSCRIBED,
        "StopOfferService": ServiceState.UNKNOWN,
    },
    frozenset({ServiceState.READY}): {
        "Subscribe": ServiceState.SUBSCRIBED,
        "StopOfferService": ServiceState.UNKNOWN,
        "TTLExpired": ServiceState.EXPIRED,
    },
    frozenset({ServiceState.SUBSCRIBED}): {
        "Notification": ServiceState.RUNNING,
        "StopOfferService": ServiceState.UNKNOWN,
        "TTLExpired": ServiceState.EXPIRED,
    },
    frozenset({ServiceState.RUNNING}): {
        "StopOfferService": ServiceState.UNKNOWN,
        "TTLExpired": ServiceState.EXPIRED,
    },
    frozenset({ServiceState.EXPIRED}): {
        "OfferService": ServiceState.READY,   # 服务重启
    },
}

# 展平为 {(当前状态, 动作) → 目标状态}
_FLAT_TRANSITIONS: dict[tuple[ServiceState, str], ServiceState] = {}
for _states, _actions in _TRANSITIONS.items():
    for _state in _states:
        for _action, _target in _actions.items():
            _FLAT_TRANSITIONS[(_state, _action)] = _target

# 各状态下合法的动作名集合
_VALID_ACTIONS: dict[ServiceState, set[str]] = {}
for (_state, _action), _ in _FLAT_TRANSITIONS.items():
    _VALID_ACTIONS.setdefault(_state, set()).add(_action)

# 所有可能的动作名
_ALL_ACTIONS: set[str] = {
    "FindService", "OfferService", "StopOfferService",
    "Subscribe", "SubscribeAck", "Notification", "TTLExpired",
    "RPCRequest", "RPCResponse",
}


# ── SD Entry Type 常量（scapy SDEntry_Service/SDEntry_EventGroup 的 type 字段）──

_SD_FIND_SERVICE       = 0x00
_SD_OFFER_SERVICE      = 0x01   # TTL > 0: Offer；TTL = 0: StopOffer
_SD_SUBSCRIBE          = 0x06   # SDEntry_EventGroup
_SD_SUBSCRIBE_ACK      = 0x07   # SDEntry_EventGroup


def _sd_action_from_packet(pkt: SomeIpPacket) -> tuple[ServiceInstance, str] | None:
    """从 SD 报文解析出 (ServiceInstance, action_name)。

    返回 None 表示非 SD 报文或无法识别的 SD Entry。
    仅处理 payload 第一个 Entry。
    """
    if pkt.service_id != SD_SERVICE_ID:
        return None

    # SD payload 结构：Flags(1)+Reserved(3)+EntryArrayLen(4)+Entries+...
    payload = pkt.payload
    if len(payload) < 12:
        return None

    import struct
    entry_array_len = struct.unpack(">I", payload[4:8])[0]
    if len(payload) < 8 + entry_array_len or entry_array_len < 16:
        return None

    entry = payload[8:8 + 16]  # 取第一个 Entry（16 字节）
    entry_type = entry[0]
    srv_id   = struct.unpack(">H", entry[4:6])[0]
    inst_id  = struct.unpack(">H", entry[6:8])[0]
    ttl      = int.from_bytes(entry[9:12], "big")  # TTL 3 字节 big-endian

    instance = ServiceInstance(srv_id, inst_id)

    if entry_type == _SD_FIND_SERVICE:
        return instance, "FindService"
    if entry_type == _SD_OFFER_SERVICE:
        return instance, "StopOfferService" if ttl == 0 else "OfferService"
    if entry_type == _SD_SUBSCRIBE:
        return instance, "Subscribe"
    if entry_type == _SD_SUBSCRIBE_ACK:
        return instance, "SubscribeAck"
    return None


def _notification_instance(pkt: SomeIpPacket) -> tuple[ServiceInstance, str] | None:
    """从 NOTIFICATION 报文提取 (ServiceInstance, "Notification")。"""
    if pkt.message_type in (MessageType.NOTIFICATION, MessageType.NOTIFICATION_ACK):
        # event_id 在 method_id 字段，instance_id 约定为 0x0001（无法从报文头直接获取）
        return ServiceInstance(pkt.service_id, 0x0001), "Notification"
    return None


# ── 状态机核心 ────────────────────────────────────────────────────────────────


class ServiceStateMachine:
    """SOME/IP 服务实例生命周期状态机。

    用法::

        sm = ServiceStateMachine()
        sm.on_packet(build_sd_find(0x1234, 0x0001))
        sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
        assert sm.get_state(ServiceInstance(0x1234, 0x0001)) == ServiceState.READY
    """

    def __init__(
        self,
        storage: "SessionStorage | None" = None,
        session_id: str | None = None,
    ) -> None:
        self._states: dict[ServiceInstance, ServiceState] = {}
        self._storage = storage
        self._session_id = session_id or str(uuid.uuid4())

        # 从持久化存储恢复状态
        if storage is not None:
            restored = storage.load_all(self._session_id)
            for (srv_id, inst_id), state in restored.items():
                self._states[ServiceInstance(srv_id, inst_id)] = state

    # ── 状态迁移 ──────────────────────────────────────────────────────────────

    def on_packet(
        self, pkt: SomeIpPacket
    ) -> tuple[ServiceInstance, ServiceState] | None:
        """根据报文自动更新状态。

        Returns:
            ``(instance, new_state)`` 若状态发生变化，否则 ``None``。
        """
        parsed = _sd_action_from_packet(pkt) or _notification_instance(pkt)
        if parsed is None:
            return None
        instance, action = parsed
        return self._apply(instance, action)

    def expire(self, instance: ServiceInstance) -> None:
        """手动触发 TTL 过期，将实例迁移至 EXPIRED 状态。"""
        self._apply(instance, "TTLExpired")

    def _apply(
        self, instance: ServiceInstance, action: str
    ) -> tuple[ServiceInstance, ServiceState] | None:
        current = self._states.get(instance, ServiceState.UNKNOWN)
        new_state = _FLAT_TRANSITIONS.get((current, action))
        if new_state is None:
            return None  # 无合法迁移，忽略
        self._states[instance] = new_state
        if self._storage is not None:
            self._storage.save_state(
                self._session_id, instance.service_id, instance.instance_id, new_state
            )
        return instance, new_state

    # ── 状态查询 ──────────────────────────────────────────────────────────────

    def get_state(self, instance: ServiceInstance) -> ServiceState:
        """查询实例当前状态，未知实例返回 UNKNOWN。"""
        return self._states.get(instance, ServiceState.UNKNOWN)

    def get_all_states(self) -> dict[ServiceInstance, ServiceState]:
        """返回所有已跟踪实例的状态快照。"""
        return dict(self._states)

    def get_valid_transitions(
        self, state: ServiceState
    ) -> list[tuple[str, ServiceState]]:
        """返回给定状态下所有合法转换 [(action_name, target_state), ...]。"""
        return [
            (action, target)
            for (s, action), target in _FLAT_TRANSITIONS.items()
            if s == state
        ]

    def get_valid_actions(self, state: ServiceState) -> set[str]:
        """返回给定状态下合法的动作名集合。"""
        return _VALID_ACTIONS.get(state, set())

    def get_invalid_actions(self, state: ServiceState) -> list[str]:
        """返回当前状态下**不合法**的动作名列表（供 Layer 3 变异器使用）。"""
        valid = self.get_valid_actions(state)
        return sorted(_ALL_ACTIONS - valid)

    # ── 可视化 ────────────────────────────────────────────────────────────────

    def export_mermaid(self) -> str:
        """导出 Mermaid stateDiagram-v2 格式的状态图字符串（GUI 用）。

        包含所有定义的迁移规则，与当前运行时状态无关。
        """
        lines = ["stateDiagram-v2", "    [*] --> UNKNOWN"]
        seen: set[tuple[str, str, str]] = set()
        for (state, action), target in sorted(
            _FLAT_TRANSITIONS.items(), key=lambda x: (x[0][0].value, x[0][1])
        ):
            entry = (state.value.upper(), target.value.upper(), action)
            if entry not in seen:
                seen.add(entry)
                lines.append(
                    f"    {state.value.upper()} --> {target.value.upper()} : {action}"
                )
        return "\n".join(lines)

    @property
    def session_id(self) -> str:
        return self._session_id

    def __repr__(self) -> str:
        return (
            f"ServiceStateMachine(session={self._session_id!r}, "
            f"instances={len(self._states)})"
        )

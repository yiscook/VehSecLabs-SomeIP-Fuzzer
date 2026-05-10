# Phase 3 - 状态机模型 + 攻击链编排（创新点 C2、C3）

```yaml
phase: 3
title: 动态状态机 + 多报文攻击链
status: Complete
recommended_model: Opus 4.7（设计） + Sonnet 4.6（实现）
acceptance_passed: true
started_at: 2026-05-10
completed_at: 2026-05-10
git_tag: v0.3.0
```

---

## 3.1 目标

实现申报书的两大核心创新点：

- **C2 动态状态机模型**：实时跟踪服务实例生命周期与事件订阅状态，动态调整变异策略
- **C3 多报文攻击链**：支持服务发现 → RPC调用 → 事件触发 等跨阶段组合攻击

---

## 3.2 任务清单

### 3.A - 状态机模块（Layer 3 变异）

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 3.1 | 服务实例状态机定义 | `core/state_machine.py` | ✅ |
| 3.2 | 事件订阅状态机定义 | `core/state_machine.py` | ✅ |
| 3.3 | 状态跟踪器（监听报文流自动迁移状态） | `core/state_machine.py` | ✅ |
| 3.4 | 状态机变异器（12 种） | `core/mutators/layer3_state.py` | ✅ |
| 3.5 | 状态可视化（GUI 用，导出 mermaid 图） | `core/state_machine.py` | ✅ |
| 3.6 | 状态机持久化（恢复中断的会话） | `data/storage.py` | ✅ |

### 3.B - 攻击链模块（Layer 4 变异）

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 3.7 | 攻击链 DSL 设计（YAML 模板） | `configs/attack_chains/*.yaml` | ✅ |
| 3.8 | 攻击链解析器 | `core/attack_chain.py` | ✅ |
| 3.9 | 攻击链编排引擎（步骤间依赖、超时） | `core/attack_chain.py` | ✅ |
| 3.10 | 内置攻击链：服务劫持链 | `configs/attack_chains/hijack.yaml` | ✅ |
| 3.11 | 内置攻击链：DoS 资源耗尽链 | `configs/attack_chains/dos.yaml` | ✅ |
| 3.12 | 内置攻击链：会话冒用链 | `configs/attack_chains/session_steal.yaml` | ✅ |
| 3.13 | 内置攻击链：反序列化攻击链 | `configs/attack_chains/deser.yaml` | ✅ |
| 3.14 | 内置攻击链：订阅风暴链 | `configs/attack_chains/sub_storm.yaml` | ✅ |
| 3.15 | 内置攻击链：恶意 Offer 竞速链 | `configs/attack_chains/race_offer.yaml` | ✅ |
| 3.16 | 内置攻击链：分段重组攻击链（TP） | `configs/attack_chains/tp_attack.yaml` | ✅ |
| 3.17 | 内置攻击链：版本降级攻击链 | `configs/attack_chains/version_downgrade.yaml` | ✅ |
| 3.18 | 攻击链触发成功率统计 | `core/attack_chain.py` | ✅ |

---

## 3.3 状态机详细设计

### 3.3.1 服务实例状态机

```
                    ┌─────────────┐
                    │   UNKNOWN   │
                    └──────┬──────┘
                           │ FindService
                           ▼
                    ┌─────────────┐
              ┌─────│  DISCOVERED │◄────────┐
              │     └──────┬──────┘          │
       OfferService        │                 │ StopOfferService
              │            │ Subscribe       │
              ▼            ▼                 │
         ┌────────┐  ┌────────────┐         │
         │ READY  │──│ SUBSCRIBED │─────────┘
         └────┬───┘  └──────┬─────┘
              │             │ EventNotify
              │             ▼
              │      ┌─────────────┐
              │      │   RUNNING   │
              │      └──────┬──────┘
              │             │ TTL expire
              ▼             ▼
         ┌─────────────────────┐
         │     EXPIRED         │
         └─────────────────────┘
```

### 3.3.2 状态跟踪器

```python
class ServiceStateMachine:
    states: dict[ServiceInstance, ServiceState]
    
    def on_packet_received(self, pkt: SomeIpPacket):
        """根据报文自动迁移状态"""
        if pkt.is_sd_offer():
            self.states[instance] = ServiceState.READY
        elif pkt.is_sd_subscribe():
            self.states[instance] = ServiceState.SUBSCRIBED
        # ...
    
    def get_invalid_actions(self, state: ServiceState) -> list[Action]:
        """返回当前状态下的非法动作（用于变异）"""
        ...
```

### 3.3.3 Layer 3 变异策略（12 种）

| 编号 | 策略名 | 描述 |
|------|--------|------|
| L3-01 | skip_offer_subscribe | 跳过 Offer，直接 Subscribe |
| L3-02 | rpc_before_ready | NotReady 状态调用 RPC |
| L3-03 | duplicate_offer | 同实例多次 Offer |
| L3-04 | offer_after_stop | StopOffer 后立即 Offer |
| L3-05 | rapid_subscribe_unsubscribe | 快速订阅/退订循环 |
| L3-06 | subscribe_unknown_event | 订阅不存在的 EventGroup |
| L3-07 | invalid_state_transition | 强制非法状态迁移 |
| L3-08 | concurrent_clients_same_session | 多客户端同 Session ID |
| L3-09 | event_without_subscription | 未订阅情况下推送事件 |
| L3-10 | restart_without_cleanup | 重启不清理状态 |
| L3-11 | session_id_overflow | 会话 ID 触发回绕 |
| L3-12 | ttl_zero_offer | TTL=0 立即过期的 Offer |

---

## 3.4 攻击链 DSL 设计

### YAML 模板格式

```yaml
# configs/attack_chains/hijack.yaml
name: 服务劫持攻击链
id: AC-001
description: 通过恶意 Offer 抢占合法服务，截获后续 Subscribe
severity: high
cvss: 8.5

steps:
  - id: step_1_listen_findservice
    action: wait_for
    filter:
      message_type: SD
      sd_entry_type: FindService
    timeout: 30
    
  - id: step_2_send_malicious_offer
    action: send
    template: sd_offer
    params:
      service_id: "${step_1.service_id}"
      instance_id: "${step_1.instance_id}"
      endpoint_ip: "${attacker_ip}"
      endpoint_port: 31337
      ttl: 3600
    delay_ms: 50
    
  - id: step_3_capture_subscribe
    action: wait_for
    filter:
      message_type: SD
      sd_entry_type: Subscribe
      target_endpoint: "${attacker_ip}"
    timeout: 10
    
  - id: step_4_send_fake_response
    action: send
    template: notification
    params:
      service_id: "${step_1.service_id}"
      payload: "${malicious_payload}"
    repeat: 5

success_criteria:
  - step_3_completed: true
  - victim_reachable: false  # 真实服务被屏蔽
```

### 攻击链编排引擎

```python
class AttackChainEngine:
    async def execute(self, chain: AttackChain, transport: Transport) -> ChainResult:
        """按步骤执行攻击链，处理依赖、超时、变量替换"""
        context = {}
        for step in chain.steps:
            result = await self._execute_step(step, context, transport)
            context[step.id] = result
            if not result.success and step.required:
                return ChainResult(success=False, failed_at=step.id)
        return self._evaluate_success_criteria(chain, context)
```

---

## 3.5 8 个内置攻击链清单

| 链 ID | 名称 | 步骤数 | CVSS | 创新点 |
|------|------|--------|------|--------|
| AC-001 | 服务劫持链 | 4 | 8.5 | 抢占式 Offer + 捕获 Subscribe |
| AC-002 | DoS 资源耗尽链 | 3 | 7.5 | 海量服务注册 |
| AC-003 | 会话冒用链 | 5 | 7.0 | 嗅探+伪造 Session ID |
| AC-004 | 反序列化攻击链 | 3 | 9.0 | 畸形 TLV 触发解析异常 |
| AC-005 | 订阅风暴链 | 2 | 6.5 | 高频订阅/退订 |
| AC-006 | 恶意 Offer 竞速链 | 4 | 8.0 | 时序竞争 |
| AC-007 | TP 分段重组攻击链 | 6 | 8.5 | 分段乱序、缺失、重叠 |
| AC-008 | 版本降级攻击链 | 3 | 6.0 | 强制使用旧版本 |

---

## 3.6 测试

### 状态机测试

```python
def test_service_state_transition():
    sm = ServiceStateMachine()
    pkt = SomeIpPacket.sd_offer(srv=0x1234, inst=0x0001)
    sm.on_packet_received(pkt)
    assert sm.get_state((0x1234, 0x0001)) == ServiceState.READY

def test_invalid_state_detection():
    sm = ServiceStateMachine()
    actions = sm.get_invalid_actions(ServiceState.UNKNOWN)
    assert "rpc_call" in [a.name for a in actions]
```

### 攻击链测试（mock transport）

```python
@pytest.mark.asyncio
async def test_hijack_chain():
    chain = AttackChain.from_yaml("configs/attack_chains/hijack.yaml")
    mock_transport = MockTransport(scripted_responses=[...])
    engine = AttackChainEngine()
    result = await engine.execute(chain, mock_transport)
    assert result.steps_completed == 4
```

---

## 3.7 验收清单

- [x] 服务状态机包含至少 6 个状态（实现 6 个：UNKNOWN/DISCOVERED/READY/SUBSCRIBED/RUNNING/EXPIRED）
- [x] 12 种 Layer 3 状态机变异策略全部实现并测试（L3-01~L3-12，`layer3_state.py`）
- [x] 8 个内置攻击链全部实现，YAML 模板完整（AC-001~AC-008，`configs/attack_chains/`）
- [x] 攻击链引擎支持变量替换（`${step.field}`）、超时、依赖（`required` 字段）
- [ ] 状态机能从 PCAP 文件回放重建状态（需外部 PCAP 靶机环境，延至 Phase 8 验证）
- [x] 单元测试覆盖率 ≥ 75%（`state_machine.py` 92%，`layer3_state.py` 80%，326 个测试全通过）
- [x] git 提交规范，攻击链 + 状态机合并为一个 Phase 3 commit
- [x] 推送到 GitHub（`phase-3` 分支，merge 到 master，tag `v0.3.0`）

---

## 3.8 问题记录

**验收清单 1 项延至 Phase 8**：
- "状态机能从 PCAP 文件回放重建状态" — 需要外部 vsomeip VM 靶机抓包环境，
  与 Phase 1 的 PCAP 相关验收条件一致，统一在 Phase 8（靶机集成）时验证。
  `on_packet()` 接口设计支持任何 `SomeIpPacket` 输入，具备 PCAP 回放能力，
  仅缺少真实 PCAP 文件用于端到端验证。

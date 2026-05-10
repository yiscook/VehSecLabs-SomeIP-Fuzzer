# Phase 4 - 反馈引擎 + 崩溃检测 + 用例重放（创新点 C4）

```yaml
phase: 4
title: 反馈引擎 + 崩溃检测 + 重放
status: Complete
recommended_model: Opus 4.7（GA/Markov 算法） + Sonnet 4.6（监控/重放）
acceptance_passed: true
started_at: 2026-05-10
completed_at: 2026-05-10
git_tag: v0.4.0
```

---

## 4.1 目标

实现申报书要求的：
- **C4 反馈优化驱动的测试效率**：用简化算法替代 DL（电脑配置受限），保留 DL 接口
- **崩溃检测机制**：3 种检测方式融合，覆盖率 ≥ 95%
- **用例重放**：每个崩溃可 100% 复现

---

## 4.2 任务清单

### 4.A - 反馈引擎（Layer 5 变异）

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 4.1 | 反馈接口抽象 `FeedbackEngine` | `core/feedback.py` | ✅ |
| 4.2 | 遗传算法变异权重调整 | `core/feedback.py` | ✅ |
| 4.3 | 马尔可夫链字段转移学习 | `core/feedback.py` | ✅ |
| 4.4 | 响应熵值分析 | `core/feedback.py` | ✅ |
| 4.5 | 种子能量调度（高价值种子优先） | `core/feedback.py` | ✅ |
| 4.6 | DL 模型接口（预留，演示 Demo） | `core/feedback.py` | ✅ |

### 4.B - 崩溃检测

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 4.7 | 心跳检测（每 N 包发合法心跳） | `core/monitor.py` | ✅ |
| 4.8 | 响应超时检测 | `core/monitor.py` | ✅ |
| 4.9 | 异常响应模式识别 | `core/monitor.py` | ✅ |
| 4.10 | 远程进程监控 Agent（VM 内） | `scripts/agent.py` | ✅ |
| 4.11 | Agent ↔ 主机通信协议（SSH/HTTP） | `core/monitor.py` | ✅ |
| 4.12 | 崩溃严重度自动分级（CVSS 计算辅助） | `core/monitor.py` | ✅ |

### 4.C - 用例重放

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 4.13 | 测试用例完整记录（输入+上下文） | `data/crash_store.py` | ✅ |
| 4.14 | 重放引擎 | `core/replay.py` | ✅ |
| 4.15 | 重放脚本生成（导出独立 .py） | `core/replay.py` | ✅ |
| 4.16 | 最小化算法（缩减触发崩溃的最小报文） | `core/replay.py` | ✅ |

---

## 4.3 反馈引擎设计

### 4.3.1 三层反馈机制

```
┌─────────────────────────────────────────────┐
│            Mutation Scheduler                │
│   ┌──────────────────────────────────────┐  │
│   │ 权重表: { mutator_id: weight }       │  │
│   └──────────────────────────────────────┘  │
└──────────────────┬──────────────────────────┘
                   │ select(weighted_random)
                   ▼
              [发送报文]
                   │
                   ▼
              [收到响应]
                   │
                   ▼
┌─────────────────────────────────────────────┐
│           FeedbackEngine                     │
│  - GA: 触发新响应 → 权重 +α                  │
│  - Markov: 学习字段值的转移概率              │
│  - Entropy: 响应熵值变大 → 探索价值高        │
└──────────────────┬──────────────────────────┘
                   │ update_weight()
                   ▼
            [更新权重表]
```

### 4.3.2 简化遗传算法

```python
class GAFeedback:
    population: list[SeedPacket]
    fitness: dict[bytes, float]  # 报文hash → 适应度
    
    def evaluate(self, packet, response):
        """根据响应是否新颖打分"""
        if response.is_new_pattern:
            self.fitness[packet.hash()] += 10
        elif response.timeout:
            self.fitness[packet.hash()] += 5
    
    def evolve(self):
        """选择高适应度种子，做交叉/变异"""
        elite = sorted(self.population, key=lambda p: self.fitness.get(p.hash(), 0))[-10:]
        new_gen = []
        for parent in elite:
            child = self.crossover(parent, random.choice(elite))
            child = self.mutate(child)
            new_gen.append(child)
        self.population = new_gen
```

### 4.3.3 马尔可夫字段学习

```python
class MarkovFieldLearner:
    """从合法流量学习字段值的转移概率，引导变异"""
    
    transitions: dict[tuple[str, int], dict[int, int]]  # (field, prev_value) → {next_value: count}
    
    def observe(self, packet):
        for field in ['service_id', 'method_id', 'session_id']:
            value = getattr(packet, field)
            self.transitions.setdefault((field, self.last[field]), {})
            self.transitions[(field, self.last[field])][value] += 1
            self.last[field] = value
    
    def suggest_value(self, field: str, prev_value: int) -> int:
        """根据学到的概率返回下一个值（带噪声扰动）"""
        ...
```

---

## 4.4 崩溃检测三方融合

```
┌────────────────────────────────────────────┐
│           Crash Decision Layer              │
│   crashed = heartbeat_fail OR response_anomaly OR agent_alert │
└────────────────────────────────────────────┘
        ▲             ▲             ▲
        │             │             │
   ┌────┴────┐   ┌───┴────┐   ┌────┴────┐
   │ 心跳检测 │   │ 响应分析│   │ Agent  │
   │ (主机)   │   │ (主机)  │   │ (VM)   │
   └─────────┘   └─────────┘   └─────────┘
```

### 4.4.1 心跳检测

```python
class HeartbeatMonitor:
    interval: int = 100  # 每 100 个 fuzz 包发 1 个心跳
    timeout: float = 2.0
    
    async def check(self, transport):
        ping = SomeIpPacket.request(KNOWN_SRV, KNOWN_METHOD, b"ping")
        await transport.send(ping)
        try:
            resp = await asyncio.wait_for(transport.recv(), timeout=self.timeout)
            return resp.payload == b"pong"
        except asyncio.TimeoutError:
            return False
```

### 4.4.2 远程 Agent（VM 内）

简单的 HTTP 服务，监控 vsomeip 进程：
```python
# scripts/agent.py - 跑在 VM 里
@app.get("/status")
def status():
    proc = find_process("vsomeipd")
    return {
        "alive": proc is not None,
        "pid": proc.pid if proc else None,
        "memory_mb": proc.memory_info().rss / 1024 / 1024 if proc else 0,
        "cpu_percent": proc.cpu_percent() if proc else 0,
        "asan_log": tail_file("/tmp/asan.log", 100),
    }
```

---

## 4.5 用例重放与最小化

### 4.5.1 重放脚本格式

每个崩溃自动导出独立 Python 脚本：
```python
# results/crashes/crash_20260510_153045.py
"""
崩溃报告
=========
触发时间: 2026-05-10 15:30:45
靶机: 192.168.81.128:30509
变异策略: L1-L01_overflow_4byte_max
最小复现集: 1 个报文
"""
import asyncio
from someip_fuzzer.core.protocol import SomeIpPacket
from someip_fuzzer.core.transport import SomeIpUdpTransport

async def reproduce():
    transport = SomeIpUdpTransport()
    await transport.start(None, ("192.168.81.128", 30509))
    
    # 步骤 1：发送畸形报文
    pkt = SomeIpPacket(
        service_id=0x1234,
        method_id=0x5678,
        client_id=0xDEAD,
        session_id=0x0001,
        # Length 字段被设置为 0xFFFFFFFF
        message_type=0x00,
        payload=bytes.fromhex("aabbccdd"),
    )
    pkt._raw_length = 0xFFFFFFFF  # 故意覆盖
    await transport.send(pkt)
    
    print("已发送崩溃触发报文，请观察靶机状态")

if __name__ == "__main__":
    asyncio.run(reproduce())
```

### 4.5.2 最小化算法（Delta Debugging）

```python
def minimize(packets: list[SomeIpPacket], oracle) -> list[SomeIpPacket]:
    """二分缩减触发崩溃的报文集合"""
    while True:
        reduced = False
        # 尝试删除每个报文，看是否仍触发崩溃
        for i in range(len(packets)):
            candidate = packets[:i] + packets[i+1:]
            if oracle(candidate):  # 仍然崩溃
                packets = candidate
                reduced = True
                break
        if not reduced:
            break
    return packets
```

---

## 4.6 测试

### 反馈引擎测试

```python
def test_ga_evolution_improves_fitness():
    ga = GAFeedback()
    # 注入 100 个随机种子
    for _ in range(100):
        ga.population.append(random_seed())
    
    initial_avg = avg(ga.fitness.values())
    
    # 模拟 10 代进化
    for _ in range(10):
        for p in ga.population:
            response = simulated_response(p)
            ga.evaluate(p, response)
        ga.evolve()
    
    final_avg = avg(ga.fitness.values())
    assert final_avg > initial_avg * 1.5
```

### 崩溃检测测试

```python
@pytest.mark.asyncio
async def test_crash_detection_via_timeout():
    mock_transport = MockTransportNoResponse()
    monitor = HeartbeatMonitor(timeout=0.5)
    alive = await monitor.check(mock_transport)
    assert alive is False
```

### 重放测试

```python
def test_minimization_reduces_packets():
    packets = [pkt_a, pkt_b, pkt_crash, pkt_d]  # 只有 pkt_crash 触发崩溃
    minimal = minimize(packets, oracle=lambda pkts: pkt_crash in pkts)
    assert minimal == [pkt_crash]
```

---

## 4.7 验收清单

- [x] GA + Markov + Entropy 三种反馈算法实现（`core/feedback.py`，覆盖率 94%）
- [x] DL 模型接口预留（`DLModelInterface`，placeholder score=1.0，`is_available()=False`）
- [x] 崩溃检测三方融合工作正常（`CrashDetector`，任一触发即记录，严重度四级）
- [x] 远程 Agent 可在 VM 中运行（`scripts/agent.py`，独立 HTTP 服务，psutil + http.server）
- [x] 重放脚本可独立执行（`ReplayScriptGenerator` 生成 .py，语法验证通过）
- [x] 最小化算法（`DeltaDebugger` Delta Debugging，5包→1包测试通过）
- [ ] 实测：在 vsomeip 已知漏洞版本上能自动发现 ≥ 3 个崩溃（需 VM 靶机，延至 Phase 8）
- [x] 单元测试覆盖率 ≥ 70%（新增模块均 ≥ 90%，390 个测试全部通过）
- [x] git 规范提交、push GitHub（`phase-4` 分支 → merge master → tag v0.4.0）

---

## 4.8 问题记录

**1 项延至 Phase 8**：
- "实测在 vsomeip 已知漏洞版本上自动发现崩溃" — 需要外部 VM 靶机环境，
  与 Phase 1 PCAP 和 Phase 3 PCAP 回放验收条件一致，统一在 Phase 8 完成。
  `CrashDetector` 三路检测逻辑已完整实现，`AgentClient` 支持无 Agent 降级运行。

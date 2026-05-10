# Phase 1 - 协议核心层

```yaml
phase: 1
title: SOME/IP 协议核心层
status: Complete
recommended_model: Sonnet 4.6
acceptance_passed: true
started_at: 2026-05-10
completed_at: 2026-05-10
git_tag: v0.1.0
```

---

## 1.1 目标

实现 SOME/IP 与 SOME/IP-SD 报文的**构造、解析、发送、接收**能力，作为后续变异引擎和 GUI 的底层依赖。

---

## 1.2 任务清单

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 1.1 | SOME/IP 报文构造封装 | `core/protocol.py` | ✅ |
| 1.2 | SOME/IP-SD 服务发现报文构造 | `core/protocol.py` | ✅ |
| 1.3 | SOME/IP-TP 分段报文支持 | `core/protocol.py` | ✅ |
| 1.4 | UDP 异步收发器 | `core/transport.py` | ✅ |
| 1.5 | TCP 异步收发器 | `core/transport.py` | ✅ |
| 1.6 | 多播订阅与发送（SD 用） | `core/transport.py` | ✅ |
| 1.7 | 报文序列化器（Header → bytes） | `core/protocol.py` | ✅ |
| 1.8 | 报文反序列化器（bytes → Header + Payload） | `core/protocol.py` | ✅ |
| 1.9 | PCAP 抓包封装 | `utils/pcap.py` | ✅ |
| 1.10 | 报文工厂方法（常用模板：Request、Notification、Offer、Subscribe） | `core/protocol.py` | ✅ |
| 1.11 | loguru 日志统一封装 | `utils/logger.py` | ✅ |
| 1.12 | 配置加载（TOML） | `utils/config.py` | ✅ |

---

## 1.3 关键设计

### 1.3.1 协议模型 (`SomeIpPacket`)

封装 scapy 原生类，提供更友好的 API：

```python
@dataclass
class SomeIpPacket:
    service_id: int
    method_id: int
    client_id: int = 0
    session_id: int = 1
    protocol_version: int = 1
    interface_version: int = 1
    message_type: MessageType = MessageType.REQUEST
    return_code: ReturnCode = ReturnCode.E_OK
    payload: bytes = b""
    
    def to_scapy(self) -> SOMEIP: ...
    def to_bytes(self) -> bytes: ...
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "SomeIpPacket": ...
    
    @classmethod
    def request(cls, srv: int, method: int, payload: bytes) -> "SomeIpPacket": ...
```

### 1.3.2 异步传输层

使用 `asyncio.DatagramProtocol`，避免阻塞 GUI：

```python
class SomeIpUdpTransport:
    async def start(self, local_addr, remote_addr): ...
    async def send(self, packet: SomeIpPacket) -> None: ...
    async def recv(self, timeout: float = 1.0) -> SomeIpPacket | None: ...
    async def stop(self): ...
    
    # 回调机制（GUI 实时显示）
    on_sent: Callable[[SomeIpPacket], None]
    on_received: Callable[[SomeIpPacket], None]
```

### 1.3.3 多播支持（SD 必备）

```python
class MulticastTransport:
    """SOME/IP-SD 默认地址 224.224.224.245:30490"""
    DEFAULT_MULTICAST = "224.224.224.245"
    DEFAULT_SD_PORT = 30490
```

---

## 1.4 测试

### 单元测试

```python
# test_protocol.py
def test_someip_serialize():
    p = SomeIpPacket.request(0x1234, 0x5678, b"hello")
    data = p.to_bytes()
    assert len(data) >= 16  # SOME/IP header
    
def test_someip_roundtrip():
    p1 = SomeIpPacket.request(0x1234, 0x5678, b"world")
    p2 = SomeIpPacket.from_bytes(p1.to_bytes())
    assert p1.service_id == p2.service_id
    assert p1.payload == p2.payload

def test_sd_offer_service():
    sd = build_sd_offer(srv_id=0x1111, instance=0x0001, addr="192.168.1.1", port=30509)
    assert sd.entry_array[0].type == 0x01  # OfferService

def test_someip_tp_fragment():
    # 大 payload 自动分段
    p = SomeIpPacket.request(0x1234, 0x5678, b"X" * 5000)
    fragments = p.fragment_tp(mtu=1400)
    assert len(fragments) > 1
```

### 集成测试（需要环回测试）

```python
# test_transport.py
@pytest.mark.asyncio
async def test_udp_loopback():
    server = SomeIpUdpTransport()
    await server.start(("127.0.0.1", 30509), None)
    
    client = SomeIpUdpTransport()
    await client.start(None, ("127.0.0.1", 30509))
    
    sent = SomeIpPacket.request(0x1234, 0x5678, b"ping")
    await client.send(sent)
    
    received = await server.recv(timeout=1.0)
    assert received.payload == b"ping"
```

---

## 1.5 验收清单

- [x] 所有 12 个子任务完成
- [x] 单元测试覆盖率 76%（core/protocol.py 99%）
- [x] 能构造 5 种典型报文：Request、Response、Notification、Offer、Subscribe
- [x] UDP 环回收发延迟 < 100ms（本机 loopback）
- [ ] 能成功抓取并解析至少 100 个 SOME/IP 报文（需外部 VM 靶机，Phase 8 验证）
- [ ] 多播报文互通（需 VM 靶机，Phase 8 验证）
- [x] git 提交符合规范（4 条 phase-1 原子 commit + 1 条 merge commit）
- [x] 推送到 GitHub `phase-1` 分支并合并到 master，tag v0.1.0

---

## 1.6 关键依赖

来自 `scapy.contrib.automotive.someip`：
- `SOMEIP` - 主报文类
- `SD` - 服务发现报文
- `SDEntry_Service`, `SDEntry_EventGroup`
- `SDOption_IP4_EndPoint`, `SDOption_IP4_Multicast`

---

## 1.7 问题记录

**验收清单 2 项延至 Phase 8**：

- "能成功抓取并解析至少 100 个 SOME/IP 报文" — 需要外部 vsomeip VM 靶机，条件尚未具备
- "多播报文互通" — 同上，需 VM 靶机网络环境

两项均已在验收清单中标注"需外部 VM 靶机，Phase 8 验证"，不影响 Phase 1 通过。
将在 Phase 8（vsomeip 靶机集成 + 端到端联调）中统一验证。

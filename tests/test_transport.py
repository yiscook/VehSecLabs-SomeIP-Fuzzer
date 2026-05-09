"""传输层集成测试（本地 UDP 环回，无需外部服务）。"""

import asyncio
import time

import pytest

from someip_fuzzer.core.protocol import SomeIpPacket
from someip_fuzzer.core.transport import SomeIpTcpTransport, SomeIpUdpTransport


@pytest.mark.asyncio
async def test_udp_loopback_payload():
    """UDP 环回：payload 原样送达。"""
    server = SomeIpUdpTransport()
    client = SomeIpUdpTransport()
    try:
        await server.start(local_addr=("127.0.0.1", 0))
        server_port = server._transport.get_extra_info("sockname")[1]

        await client.start(local_addr=("127.0.0.1", 0))

        sent = SomeIpPacket.request(0x1234, 0x5678, b"ping")
        await client.send(sent, addr=("127.0.0.1", server_port))

        received = await server.recv(timeout=2.0)
        assert received is not None, "No packet received"
        assert received.payload == b"ping"
        assert received.service_id == 0x1234
        assert received.method_id == 0x5678
    finally:
        await client.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_udp_loopback_rtt():
    """UDP 环回 RTT 应 < 100ms（本机）。"""
    server = SomeIpUdpTransport()
    client = SomeIpUdpTransport()
    try:
        await server.start(local_addr=("127.0.0.1", 0))
        server_port = server._transport.get_extra_info("sockname")[1]
        await client.start(local_addr=("127.0.0.1", 0))

        pkt = SomeIpPacket.request(0x1234, 0x5678, b"rtt_test")
        t0 = time.perf_counter()
        await client.send(pkt, addr=("127.0.0.1", server_port))
        _ = await server.recv(timeout=2.0)
        rtt = (time.perf_counter() - t0) * 1000

        assert rtt < 100, f"RTT too high: {rtt:.1f}ms"
    finally:
        await client.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_udp_on_sent_callback():
    """on_sent 回调在发包时被调用。"""
    client = SomeIpUdpTransport()
    received_callbacks: list[SomeIpPacket] = []
    client.on_sent = received_callbacks.append

    try:
        await client.start(local_addr=("127.0.0.1", 0))
        pkt = SomeIpPacket.request(0x1234, 0x5678, b"cb_test")
        await client.send(pkt, addr=("127.0.0.1", 1))  # 端口 1 不可达，但回调应触发
    except Exception:
        pass  # sendto 可能失败（无人监听），但回调应在 sendto 前触发
    finally:
        await client.stop()

    # on_sent 应在 send() 内部 sendto 后立即调用
    # （即使对端不存在，UDP 发送端不报错）
    assert len(received_callbacks) == 1
    assert received_callbacks[0].payload == b"cb_test"


@pytest.mark.asyncio
async def test_udp_on_received_callback():
    """on_received 回调在收到报文时被调用。"""
    server = SomeIpUdpTransport()
    client = SomeIpUdpTransport()
    received_pkts: list[SomeIpPacket] = []
    server.on_received = received_pkts.append

    try:
        await server.start(local_addr=("127.0.0.1", 0))
        server_port = server._transport.get_extra_info("sockname")[1]
        await client.start(local_addr=("127.0.0.1", 0))

        pkt = SomeIpPacket.request(0x5678, 0x1234, b"on_recv_test")
        await client.send(pkt, addr=("127.0.0.1", server_port))
        result = await server.recv(timeout=2.0)

        assert result is not None
        assert len(received_pkts) == 1
        assert received_pkts[0].service_id == 0x5678
    finally:
        await client.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_udp_recv_timeout():
    """无数据时 recv() 应在超时后返回 None。"""
    server = SomeIpUdpTransport()
    try:
        await server.start(local_addr=("127.0.0.1", 0))
        result = await server.recv(timeout=0.1)
        assert result is None
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_udp_multiple_packets():
    """连续发送 10 个报文，全部能被接收。"""
    server = SomeIpUdpTransport()
    client = SomeIpUdpTransport()
    try:
        await server.start(local_addr=("127.0.0.1", 0))
        server_port = server._transport.get_extra_info("sockname")[1]
        await client.start(local_addr=("127.0.0.1", 0))

        for i in range(10):
            pkt = SomeIpPacket.request(0x1234, 0x5678, f"pkt{i}".encode())
            await client.send(pkt, addr=("127.0.0.1", server_port))

        received = []
        for _ in range(10):
            r = await server.recv(timeout=1.0)
            if r:
                received.append(r)

        assert len(received) == 10
    finally:
        await client.stop()
        await server.stop()


@pytest.mark.asyncio
async def test_tcp_loopback():
    """TCP 环回：客户端发送，服务端接收。"""
    PORT = 39901
    server = SomeIpTcpTransport()
    client = SomeIpTcpTransport()
    try:
        server_task = asyncio.create_task(server.listen("127.0.0.1", PORT))
        await asyncio.sleep(0.05)  # 等待服务端就绪
        await client.connect("127.0.0.1", PORT)
        await server_task  # 等待 accept 完成

        pkt = SomeIpPacket.request(0x1234, 0x5678, b"tcp_test")
        await client.send(pkt)

        received = await server.recv(timeout=2.0)
        assert received is not None
        assert received.payload == b"tcp_test"
    finally:
        await client.stop()
        await server.stop()

"""SOME/IP 异步网络传输层 —— UDP、TCP、多播。"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from typing import Callable

from someip_fuzzer.core.protocol import SomeIpPacket
from someip_fuzzer.utils.logger import logger


# ── UDP 传输 ──────────────────────────────────────────────────────────────────

class _UdpProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol 实现，内部供 SomeIpUdpTransport 使用。"""

    def __init__(self, recv_queue: asyncio.Queue[tuple[bytes, tuple]]) -> None:
        self._queue = recv_queue

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._queue.put_nowait((data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.warning(f"UDP error: {exc}")


class SomeIpUdpTransport:
    """异步 UDP 传输，支持 send / recv / 回调钩子。"""

    def __init__(self) -> None:
        self._transport: asyncio.DatagramTransport | None = None
        self._recv_queue: asyncio.Queue[tuple[bytes, tuple]] = asyncio.Queue()
        self._remote_addr: tuple[str, int] | None = None
        self.on_sent: Callable[[SomeIpPacket], None] | None = None
        self.on_received: Callable[[SomeIpPacket], None] | None = None

    async def start(
        self,
        local_addr: tuple[str, int] | None = None,
        remote_addr: tuple[str, int] | None = None,
    ) -> None:
        """绑定本地端口并（可选）记录远端地址。"""
        self._remote_addr = remote_addr
        loop = asyncio.get_event_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self._recv_queue),
            local_addr=local_addr or ("0.0.0.0", 0),
            allow_broadcast=True,
        )
        local = self._transport.get_extra_info("sockname")
        logger.debug(f"UDP transport started, local={local}, remote={remote_addr}")

    async def send(self, packet: SomeIpPacket, addr: tuple[str, int] | None = None) -> None:
        """发送报文。addr 为 None 时使用 start() 时指定的 remote_addr。"""
        target = addr or self._remote_addr
        if target is None:
            raise ValueError("No remote address specified")
        if self._transport is None:
            raise RuntimeError("Transport not started")
        data = packet.to_bytes()
        self._transport.sendto(data, target)
        if self.on_sent:
            self.on_sent(packet)

    async def recv(self, timeout: float = 2.0) -> SomeIpPacket | None:
        """接收一个报文，超时返回 None。"""
        try:
            data, addr = await asyncio.wait_for(self._recv_queue.get(), timeout=timeout)
            pkt = SomeIpPacket.from_bytes(data, source_addr=addr)
            if self.on_received:
                self.on_received(pkt)
            return pkt
        except asyncio.TimeoutError:
            return None

    async def stop(self) -> None:
        if self._transport and not self._transport.is_closing():
            self._transport.close()
        self._transport = None
        logger.debug("UDP transport stopped")


# ── 多播传输（SOME/IP-SD） ────────────────────────────────────────────────────

class SomeIpMulticastTransport(SomeIpUdpTransport):
    """SOME/IP-SD 多播传输。

    Windows 需要绑定到具体网卡 IP（非 0.0.0.0），
    并手动加入多播组。
    """

    DEFAULT_MULTICAST: str = "224.224.224.245"
    DEFAULT_SD_PORT: int = 30490

    def __init__(
        self,
        multicast_group: str = DEFAULT_MULTICAST,
        sd_port: int = DEFAULT_SD_PORT,
    ) -> None:
        super().__init__()
        self._multicast_group = multicast_group
        self._sd_port = sd_port

    async def join(self, local_ip: str) -> None:
        """创建 UDP 套接字，加入多播组，绑定 SD 端口。"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

        # 加入多播组
        mreq = struct.pack("4s4s",
                           socket.inet_aton(self._multicast_group),
                           socket.inet_aton(local_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        # Windows 多播发送需要指定出口接口
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                        socket.inet_aton(local_ip))

        sock.bind((local_ip, self._sd_port))

        loop = asyncio.get_event_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self._recv_queue),
            sock=sock,
        )
        self._remote_addr = (self._multicast_group, self._sd_port)
        logger.info(f"Joined multicast group {self._multicast_group}:{self._sd_port} via {local_ip}")


# ── TCP 传输 ──────────────────────────────────────────────────────────────────

class SomeIpTcpTransport:
    """异步 TCP 传输，支持作为客户端或服务端运行。"""

    # SOME/IP header 固定 16 字节，length 字段在 [4:8]
    _HEADER_LEN: int = 16

    def __init__(self) -> None:
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._server: asyncio.Server | None = None
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._recv_task: asyncio.Task | None = None
        self.on_sent: Callable[[SomeIpPacket], None] | None = None
        self.on_received: Callable[[SomeIpPacket], None] | None = None

    async def connect(self, host: str, port: int) -> None:
        """作为客户端连接到远端 SOME/IP 服务。"""
        self._reader, self._writer = await asyncio.open_connection(host, port)
        self._recv_task = asyncio.create_task(self._read_loop())
        logger.debug(f"TCP connected to {host}:{port}")

    async def listen(self, host: str = "0.0.0.0", port: int = 30509) -> None:
        """作为服务端监听，接受第一个连接。"""
        connect_future: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = (
            asyncio.get_event_loop().create_future()
        )

        async def _accept(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            if not connect_future.done():
                connect_future.set_result((r, w))

        self._server = await asyncio.start_server(_accept, host, port)
        self._reader, self._writer = await connect_future
        self._recv_task = asyncio.create_task(self._read_loop())
        logger.debug(f"TCP listening on {host}:{port}, client connected")

    async def _read_loop(self) -> None:
        assert self._reader is not None
        try:
            while True:
                # 读取固定 16 字节 header
                header = await self._reader.readexactly(self._HEADER_LEN)
                length = int.from_bytes(header[4:8], "big")
                # length = 8 + payload_len，剩余需要读 length - 8 字节
                extra = length - 8
                body = await self._reader.readexactly(extra) if extra > 0 else b""
                raw = header + body
                self._recv_queue.put_nowait(raw)
        except asyncio.IncompleteReadError:
            logger.debug("TCP connection closed by peer")
        except asyncio.CancelledError:
            pass

    async def send(self, packet: SomeIpPacket) -> None:
        if self._writer is None:
            raise RuntimeError("TCP transport not connected")
        data = packet.to_bytes()
        self._writer.write(data)
        await self._writer.drain()
        if self.on_sent:
            self.on_sent(packet)

    async def recv(self, timeout: float = 2.0) -> SomeIpPacket | None:
        try:
            raw = await asyncio.wait_for(self._recv_queue.get(), timeout=timeout)
            pkt = SomeIpPacket.from_bytes(raw)
            if self.on_received:
                self.on_received(pkt)
            return pkt
        except asyncio.TimeoutError:
            return None

    async def stop(self) -> None:
        if self._recv_task:
            self._recv_task.cancel()
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
        if self._server:
            self._server.close()
        self._reader = None
        self._writer = None
        logger.debug("TCP transport stopped")


# ── 便捷测量工具 ──────────────────────────────────────────────────────────────

async def measure_rtt(transport: SomeIpUdpTransport,
                      packet: SomeIpPacket,
                      addr: tuple[str, int],
                      timeout: float = 2.0) -> float | None:
    """发送报文并测量 RTT（秒）。无响应返回 None。"""
    t0 = time.perf_counter()
    await transport.send(packet, addr)
    resp = await transport.recv(timeout=timeout)
    if resp is None:
        return None
    return time.perf_counter() - t0

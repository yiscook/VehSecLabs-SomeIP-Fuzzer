"""SOME/IP 模糊测试种子语料库（SQLite 后端）。

职责：持久化存储种子报文（raw bytes），提供去重、按服务过滤、随机采样等能力。

设计要点：
- 仅存 raw bytes + 元数据，不存 SomeIpPacket dataclass，避免序列化版本耦合。
- 用 sha256 唯一约束自动去重，add() 遇到重复直接 IGNORE，返回 None。
- 全部 SQL 使用参数化查询，绝不字符串拼接，杜绝 SQL 注入。
- 数据库文件路径由调用方指定；传 ":memory:" 可做内存库（用于测试）。
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from someip_fuzzer.core.protocol import SomeIpPacket

# ── Schema ───────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS seeds (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_bytes   BLOB    NOT NULL,
    source      TEXT    NOT NULL DEFAULT 'manual',
    service_id  INTEGER,
    method_id   INTEGER,
    msg_type    INTEGER,
    payload_len INTEGER,
    sha256      TEXT    UNIQUE NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    note        TEXT
);
CREATE INDEX IF NOT EXISTS idx_service ON seeds(service_id, method_id);
"""

# ── 结果容器 ──────────────────────────────────────────────────────────────────


@dataclass
class SeedRecord:
    """一条种子记录，由 :meth:`SeedCorpus.get` 和 :meth:`SeedCorpus.list` 返回。"""

    id: int
    raw_bytes: bytes
    source: str
    service_id: int | None
    method_id: int | None
    msg_type: int | None
    payload_len: int | None
    sha256: str
    created_at: str
    note: str | None

    def to_packet(self) -> SomeIpPacket | None:
        """尝试将 raw_bytes 解析成 SomeIpPacket；畸形字节返回 None。"""
        try:
            return SomeIpPacket.from_bytes(self.raw_bytes)
        except Exception:
            return None


# ── 主类 ─────────────────────────────────────────────────────────────────────


class SeedCorpus:
    """SQLite 种子语料库。

    Args:
        db_path: 数据库文件路径；传 ``":memory:"`` 使用内存数据库（测试用）。

    Examples::

        corpus = SeedCorpus(":memory:")
        seed_id = corpus.add(packet, source="manual")
        record = corpus.get(seed_id)
        print(corpus.count())
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._path = str(db_path)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()

    # ── 写操作 ───────────────────────────────────────────────────────────────

    def add(
        self,
        packet: SomeIpPacket,
        source: str = "manual",
        note: str | None = None,
    ) -> int | None:
        """添加一条种子。sha256 重复时静默跳过，返回 None；成功返回新行 id。

        Args:
            packet: 要存储的 SOME/IP 报文。
            source: 来源标签，如 'manual' / 'pcap' / 'sd_response' / 'mutation'。
            note: 可选备注（如触发崩溃的上下文描述）。

        Returns:
            新行的 ``id``（int），或 ``None``（若 sha256 已存在）。
        """
        raw = packet.to_bytes()
        digest = hashlib.sha256(raw).hexdigest()

        try:
            payload = packet.payload if hasattr(packet, "payload") else b""
        except Exception:
            payload = b""

        sql = """
            INSERT OR IGNORE INTO seeds
                (raw_bytes, source, service_id, method_id, msg_type, payload_len, sha256, note)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?)
        """
        cur = self._conn.execute(
            sql,
            (
                raw,
                source,
                packet.service_id,
                packet.method_id,
                int(packet.message_type),
                len(payload),
                digest,
                note,
            ),
        )
        self._conn.commit()
        if cur.lastrowid and cur.rowcount > 0:
            return cur.lastrowid
        return None

    def add_raw(
        self,
        raw_bytes: bytes,
        source: str = "manual",
        note: str | None = None,
    ) -> int | None:
        """直接添加 raw bytes（畸形报文 / 已变异报文）。

        元数据字段（service_id 等）无法解析时填 None。
        """
        digest = hashlib.sha256(raw_bytes).hexdigest()

        # 尝试解析出元数据，失败则留 None
        service_id = method_id = msg_type = payload_len = None
        try:
            pkt = SomeIpPacket.from_bytes(raw_bytes)
            service_id = pkt.service_id
            method_id = pkt.method_id
            msg_type = int(pkt.msg_type)
            payload_len = len(pkt.payload) if hasattr(pkt, "payload") else None
        except Exception:
            pass

        sql = """
            INSERT OR IGNORE INTO seeds
                (raw_bytes, source, service_id, method_id, msg_type, payload_len, sha256, note)
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?)
        """
        cur = self._conn.execute(
            sql,
            (raw_bytes, source, service_id, method_id, msg_type, payload_len, digest, note),
        )
        self._conn.commit()
        if cur.lastrowid and cur.rowcount > 0:
            return cur.lastrowid
        return None

    # ── 读操作 ───────────────────────────────────────────────────────────────

    def get(self, seed_id: int) -> SeedRecord | None:
        """按 id 获取单条记录。不存在返回 None。"""
        row = self._conn.execute(
            "SELECT * FROM seeds WHERE id = ?", (seed_id,)
        ).fetchone()
        return _row_to_record(row) if row else None

    def list(
        self,
        service_id: int | None = None,
        limit: int | None = None,
    ) -> list[SeedRecord]:
        """列出种子，可按 service_id 过滤。

        Args:
            service_id: 若指定，仅返回匹配该服务的种子。
            limit: 最多返回条数（None 表示不限）。
        """
        if service_id is not None:
            sql = "SELECT * FROM seeds WHERE service_id = ? ORDER BY id"
            params: tuple = (service_id,)
        else:
            sql = "SELECT * FROM seeds ORDER BY id"
            params = ()

        if limit is not None:
            sql += " LIMIT ?"
            params = params + (limit,)

        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_record(r) for r in rows]

    def iter(self, batch_size: int = 100) -> Iterator[SeedRecord]:
        """逐批迭代所有种子，内存友好（语料库较大时使用）。"""
        offset = 0
        while True:
            rows = self._conn.execute(
                "SELECT * FROM seeds ORDER BY id LIMIT ? OFFSET ?",
                (batch_size, offset),
            ).fetchall()
            if not rows:
                break
            for row in rows:
                yield _row_to_record(row)
            offset += len(rows)
            if len(rows) < batch_size:
                break

    def sample(self, n: int, service_id: int | None = None) -> list[SeedRecord]:
        """随机采样 n 条种子（用于变异引擎选种子）。

        SQLite 的 ORDER BY RANDOM() 对大语料库性能一般，n 通常较小（< 100）所以可接受。
        """
        if service_id is not None:
            sql = "SELECT * FROM seeds WHERE service_id = ? ORDER BY RANDOM() LIMIT ?"
            params = (service_id, n)
        else:
            sql = "SELECT * FROM seeds ORDER BY RANDOM() LIMIT ?"
            params = (n,)
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_record(r) for r in rows]

    def count(self, service_id: int | None = None) -> int:
        """统计种子总数（可按 service_id 过滤）。"""
        if service_id is not None:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM seeds WHERE service_id = ?", (service_id,)
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM seeds").fetchone()
        return row[0] if row else 0

    def purge(self, service_id: int | None = None) -> int:
        """删除种子。

        Args:
            service_id: 若指定，仅删除匹配的种子；否则清空全表。

        Returns:
            删除的行数。
        """
        if service_id is not None:
            cur = self._conn.execute(
                "DELETE FROM seeds WHERE service_id = ?", (service_id,)
            )
        else:
            cur = self._conn.execute("DELETE FROM seeds")
        self._conn.commit()
        return cur.rowcount

    # ── 生命周期 ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        """关闭数据库连接（不调用也会在 GC 时关闭）。"""
        self._conn.close()

    def __enter__(self) -> "SeedCorpus":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"SeedCorpus(path={self._path!r}, count={self.count()})"


# ── 工具函数 ──────────────────────────────────────────────────────────────────


def _row_to_record(row: sqlite3.Row) -> SeedRecord:
    return SeedRecord(
        id=row["id"],
        raw_bytes=bytes(row["raw_bytes"]),
        source=row["source"],
        service_id=row["service_id"],
        method_id=row["method_id"],
        msg_type=row["msg_type"],
        payload_len=row["payload_len"],
        sha256=row["sha256"],
        created_at=row["created_at"],
        note=row["note"],
    )

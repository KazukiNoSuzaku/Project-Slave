"""Append-only, hash-chained event store on DuckDB (design.md §2, §9).

Every event is sealed into a single chain:

    hash_n = sha256(hash_{n-1} + "\\n" + canonical_json(event_n))

with hash_{-1} = 64 zeros. The canonical JSON body is stored verbatim, so
`verify()` can recompute the whole chain from the table alone; editing,
deleting or reordering any row breaks every later link. The store exposes no
update or delete API. Publishing `head_hash` somewhere outside the database
(a log line, a commit) also detects truncation of the tail.

Writes are buffered and inserted in Arrow batches for throughput. The owner
calls `maybe_flush()` outside the gateway's latency-critical path.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

import duckdb
import pyarrow as pa

from slave.schema import Event

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq        BIGINT PRIMARY KEY,
    event_id   VARCHAR NOT NULL,
    session_id VARCHAR NOT NULL,
    ts         TIMESTAMPTZ NOT NULL,
    kind       VARCHAR NOT NULL,
    src_id     VARCHAR NOT NULL,
    dst_id     VARCHAR,
    body       VARCHAR NOT NULL,
    prev_hash  VARCHAR NOT NULL,
    hash       VARCHAR NOT NULL
)
"""

_ARROW_SCHEMA = pa.schema([
    ("seq", pa.int64()),
    ("event_id", pa.string()),
    ("session_id", pa.string()),
    ("ts", pa.timestamp("us", tz="UTC")),
    ("kind", pa.string()),
    ("src_id", pa.string()),
    ("dst_id", pa.string()),
    ("body", pa.string()),
    ("prev_hash", pa.string()),
    ("hash", pa.string()),
])


def chain_hash(prev_hash: str, body: str) -> str:
    return hashlib.sha256(f"{prev_hash}\n{body}".encode()).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    head_hash: str
    bad_seq: int | None = None
    reason: str | None = None


class EventStore:
    def __init__(self, path: str | Path = ":memory:", *, batch_size: int = 5000,
                 max_buffer: int = 200_000) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.con = duckdb.connect(self.path)
        self.con.execute(_SCHEMA)
        self.batch_size = batch_size
        self.max_buffer = max_buffer
        rows = self.con.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchall()
        self.head_seq, self.head_hash = rows[0] if rows else (-1, GENESIS)
        self._buf: list[tuple] = []

    # ---- writing ------------------------------------------------------------

    def append(self, event: Event) -> Event:
        body = event.canonical_json()
        seq = self.head_seq + 1
        prev = self.head_hash
        h = chain_hash(prev, body)
        self._buf.append((seq, event.event_id, event.session_id, event.ts, event.kind.value, event.src_id,
                          event.dst_id, body, prev, h))
        self.head_seq, self.head_hash = seq, h
        # `append` runs inside the gateway's gated path, so it only buffers.
        # Disk writes happen in `maybe_flush`, called off the hot path; the
        # hard cap only bounds memory if nobody calls it.
        if len(self._buf) >= self.max_buffer:
            self.flush()
        return event.model_copy(update={"seq": seq, "prev_hash": prev, "hash": h})

    __call__ = append  # usable directly as a Gateway sink

    def maybe_flush(self) -> None:
        """Write the buffer if it has reached `batch_size`. Call between gated actions."""
        if len(self._buf) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._buf:
            return
        cols = list(zip(*self._buf))
        batch = pa.Table.from_arrays([pa.array(c, type=f.type) for c, f in zip(cols, _ARROW_SCHEMA)],
                                     schema=_ARROW_SCHEMA)
        self.con.register("_batch", batch)
        try:
            self.con.execute("INSERT INTO events SELECT * FROM _batch")
        finally:
            self.con.unregister("_batch")
        self._buf.clear()

    # ---- reading ------------------------------------------------------------

    def count(self) -> int:
        self.flush()
        return self.con.execute("SELECT count(*) FROM events").fetchone()[0]

    def session_events(self, session_id: str) -> list[Event]:
        self.flush()
        rows = self.con.execute(
            "SELECT seq, body, prev_hash, hash FROM events WHERE session_id = ? ORDER BY seq", [session_id]
        ).fetchall()
        return [Event.model_validate_json(body).model_copy(update={"seq": s, "prev_hash": p, "hash": h})
                for s, body, p, h in rows]

    def verify(self, *, chunk: int = 50_000) -> VerifyResult:
        """Recompute the full chain from stored bodies."""
        self.flush()
        # Own cursor, so an early return can't leave the main connection busy.
        with self.con.cursor() as cur:
            cur.execute("SELECT seq, body, prev_hash, hash FROM events ORDER BY seq")
            expected_seq, running = 0, GENESIS
            while rows := cur.fetchmany(chunk):
                for seq, body, prev, h in rows:
                    if seq != expected_seq:
                        return VerifyResult(False, expected_seq, running, expected_seq, f"gap: found seq {seq}")
                    if prev != running:
                        return VerifyResult(False, seq, running, seq, "prev_hash does not match previous row")
                    if chain_hash(prev, body) != h:
                        return VerifyResult(False, seq, running, seq, "body does not match its hash")
                    running = h
                    expected_seq += 1
        return VerifyResult(True, expected_seq, running)

    # ---- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        self.flush()
        self.con.close()

    def __enter__(self) -> EventStore:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.close()

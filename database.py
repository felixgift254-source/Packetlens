import sqlite3
import os
import io
import logging
import pandas as pd
from pathlib import Path

DB_NAME = "network_traffic.db"

# ── Batch size driven by config (falls back to 50 if config not loaded yet) ───
try:
    import yaml as _yaml
    _db_cfg = _yaml.safe_load(open(Path(__file__).parent / "config.yaml")) or {}
    _BATCH_SIZE: int = int(_db_cfg.get("database", {}).get("batch_size", 50))
except Exception:
    _BATCH_SIZE = 50

_batch: list = []      # module-level packet buffer

logger = logging.getLogger(__name__)


def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Enable WAL mode so concurrent reads (Streamlit) never block writes (sniffer)
    c.execute("PRAGMA journal_mode=WAL")

    c.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            length INTEGER,
            sni TEXT,
            info TEXT,
            tcp_flags TEXT
        )
    ''')
    # Index on timestamp for fast recent-data queries (ORDER BY timestamp ASC LIMIT N)
    c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)')

    # Forward-compatible schema migration for older databases
    c.execute("PRAGMA table_info(packets)")
    columns = [col[1] for col in c.fetchall()]
    for col, coltype in [
        ('sni', 'TEXT'),
        ('src_port', 'INTEGER'),
        ('dst_port', 'INTEGER'),
        ('info', 'TEXT'),
        ('tcp_flags', 'TEXT'),
    ]:
        if col not in columns:
            c.execute(f"ALTER TABLE packets ADD COLUMN {col} {coltype}")

    # ── SNMP metrics table ────────────────────────────────────────────────────
    c.execute('''
        CREATE TABLE IF NOT EXISTS snmp_metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   DATETIME,
            device_ip   TEXT,
            device_name TEXT,
            if_index    INTEGER,
            if_name     TEXT,
            in_octets   INTEGER,
            out_octets  INTEGER,
            in_bps      REAL,
            out_bps     REAL,
            in_errors   INTEGER,
            out_errors  INTEGER,
            if_status   INTEGER,
            cpu_pct     REAL
        )
    ''')
    c.execute(
        'CREATE INDEX IF NOT EXISTS idx_snmp_ts ON snmp_metrics(timestamp)'
    )
    c.execute(
        'CREATE INDEX IF NOT EXISTS idx_snmp_device ON snmp_metrics(device_ip)'
    )

    # ── Security alerts history table ─────────────────────────────────────────
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   DATETIME DEFAULT (datetime('now')),
            severity    TEXT,
            category    TEXT,
            src_ip      TEXT,
            dst_ip      TEXT,
            detail      TEXT
        )
    ''')
    c.execute(
        'CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)'
    )

    # ── ARP cache for spoofing detection ─────────────────────────────────────
    c.execute('''
        CREATE TABLE IF NOT EXISTS arp_cache (
            ip   TEXT PRIMARY KEY,
            mac  TEXT,
            seen DATETIME DEFAULT (datetime('now'))
        )
    ''')

    # ── Session notes ─────────────────────────────────────────────────────────
    c.execute('''
        CREATE TABLE IF NOT EXISTS session_notes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT (datetime('now')),
            note      TEXT
        )
    ''')

    conn.commit()
    conn.close()


def _flush_batch(batch: list) -> None:
    """Bulk-insert a list of packet tuples using executemany (much faster than one-by-one)."""
    if not batch:
        return
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        c = conn.cursor()
        c.executemany(
            '''INSERT INTO packets
               (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, sni, info, tcp_flags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            batch,
        )
        conn.commit()
        conn.close()
    except Exception:
        logger.error("Batch insert failed", exc_info=True)


def insert_packet(timestamp, src_ip, dst_ip, src_port, dst_port,
                  protocol, length, sni=None, info=None, tcp_flags=None):
    """Queue a packet and flush to SQLite when the batch is full.

    Callers do not need to change — signature is identical to the original.
    """
    global _batch
    _batch.append((timestamp, src_ip, dst_ip, src_port, dst_port,
                   protocol, length, sni, info, tcp_flags))
    if len(_batch) >= _BATCH_SIZE:
        _flush_batch(_batch)
        _batch = []


def flush_remaining():
    """Call this on sniffer shutdown to write any partial batch to disk."""
    global _batch
    if _batch:
        _flush_batch(_batch)
        _batch = []


def get_data(limit=10000):
    """Return the most recent `limit` packets ordered oldest-first for charting."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        # Single ORDER BY ASC avoids the double-sort that existed before
        query = (
            "SELECT * FROM ("
            f"  SELECT * FROM packets ORDER BY timestamp DESC LIMIT {limit}"
            ") ORDER BY timestamp ASC"
        )
        df = pd.read_sql_query(query, conn)
        conn.close()
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception:
        logger.error("Error reading from database", exc_info=True)
        return pd.DataFrame()


def clear_db():
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        c = conn.cursor()
        c.execute("DELETE FROM packets")
        conn.commit()
        conn.close()
    except Exception:
        logger.error("Database clear failed", exc_info=True)


def cleanup_old_records(limit=3000):
    """Circular logging: keep only the latest `limit` records.

    Fix #8: Only runs the expensive DELETE when the table is actually over limit,
    avoiding a slow subquery on every 2-second Streamlit refresh.
    """
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        c = conn.cursor()

        # Fast COUNT check first — skip DELETE if we are within the limit
        c.execute("SELECT COUNT(*) FROM packets")
        count = c.fetchone()[0]
        if count > limit:
            c.execute(f'''
                DELETE FROM packets
                WHERE id NOT IN (
                    SELECT id FROM packets
                    ORDER BY timestamp DESC
                    LIMIT {limit}
                )
            ''')
            conn.commit()
            logger.debug("Cleaned up %d old records", count - limit)
        conn.close()
    except Exception:
        logger.error("Cleanup error", exc_info=True)


def get_packets_as_pcap(limit=10000, df_filtered: "pd.DataFrame | None" = None):
    """Build a real .pcap file from stored packet metadata.

    If `df_filtered` is supplied (e.g. from the active display filter), only
    those rows are exported. Otherwise the most recent `limit` raw rows are used.

    Returns raw bytes for st.download_button.
    Note: Payloads are blank (we only stored headers), but the pcap is
    valid and openable in Wireshark.
    """
    try:
        from scapy.all import IP, TCP, UDP, ICMP, wrpcap  # type: ignore[attr-defined]
        df = df_filtered if df_filtered is not None else get_data(limit=limit)
        if df is None or df.empty:
            return None

        protocol_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
        packets = []

        for _, row in df.iterrows():
            try:
                proto_num = protocol_map.get(row['protocol'], 0)
                ip_layer = IP(
                    src=str(row['src_ip']),
                    dst=str(row['dst_ip']),
                    proto=proto_num,
                    len=int(row['length']),
                )
                if row['protocol'] == 'TCP':
                    pkt = ip_layer / TCP(
                        sport=int(row.get('src_port', 0) or 0),
                        dport=int(row.get('dst_port', 0) or 0),
                    )
                elif row['protocol'] == 'UDP':
                    pkt = ip_layer / UDP(
                        sport=int(row.get('src_port', 0) or 0),
                        dport=int(row.get('dst_port', 0) or 0),
                    )
                elif row['protocol'] == 'ICMP':
                    pkt = ip_layer / ICMP()
                else:
                    pkt = ip_layer
                packets.append(pkt)
            except Exception:
                continue

        if not packets:
            return None

        # scapy's wrpcap() calls buf.close() after writing, which makes
        # getvalue() raise ValueError on a plain BytesIO.  Use a subclass
        # that silently ignores close() so we can read the bytes afterwards.
        class _UnclosableBytesIO(io.BytesIO):
            def close(self) -> None:
                pass  # intentionally suppress close so getvalue() still works

        buf = _UnclosableBytesIO()
        wrpcap(buf, packets)
        data = buf.getvalue()
        io.BytesIO.close(buf)  # now actually close to free memory
        return data

    except Exception:
        logger.error("PCAP export error", exc_info=True)
        return None


# ════════════════════════════════════════════════════════════════════════════
#  SNMP metric persistence
# ════════════════════════════════════════════════════════════════════════════

def insert_snmp_metric(
    timestamp: str,
    device_ip: str,
    device_name: str,
    if_index: int,
    if_name: str,
    in_octets: int,
    out_octets: int,
    in_bps: float,
    out_bps: float,
    in_errors: int,
    out_errors: int,
    if_status: int,
    cpu_pct: float,
) -> None:
    """Insert a single SNMP poll result row.

    Polling rate is ~30 s so there is no benefit to batching here.
    """
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """INSERT INTO snmp_metrics
               (timestamp, device_ip, device_name, if_index, if_name,
                in_octets, out_octets, in_bps, out_bps,
                in_errors, out_errors, if_status, cpu_pct)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, device_ip, device_name, if_index, if_name,
             in_octets, out_octets, in_bps, out_bps,
             in_errors, out_errors, if_status, cpu_pct),
        )
        conn.commit()
        conn.close()
    except Exception:
        logger.error("SNMP metric insert failed", exc_info=True)


def get_snmp_metrics(device_ip: str | None = None, limit: int = 1000) -> "pd.DataFrame":
    """Return the most recent SNMP rows, optionally filtered by device IP."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        if device_ip:
            query = (
                "SELECT * FROM ("
                f"  SELECT * FROM snmp_metrics WHERE device_ip = ? "
                f"  ORDER BY timestamp DESC LIMIT {limit}"
                ") ORDER BY timestamp ASC"
            )
            df = pd.read_sql_query(query, conn, params=[device_ip])
        else:
            query = (
                "SELECT * FROM ("
                f"  SELECT * FROM snmp_metrics ORDER BY timestamp DESC LIMIT {limit}"
                ") ORDER BY timestamp ASC"
            )
            df = pd.read_sql_query(query, conn)
        conn.close()
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception:
        logger.error("Error reading snmp_metrics", exc_info=True)
        return pd.DataFrame()


def get_snmp_devices() -> list[str]:
    """Return a sorted list of distinct device IPs that have been polled."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        cur = conn.execute(
            "SELECT DISTINCT device_ip FROM snmp_metrics ORDER BY device_ip"
        )
        ips = [row[0] for row in cur.fetchall()]
        conn.close()
        return ips
    except Exception:
        logger.error("Error fetching SNMP device list", exc_info=True)
        return []


def cleanup_snmp_records(limit: int = 5000) -> None:
    """Circular logging: keep only the most recent `limit` SNMP rows."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM snmp_metrics")
        count = c.fetchone()[0]
        if count > limit:
            c.execute(
                f"""DELETE FROM snmp_metrics
                    WHERE id NOT IN (
                        SELECT id FROM snmp_metrics
                        ORDER BY timestamp DESC LIMIT {limit}
                    )"""
            )
            conn.commit()
            logger.debug("Cleaned up %d old SNMP records", count - limit)
        conn.close()
    except Exception:
        logger.error("SNMP cleanup error", exc_info=True)


# ════════════════════════════════════════════════════════════════════════════
#  Security alert history
# ════════════════════════════════════════════════════════════════════════════

def insert_alert(severity: str, category: str, detail: str,
                 src_ip: str = "", dst_ip: str = "") -> None:
    """Persist a security alert so it survives dashboard refreshes."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "INSERT INTO alerts (severity, category, src_ip, dst_ip, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (severity, category, src_ip, dst_ip, detail),
        )
        conn.commit()
        conn.close()
    except Exception:
        logger.error("Alert insert failed", exc_info=True)


def get_alerts(limit: int = 200) -> "pd.DataFrame":
    """Return the most recent security alerts, newest-first."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        df = pd.read_sql_query(
            f"SELECT * FROM alerts ORDER BY timestamp DESC LIMIT {limit}", conn
        )
        conn.close()
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception:
        logger.error("Error reading alerts", exc_info=True)
        return pd.DataFrame()


def cleanup_alerts(limit: int = 1000) -> None:
    """Keep only the most recent `limit` alert rows."""
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM alerts")
        count = c.fetchone()[0]
        if count > limit:
            c.execute(
                f"DELETE FROM alerts WHERE id NOT IN "
                f"(SELECT id FROM alerts ORDER BY timestamp DESC LIMIT {limit})"
            )
            conn.commit()
        conn.close()
    except Exception:
        logger.error("Alert cleanup error", exc_info=True)


# ════════════════════════════════════════════════════════════════════════════
#  ARP spoofing detection helpers
# ════════════════════════════════════════════════════════════════════════════

def check_and_update_arp(ip: str, mac: str) -> str | None:
    """Return a conflict description if the MAC for `ip` changed, else None.

    Also updates the arp_cache table with the latest mapping.
    """
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        cur = conn.execute("SELECT mac FROM arp_cache WHERE ip = ?", (ip,))
        row = cur.fetchone()
        conflict: str | None = None
        if row:
            old_mac = row[0]
            if old_mac != mac:
                conflict = (
                    f"ARP Spoof? IP {ip} changed MAC: {old_mac} → {mac}"
                )
                conn.execute(
                    "UPDATE arp_cache SET mac=?, seen=datetime('now') WHERE ip=?",
                    (mac, ip),
                )
        else:
            conn.execute(
                "INSERT INTO arp_cache (ip, mac) VALUES (?, ?)", (ip, mac)
            )
        conn.commit()
        conn.close()
        return conflict
    except Exception:
        logger.error("ARP cache error", exc_info=True)
        return None


# ════════════════════════════════════════════════════════════════════════════
#  Session notes
# ════════════════════════════════════════════════════════════════════════════

def add_session_note(note: str) -> None:
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("INSERT INTO session_notes (note) VALUES (?)", (note,))
        conn.commit()
        conn.close()
    except Exception:
        logger.error("Session note insert failed", exc_info=True)


def get_session_notes(limit: int = 50) -> "pd.DataFrame":
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        df = pd.read_sql_query(
            f"SELECT * FROM session_notes ORDER BY timestamp DESC LIMIT {limit}",
            conn,
        )
        conn.close()
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception:
        logger.error("Session notes read failed", exc_info=True)
        return pd.DataFrame()

"""
PacketLens — SNMP Device Poller
================================
Periodically polls one or more SNMP-capable devices (routers, switches, APs)
and stores per-interface metrics in the snmp_metrics SQLite table so the
Streamlit dashboard can display device-level bandwidth, error rates, and health.

Supported SNMP versions
-----------------------
* SNMPv2c (default) - community string authentication, no encryption.
* SNMPv3            - username + auth/priv key, full encryption.

Usage (CLI one-shot test — no Streamlit required)
-------------------------------------------------
    python snmp_poller.py --target 192.168.1.1 --community public --once

Usage (from app.py)
-------------------
    from snmp_poller import SnmpPoller, SnmpTarget
    poller = SnmpPoller()
    poller.start(targets=[SnmpTarget("192.168.1.1")], interval_s=30)
    ...
    poller.stop()

OIDs collected
--------------
    ifDescr          1.3.6.1.2.1.2.2.1.2
    ifOperStatus     1.3.6.1.2.1.2.2.1.8
    ifInOctets       1.3.6.1.2.1.2.2.1.10
    ifOutOctets      1.3.6.1.2.1.2.2.1.16
    ifInErrors       1.3.6.1.2.1.2.2.1.14
    ifOutErrors      1.3.6.1.2.1.2.2.1.20
    sysName          1.3.6.1.2.1.1.5.0
    hrProcessorLoad  1.3.6.1.2.1.25.3.3.1.2
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import database

logger = logging.getLogger("packetlens.snmp")

# ── OID constants ──────────────────────────────────────────────────────────────
_OID_SYS_NAME      = "1.3.6.1.2.1.1.5.0"
_OID_IF_DESCR      = "1.3.6.1.2.1.2.2.1.2"
_OID_IF_STATUS     = "1.3.6.1.2.1.2.2.1.8"
_OID_IF_IN_OCTETS  = "1.3.6.1.2.1.2.2.1.10"
_OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
_OID_IF_IN_ERRORS  = "1.3.6.1.2.1.2.2.1.14"
_OID_IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
_OID_CPU_LOAD      = "1.3.6.1.2.1.25.3.3.1.2"


def _build_auth(target: "SnmpTarget"):
    """Return the correct pysnmp auth object for the target's SNMP version.

    For SNMPv3 we map protocol name strings to the pysnmp typed OID objects
    so that auth and encryption work correctly.
    """
    from pysnmp.hlapi.asyncio import (  # type: ignore[import-untyped]
        CommunityData, UsmUserData,
    )
    if target.version != "3":
        return CommunityData(target.community, mpModel=1)

    # Map auth protocol string → pysnmp constant
    try:
        from pysnmp.proto.secmod.rfc3826.priv.aes import Aes  # type: ignore[import-untyped]
        from pysnmp.proto.secmod.rfc3414.auth.hmacmd5 import HmacMd5  # type: ignore[import-untyped]
        from pysnmp.proto.secmod.rfc3414.auth.hmacsha import HmacSha  # type: ignore[import-untyped]
        from pysnmp.proto.secmod.rfc3414.priv.des import Des  # type: ignore[import-untyped]
        _AUTH_MAP = {"SHA": HmacSha.serviceID, "MD5": HmacMd5.serviceID}
        _PRIV_MAP = {"AES": Aes.serviceID, "DES": Des.serviceID}
        auth_proto = _AUTH_MAP.get(target.auth_protocol.upper())
        priv_proto = _PRIV_MAP.get(target.priv_protocol.upper())
    except Exception:
        auth_proto = None
        priv_proto = None

    return UsmUserData(
        target.username,
        authKey=target.auth_key or None,
        privKey=target.priv_key or None,
        authProtocol=auth_proto,
        privProtocol=priv_proto,
    )


@dataclass
class SnmpTarget:
    """Connection parameters for one SNMP-enabled device."""
    host:          str
    port:          int = 161
    version:       str = "2c"      # "2c" or "3"
    community:     str = "public"  # SNMPv2c community string
    # SNMPv3 credentials (ignored when version == "2c")
    username:      str = "public"
    auth_protocol: str = "SHA"     # "SHA" | "MD5"
    priv_protocol: str = "AES"     # "AES" | "DES"
    auth_key:      str = ""
    priv_key:      str = ""


@dataclass
class _PrevCounters:
    """Stores previous poll values for bytes/sec delta calculation."""
    timestamp:  float          = 0.0
    in_octets:  dict[int, int] = field(default_factory=dict)
    out_octets: dict[int, int] = field(default_factory=dict)
    in_errors:  dict[int, int] = field(default_factory=dict)
    out_errors: dict[int, int] = field(default_factory=dict)


# ── Low-level SNMP helpers ─────────────────────────────────────────────────────

async def _snmp_get(target: SnmpTarget, oid: str) -> Any | None:
    """Fetch a single scalar OID value from a device."""
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore[import-untyped]
            CommunityData, ContextData, ObjectIdentity, ObjectType,
            SnmpEngine, UdpTransportTarget, UsmUserData,
            get_cmd,  # pysnmp v7 snake_case API
        )
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create(
            (target.host, target.port), timeout=3, retries=1
        )
        auth = _build_auth(target)
        error_indication, error_status, _, var_binds = await get_cmd(
            engine, auth, transport, ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        if error_indication or error_status:
            return None
        for var_bind in var_binds:
            try:
                return int(var_bind[1])
            except Exception:
                return str(var_bind[1])
    except Exception as exc:
        logger.debug("SNMP GET %s %s failed: %s", target.host, oid, exc)
        return None


async def _snmp_walk(target: SnmpTarget, base_oid: str) -> dict[int, Any]:
    """Walk a table OID and return {if_index: value} dict."""
    results: dict[int, Any] = {}
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore[import-untyped]
            CommunityData, ContextData, ObjectIdentity, ObjectType,
            SnmpEngine, UdpTransportTarget, UsmUserData,
            walk_cmd,  # pysnmp v7 replaces nextCmd; stops at subtree boundary automatically
        )
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create(
            (target.host, target.port), timeout=3, retries=1
        )
        auth = _build_auth(target)
        async for (err_ind, err_status, _, var_binds) in walk_cmd(
            engine, auth, transport, ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
        ):
            if err_ind or err_status:
                break
            for var_bind in var_binds:
                oid_parts = str(var_bind[0]).split(".")
                if not oid_parts:
                    continue
                try:
                    idx = int(oid_parts[-1])
                    results[idx] = int(var_bind[1])
                except (ValueError, TypeError):
                    continue
    except Exception as exc:
        logger.debug("SNMP WALK %s %s failed: %s", target.host, base_oid, exc)
    return results


# ── High-level poll function ───────────────────────────────────────────────────

async def poll_device(
    target: SnmpTarget,
    prev: _PrevCounters,
) -> list[dict]:
    """Poll one device and return a list of per-interface metric dicts.

    Each dict maps directly to a row in the snmp_metrics table.
    Consecutive polls produce in_bps / out_bps from counter deltas.
    """
    now = datetime.now()
    now_ts = now.timestamp()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")

    # Fetch all OIDs concurrently for speed
    (
        sys_name, if_descrs, if_statuses,
        in_octets, out_octets, in_errors, out_errors, cpu_loads,
    ) = await asyncio.gather(
        _snmp_get(target, _OID_SYS_NAME),
        _snmp_walk(target, _OID_IF_DESCR),
        _snmp_walk(target, _OID_IF_STATUS),
        _snmp_walk(target, _OID_IF_IN_OCTETS),
        _snmp_walk(target, _OID_IF_OUT_OCTETS),
        _snmp_walk(target, _OID_IF_IN_ERRORS),
        _snmp_walk(target, _OID_IF_OUT_ERRORS),
        _snmp_walk(target, _OID_CPU_LOAD),
    )

    device_name: str = str(sys_name) if sys_name else target.host
    cpu_pct: float = (
        sum(cpu_loads.values()) / len(cpu_loads) if cpu_loads else 0.0
    )
    elapsed = now_ts - prev.timestamp if prev.timestamp else None
    rows: list[dict] = []

    for if_idx, if_name in (if_descrs or {}).items():
        in_oct  = in_octets.get(if_idx, 0)
        out_oct = out_octets.get(if_idx, 0)
        in_err  = in_errors.get(if_idx, 0)
        out_err = out_errors.get(if_idx, 0)
        status  = if_statuses.get(if_idx, 0)

        # Derive bytes/sec from counter delta (guard wrap-around with abs)
        if elapsed and elapsed > 0 and if_idx in prev.in_octets:
            in_bps  = abs(in_oct  - prev.in_octets.get(if_idx, 0))  / elapsed
            out_bps = abs(out_oct - prev.out_octets.get(if_idx, 0)) / elapsed
        else:
            in_bps = out_bps = 0.0

        rows.append({
            "timestamp":   timestamp_str,
            "device_ip":   target.host,
            "device_name": device_name,
            "if_index":    if_idx,
            "if_name":     str(if_name),
            "in_octets":   in_oct,
            "out_octets":  out_oct,
            "in_bps":      round(in_bps, 2),
            "out_bps":     round(out_bps, 2),
            "in_errors":   in_err,
            "out_errors":  out_err,
            "if_status":   status,
            "cpu_pct":     round(cpu_pct, 1),
        })

    # Update previous counters for next poll
    prev.timestamp  = now_ts
    prev.in_octets  = dict(in_octets  or {})
    prev.out_octets = dict(out_octets or {})
    prev.in_errors  = dict(in_errors  or {})
    prev.out_errors = dict(out_errors or {})

    logger.debug(
        "Polled %s (%s): %d interfaces, CPU=%.1f%%",
        target.host, device_name, len(rows), cpu_pct,
    )
    return rows


# ── Poller class ───────────────────────────────────────────────────────────────

class SnmpPoller:
    """Runs a periodic SNMP polling loop in a background daemon thread.

    Example::

        poller = SnmpPoller()
        poller.start(targets=[SnmpTarget("192.168.1.1")], interval_s=30)
        # ... app runs ...
        poller.stop()
    """

    def __init__(self) -> None:
        self._thread:   threading.Thread | None = None
        self._stop_evt: threading.Event          = threading.Event()
        self._targets:  list[SnmpTarget]         = []
        self._interval: int                      = 30
        self._prev:     dict[str, _PrevCounters] = {}  # keyed by target.host

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self, targets: list[SnmpTarget], interval_s: int = 30) -> None:
        """Start the polling thread. Safe to call again after stop()."""
        if self._thread and self._thread.is_alive():
            logger.warning("SnmpPoller already running — ignoring start()")
            return
        self._targets  = targets
        self._interval = interval_s
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="snmp-poller"
        )
        self._thread.start()
        logger.info(
            "SNMP poller started: %d target(s), interval=%ds",
            len(targets), interval_s,
        )

    def stop(self) -> None:
        """Signal the polling loop to stop and wait for the thread to exit."""
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("SNMP poller stopped.")

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ── Internal ───────────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Entry point for the background thread — owns its own asyncio loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._async_loop())
        finally:
            loop.close()

    async def _async_loop(self) -> None:
        """Async polling loop: poll all targets, persist, sleep, repeat."""
        database.init_db()  # ensure table exists in this thread context

        for t in self._targets:
            if t.host not in self._prev:
                self._prev[t.host] = _PrevCounters()

        while not self._stop_evt.is_set():
            await self._poll_all()
            database.cleanup_snmp_records()
            # Sleep in 0.5 s increments so stop() is responsive
            for _ in range(self._interval * 2):
                if self._stop_evt.is_set():
                    break
                await asyncio.sleep(0.5)

    async def _poll_all(self) -> None:
        """Poll every target concurrently and persist results."""
        tasks = [
            poll_device(t, self._prev[t.host]) for t in self._targets
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for target, result in zip(self._targets, results):
            if isinstance(result, BaseException):
                logger.warning("Poll failed for %s: %s", target.host, result)
                continue
            for row in result:
                database.insert_snmp_metric(**row)


# ── CLI entry-point (one-shot testing without Streamlit) ──────────────────────

def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="PacketLens — SNMP one-shot poll (for testing)"
    )
    parser.add_argument("--target",    required=True, help="Device IP address")
    parser.add_argument("--community", default="public", help="SNMP community string")
    parser.add_argument("--port",      type=int, default=161)
    parser.add_argument("--version",   default="2c", choices=["2c", "3"])
    parser.add_argument(
        "--once", action="store_true",
        help="Poll once, print results, and exit (does NOT write to DB)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    target = SnmpTarget(
        host=args.target,
        port=args.port,
        version=args.version,
        community=args.community,
    )
    prev = _PrevCounters()

    async def _run() -> None:
        rows = await poll_device(target, prev)
        if not rows:
            print(
                f"No data returned from {args.target}. "
                "Check that SNMP is enabled on the device."
            )
            return
        print(f"Device : {rows[0]['device_name']}")
        print(f"CPU    : {rows[0]['cpu_pct']}%")
        print()
        print(f"{'IDX':>4}  {'Interface':<22} {'Status':<6} {'In B/s':>12} {'Out B/s':>12}")
        print("-" * 62)
        for row in rows:
            status_str = "UP" if row["if_status"] == 1 else "DOWN"
            print(
                f"{row['if_index']:>4}  {row['if_name']:<22} "
                f"{status_str:<6} "
                f"{row['in_bps']:>12.0f} "
                f"{row['out_bps']:>12.0f}"
            )

    print(
        f"Polling {args.target}  "
        f"(community={args.community}, SNMPv{args.version})..."
    )
    asyncio.run(_run())


if __name__ == "__main__":
    _cli()

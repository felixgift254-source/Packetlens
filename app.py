import streamlit as st  # type: ignore[import-untyped]
import pandas as pd
import plotly.express as px  # type: ignore[import-untyped]
import plotly.graph_objects as go  # type: ignore[import-untyped]
import time
import database
import requests
import ipaddress
import subprocess
import sys
import os
import yaml
import joblib
import networkx as nx
from datetime import datetime
from pathlib import Path
from typing import cast
from sklearn.ensemble import IsolationForest
from snmp_poller import SnmpPoller, SnmpTarget

# ── Load configuration (Fix #10: no more hardcoded magic numbers) ─────────────
_CFG_PATH = Path(__file__).parent / "config.yaml"
if _CFG_PATH.exists():
    with open(_CFG_PATH) as _f:
        _CFG = yaml.safe_load(_f)
else:
    _CFG = {}  # safe fallback if config.yaml is missing

_THRESHOLDS  = _CFG.get("thresholds", {})
_THREAT      = _CFG.get("threat_intel", {})
_GEO         = _CFG.get("geo", {})
_ML_CFG      = _CFG.get("ml", {})

CIRC_LIMIT         = _THRESHOLDS.get("circular_log_limit", 3000)
BW_SPIKE_THRESHOLD = _THRESHOLDS.get("bandwidth_spike_bytes_per_sec", 5_000_000)
PORTSCAN_THRESHOLD = _THRESHOLDS.get("port_scan_unique_ports", 15)
PORTSCAN_WINDOW_S  = _THRESHOLDS.get("port_scan_window_seconds", 30)
GEO_TIMEOUT        = _GEO.get("api_timeout_seconds", 2)
ML_CONTAMINATION   = _ML_CFG.get("contamination", 0.05)
ML_RETRAIN_DELTA   = _ML_CFG.get("retrain_threshold", 2)

# ── SNMP config ───────────────────────────────────────────────────────────────
_SNMP_CFG          = _CFG.get("snmp", {})
_SNMP_THRESHOLDS   = _SNMP_CFG.get("thresholds", {})
SNMP_DEFAULT_INT   = int(_SNMP_CFG.get("poll_interval_seconds", 30))
SNMP_DEFAULT_COMM  = str(_SNMP_CFG.get("community", "public"))
SNMP_DEFAULT_VER   = str(_SNMP_CFG.get("version", "2c"))
SNMP_DEFAULT_PORT  = int(_SNMP_CFG.get("port", 161))
SNMP_CPU_ALERT     = float(_SNMP_THRESHOLDS.get("cpu_alert_pct", 80))
SNMP_ERR_ALERT     = float(_SNMP_THRESHOLDS.get("error_rate_alert", 100))
SNMP_LINK_ALERT    = bool(_SNMP_THRESHOLDS.get("link_down_alert", True))

SUSPICIOUS_PORTS   = {int(k): v for k, v in _THREAT.get("suspicious_ports", {
    4444: "Metasploit", 1337: "Leet", 31337: "BackOrifice", 6667: "IRC/Botnet"
}).items()}
BLOCKLIST_IPS      = list(_THREAT.get("blocklist_ips", []))
SNMP_CLEANUP_LIMIT = int(_SNMP_CFG.get("snmp_cleanup_limit", 5000))

# Persisted IsolationForest model path (survives Streamlit restarts)
_ML_MODEL_PATH = Path(__file__).parent / ".ml_model.joblib"

# ── PID lockfile path (Fix #3) ────────────────────────────────────────────────
LOCKFILE = Path(__file__).parent / "sniffer.pid"

# ── Page config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="LYFT PacketLens — Network Traffic Analyzer",
    page_icon="🔬",
    layout="wide",
)

# ── Port → Service label lookup ──────────────────────────────────────────────
PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1194: "OpenVPN", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# ── Helper: detect available interfaces ─────────────────────────────────────
@st.cache_data(ttl=30)
def get_interfaces():
    try:
        raw = subprocess.check_output(["ip", "-o", "link", "show"], stderr=subprocess.DEVNULL).decode()
        ifaces = []
        for line in raw.strip().splitlines():
            parts = line.split(": ")
            if len(parts) >= 2:
                name = parts[1].split("@")[0].strip()
                if name != "lo":
                    ifaces.append(name)
        return ifaces if ifaces else ["eth0"]
    except Exception:
        return ["eth0", "wlan0"]

# ── Helper: geo-location (cached per IP, no rate-limit risk) ─────────────────
@st.cache_data(max_entries=1000)
def get_ip_location(ip: str):
    try:
        addr = ipaddress.ip_address(ip)
        # Skip private, loopback, link-local, multicast, and IPv6 addresses
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return None
        if addr.version == 6:
            return None
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,isp,as", timeout=GEO_TIMEOUT)
        d = r.json()
        if d.get("status") == "success":
            return d["lat"], d["lon"], d.get("country", "?"), d.get("city", "?"), d.get("isp", "?"), d.get("as", "?")
    except Exception:
        pass
    return None

# ── Helper: apply display filters to DataFrame ───────────────────────────────
def apply_filters(df: pd.DataFrame, filter_text: str, proto_filter: str, port_filter: str) -> pd.DataFrame:
    out = df.copy()
    if filter_text:
        mask = (
            out["src_ip"].str.contains(filter_text, case=False, na=False) |
            out["dst_ip"].str.contains(filter_text, case=False, na=False) |
            out["sni"].astype(str).str.contains(filter_text, case=False, na=False)
        )
        out = out[mask]
    if proto_filter != "All":
        out = out[out["protocol"] == proto_filter]
    if port_filter.strip():
        try:
            p = int(port_filter.strip())
            out = out[out["dst_port"].eq(p) | out["src_port"].eq(p)]
        except ValueError:
            pass
    return out  # type: ignore

# ── Init DB ──────────────────────────────────────────────────────────────────
database.init_db()

# ════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ════════════════════════════════════════════════════════════════════════════
st.sidebar.image(
    "https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/wireshark.svg",
    width=36,
)
st.sidebar.title("LYFT PacketLens 🔬")
st.sidebar.caption("Real-Time Network Traffic Analyzer")
st.sidebar.markdown("---")

# ── Interface auto-detection ─────────────────────────────────────────────────
st.sidebar.subheader("📡 Capture Interface")
ifaces = get_interfaces()
interface = st.sidebar.selectbox(
    "Select Interface",
    options=ifaces,
    index=0,
    help="Auto-detected from your system. Run `ip link show` to verify.",
)

# ── cap_net_raw privilege check ───────────────────────────────────────────────
@st.cache_data(ttl=60)
def _has_cap_net_raw() -> bool:
    """Return True if the current Python binary has cap_net_raw set."""
    try:
        out = subprocess.check_output(
            ["getcap", sys.executable], stderr=subprocess.DEVNULL
        ).decode()
        return "cap_net_raw" in out
    except Exception:
        return False

if not _has_cap_net_raw():
    st.sidebar.warning(
        "⚠️ **No raw-socket capability detected.**\n\n"
        "Grant it once to avoid running with `sudo`:\n"
        "```\nsudo setcap cap_net_raw=eip $(which python3)\n```"
    )

# ── Capture controls ──────────────────────────────────────────────────────────
st.sidebar.markdown("---")
st.sidebar.subheader("▶ Capture Controls")

bpf_filter = st.sidebar.text_input("BPF Capture Filter", value="", help="e.g. tcp port 80, host 8.8.8.8")

# Fix #3: Restore PID from lockfile on every page load so state survives
# Streamlit restarts, hot-reloads, and browser tab refreshes.
if "sniffer_pid" not in st.session_state:
    if LOCKFILE.exists():
        try:
            _stored_pid = int(LOCKFILE.read_text().strip())
            os.kill(_stored_pid, 0)           # signal 0 = liveness check only
            st.session_state.sniffer_pid  = _stored_pid
            st.session_state.sniffer_pgid = None
        except (OSError, ValueError):
            # Process is dead or PID file is corrupt — clean up
            LOCKFILE.unlink(missing_ok=True)
            st.session_state.sniffer_pid  = None
            st.session_state.sniffer_pgid = None
    else:
        st.session_state.sniffer_pid  = None
        st.session_state.sniffer_pgid = None

# Periodic liveness check on every refresh (catches crashes mid-session)
if st.session_state.sniffer_pid is not None:
    try:
        os.kill(st.session_state.sniffer_pid, 0)
    except OSError:
        # Sniffer died unexpectedly
        LOCKFILE.unlink(missing_ok=True)
        st.session_state.sniffer_pid  = None
        st.session_state.sniffer_pgid = None

cap_col1, cap_col2 = st.sidebar.columns(2)
start_btn = cap_col1.button("▶ Start", width="stretch")
stop_btn  = cap_col2.button("⏹ Stop",  width="stretch")

if start_btn:
    if st.session_state.sniffer_pid is None:
        cmd = [sys.executable, "sniffer.py", "-i", str(interface)]
        if bpf_filter.strip():
            cmd.extend(["-f", bpf_filter.strip()])
        # Start in a new process group so we can kill the whole tree (sniffer + sudo child)
        proc = subprocess.Popen(cmd, start_new_session=True)
        st.session_state.sniffer_pid  = proc.pid
        st.session_state.sniffer_pgid = os.getpgid(proc.pid)
        LOCKFILE.write_text(str(proc.pid))    # persist PID for restart recovery
        st.sidebar.success(f"Sniffing on **{interface}** (PID {proc.pid})")
        st.rerun()  # immediately refresh so dashboard shows live data
    else:
        st.sidebar.warning("Capture already running.")

if stop_btn:
    if st.session_state.sniffer_pid is not None:
        # Kill the entire process group so the sudo child (Scapy) is not orphaned
        pgid = st.session_state.get("sniffer_pgid")
        if pgid:
            subprocess.run(["kill", "--", f"-{pgid}"])
        else:
            subprocess.run(["kill", str(st.session_state.sniffer_pid)])
        st.session_state.sniffer_pid  = None
        st.session_state.sniffer_pgid = None
        LOCKFILE.unlink(missing_ok=True)       # clean up lockfile on stop
        st.sidebar.info("Capture stopped.")
    else:
        st.sidebar.warning("No capture is running.")

# Status pill
if st.session_state.sniffer_pid:
    st.sidebar.success(f"🟢 Live — PID {st.session_state.sniffer_pid}")
else:
    st.sidebar.error("🔴 Idle")

# ── ML Controls ───────────────────────────────────────────────────────────────
st.sidebar.markdown("---")
st.sidebar.subheader("🧠 Machine Learning")
if st.sidebar.button("Retrain Isolation Forest", width="stretch", help="Clears the cached baseline and forces a retrain"):
    if _ML_MODEL_PATH.exists():
        _ML_MODEL_PATH.unlink()
    if "ml_model" in st.session_state:
        del st.session_state["ml_model"]
    if "ml_trained_on" in st.session_state:
        del st.session_state["ml_trained_on"]
    st.sidebar.success("Model cache cleared! It will retrain on the next refresh.")

ui_cont = st.sidebar.slider("ML Anomaly Sensitivity", min_value=0.01, max_value=0.15, value=float(ML_CONTAMINATION), step=0.01)
if ui_cont != st.session_state.get("ui_contamination", ML_CONTAMINATION):
    st.session_state["ui_contamination"] = ui_cont
    if _ML_MODEL_PATH.exists():
        _ML_MODEL_PATH.unlink() # Force retrain on next refresh
    if "ml_model" in st.session_state:
        del st.session_state["ml_model"]

# ── Data controls ─────────────────────────────────────────────────────────────
st.sidebar.markdown("---")
st.sidebar.subheader("⚙ Data Controls")
if st.sidebar.button("🗑 Clear Database", width="stretch"):
    database.clear_db()
    st.sidebar.success("Database cleared!")

refresh_rate = st.sidebar.slider("Refresh Rate (seconds)", min_value=3, max_value=30, value=15)
auto_refresh  = st.sidebar.checkbox("Auto-Refresh", value=True)
enable_heavy_viz = st.sidebar.checkbox("Enable Advanced Visualizations (High CPU/RAM)", value=False)

# ── PCAP Export (exports the active filtered view, not just all data) ─────────
st.sidebar.markdown("---")
st.sidebar.subheader("📦 Export Session")
if st.sidebar.button("Build PCAP", width="stretch"):
    with st.spinner("Building PCAP…"):
        # Use the filtered DataFrame stored by render_dashboard if available
        _export_df = st.session_state.get("pcap_export_df", None)
        pcap_bytes = database.get_packets_as_pcap(df_filtered=_export_df)
    if pcap_bytes:
        st.session_state["pcap_bytes"] = pcap_bytes
        _nrows = len(_export_df) if _export_df is not None else "all"
        st.sidebar.success(f"Ready ({_nrows} packets) — click Download ↓")
    else:
        st.sidebar.warning("No data to export yet.")

if "pcap_bytes" in st.session_state and st.session_state["pcap_bytes"]:
    fname = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    st.sidebar.download_button(
        label="⬇ Download .pcap",
        data=st.session_state["pcap_bytes"],
        file_name=fname,
        mime="application/vnd.tcpdump.pcap",
        width="stretch",
    )

# ── PCAP Import ───────────────────────────────────────────────────────────────
st.sidebar.markdown("---")
st.sidebar.subheader("📂 Import Offline PCAP")
uploaded_pcap = st.sidebar.file_uploader("Upload .pcap / .pcapng", type=["pcap", "pcapng"])
if uploaded_pcap is not None:
    if st.sidebar.button("Process PCAP", width="stretch"):
        # Fix #7: Warn and require explicit confirmation before wiping live data
        st.sidebar.warning("⚠️ This will **DELETE all live capture data** and replace it with the PCAP contents.")
        confirmed = st.sidebar.checkbox("✅ I understand — proceed with import", key="pcap_import_confirm")
        if confirmed:
            with st.spinner("Parsing Offline PCAP..."):
                _backup_dir = Path(__file__).parent / ".backup"
                _backup_dir.mkdir(parents=True, exist_ok=True)
                temp_pcap = str(_backup_dir / "uploaded_packetlens.pcap")
                with open(temp_pcap, "wb") as f:
                    f.write(uploaded_pcap.read())
                database.clear_db()
                subprocess.run([sys.executable, "sniffer.py", "-r", temp_pcap])
                st.sidebar.success("PCAP imported — live data cleared and replaced. Dashboard will update.")
                st.rerun()
        else:
            st.sidebar.info("Check the box above to confirm before importing.")

# ── SNMP Polling ──────────────────────────────────────────────────────────────
st.sidebar.markdown("---")
with st.sidebar.expander("🖧 SNMP Device Polling", expanded=False):
    snmp_targets_raw = st.text_area(
        "Target Device IPs (one per line)",
        value="\n".join(_SNMP_CFG.get("targets", [])),
        height=80,
        help="IP addresses of routers/switches with SNMP enabled.",
        key="snmp_targets_input",
    )
    snmp_version = st.selectbox(
        "SNMP Version", ["2c", "3"], index=0 if SNMP_DEFAULT_VER == "2c" else 1,
        key="snmp_version",
    )
    snmp_community = st.text_input(
        "Community String", value=SNMP_DEFAULT_COMM, key="snmp_community",
        disabled=(st.session_state.get("snmp_version", "2c") == "3"),
    )

    # SNMPv3 credentials — only shown when version "3" is selected
    if st.session_state.get("snmp_version") == "3":
        st.markdown("**SNMPv3 Credentials**")
        snmp_username    = st.text_input("Username",      key="snmp_username",    value=str(_SNMP_CFG.get("username", "admin")))
        snmp_auth_proto  = st.selectbox("Auth Protocol",  ["SHA", "MD5"],         key="snmp_auth_proto")
        snmp_auth_key    = st.text_input("Auth Key",       key="snmp_auth_key",   type="password")
        snmp_priv_proto  = st.selectbox("Priv Protocol",  ["AES", "DES"],         key="snmp_priv_proto")
        snmp_priv_key    = st.text_input("Priv Key",       key="snmp_priv_key",   type="password")
    else:
        snmp_username   = "public"
        snmp_auth_proto = "SHA"
        snmp_auth_key   = ""
        snmp_priv_proto = "AES"
        snmp_priv_key   = ""

    snmp_interval = st.slider(
        "Poll Interval (seconds)", min_value=10, max_value=300,
        value=SNMP_DEFAULT_INT, step=10, key="snmp_interval",
    )

    # Initialise poller singleton in session state
    if "snmp_poller" not in st.session_state:
        st.session_state.snmp_poller = SnmpPoller()

    _poller: SnmpPoller = st.session_state.snmp_poller

    snmp_col1, snmp_col2 = st.columns(2)
    if snmp_col1.button("▶ Start", key="snmp_start", use_container_width=True):
        _target_ips = [
            ip.strip() for ip in snmp_targets_raw.splitlines() if ip.strip()
        ]
        if not _target_ips:
            st.warning("Enter at least one device IP.")
        elif _poller.is_running:
            st.warning("SNMP polling already running.")
        else:
            _snmp_targets = [
                SnmpTarget(
                    host=ip,
                    port=SNMP_DEFAULT_PORT,
                    version=str(snmp_version),
                    community=snmp_community,
                    username=snmp_username,
                    auth_protocol=snmp_auth_proto or "SHA",
                    auth_key=snmp_auth_key,
                    priv_protocol=snmp_priv_proto or "AES",
                    priv_key=snmp_priv_key,
                )
                for ip in _target_ips
            ]
            _poller.start(_snmp_targets, interval_s=snmp_interval)
            st.success(f"Polling {len(_snmp_targets)} device(s) every {snmp_interval}s")

    if snmp_col2.button("⏹ Stop", key="snmp_stop", use_container_width=True):
        if _poller.is_running:
            _poller.stop()
            st.info("SNMP polling stopped.")
        else:
            st.warning("No SNMP polling is running.")

    if _poller.is_running:
        st.success("🟢 Polling active")
    else:
        st.caption("🔴 Polling idle")

# ── Session Notes ─────────────────────────────────────────────────────────────
st.sidebar.markdown("---")
with st.sidebar.expander("📝 Session Notes", expanded=False):
    _note_text = st.text_area(
        "Add a note about this capture session",
        height=80,
        placeholder="e.g. 'Baseline traffic Mon morning, no VPN'",
        key="session_note_input",
    )
    if st.button("💾 Save Note", key="save_note"):
        if _note_text.strip():
            database.add_session_note(_note_text.strip())
            st.success("Note saved!")
        else:
            st.warning("Note is empty.")
    _notes_df = database.get_session_notes(limit=10)
    if not _notes_df.empty:
        st.markdown("**Recent notes:**")
        for _, _n in _notes_df.iterrows():
            st.caption(f"🕐 {_n['timestamp'].strftime('%m-%d %H:%M')} — {_n['note']}")


# ════════════════════════════════════════════════════════════════════════════
#  MAIN DASHBOARD  (wrapped in a fragment so only the data area re-runs,
#  eliminating the whole-page dim/brighten flicker on every refresh tick)
# ════════════════════════════════════════════════════════════════════════════

@st.fragment(run_every=refresh_rate if auto_refresh else None)
def render_dashboard() -> None:
    st.title("🔬 LYFT PacketLens — Network Traffic Analyzer")
    st.caption("Live capture · Geo-mapping · ML anomaly detection · SNI extraction · PCAP export")

    # ── Fetch & clean data ───────────────────────────────────────────────────
    # Throttle expensive DB cleanup to every 10th refresh tick
    _tick = st.session_state.get("_refresh_tick", 0) + 1
    st.session_state["_refresh_tick"] = _tick
    if _tick % 10 == 1:
        database.cleanup_old_records(limit=CIRC_LIMIT)
        database.cleanup_snmp_records(limit=SNMP_CLEANUP_LIMIT)
        database.cleanup_alerts(limit=1000)
    # Cap fetch to 500 rows — reduces RAM/CPU usage on low-end machines
    _DISPLAY_LIMIT = 500
    df_raw = database.get_data(limit=_DISPLAY_LIMIT)

    if df_raw.empty:
        st.info("No packets captured yet. Select an interface and press **▶ Start**.")
        st.code(f"python3 sniffer.py -i {interface}", language="bash")
        return

    # Fix #12: get_data() already returns rows in ASC order; no re-sort needed.

    # Add port columns if not present (older rows won't have them)
    for col in ["src_port", "dst_port"]:
        if col not in df_raw.columns:
            df_raw[col] = 0
    df_raw["src_port"] = df_raw["src_port"].apply(pd.to_numeric, errors="coerce").fillna(0).astype(int)
    df_raw["dst_port"] = df_raw["dst_port"].apply(pd.to_numeric, errors="coerce").fillna(0).astype(int)

    # Add service labels
    df_raw["service"] = df_raw["dst_port"].map(PORT_SERVICES).fillna(
        df_raw["src_port"].map(PORT_SERVICES)
    ).fillna("—")

    # ── Display Filter Bar & CSV Export ──────────────────────────────────────
    st.subheader("🔍 Display Filter")
    f_col1, f_col2, f_col3 = st.columns([3, 1, 1])
    with f_col1:
        filter_text = st.text_input(
            "Filter by IP or domain",
            placeholder="e.g.  192.168.1.1  or  google.com",
            label_visibility="collapsed",
        )
    with f_col2:
        all_protos = ["All"] + sorted(df_raw["protocol"].unique().tolist())
        proto_filter = st.selectbox("Protocol", all_protos, label_visibility="collapsed")
    with f_col3:
        port_filter = st.text_input("Port", placeholder="e.g. 443", label_visibility="collapsed")

    # Apply filters first so df is always defined before any widget reads it
    df = apply_filters(df_raw, filter_text if filter_text else "", proto_filter if proto_filter else "All", port_filter if port_filter else "")
    if len(df) < len(df_raw):
        st.caption(f"Showing **{len(df):,}** of {len(df_raw):,} packets after filter.")

    # Export the filtered view (already capped at _DISPLAY_LIMIT rows) to
    # avoid sending hundreds of MB over the WebSocket.
    csv_fname = f"capture_filtered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    st.download_button(
        label="⬇ Export to CSV",
        data=df.to_csv(index=False),
        file_name=csv_fname,
        mime="text/csv",
    )

    st.markdown("---")

    # Store filtered df so sidebar PCAP export can respect the active filter
    st.session_state["pcap_export_df"] = df

    # ── Geo-Location Map ──────────────────────────────────────────────────────
    st.subheader("🌍 Destination IP Locations")

    def _make_loc(ip: str):
        loc = get_ip_location(ip)
        return {"ip": ip, "lat": loc[0], "lon": loc[1], "country": loc[2], "city": loc[3], "isp": loc[4], "asn": loc[5]} if loc else None

    # Cap to 50 unique IPs to avoid blocking the main thread with geo-HTTP loops
    _all_dst_ips = sorted(df_raw["dst_ip"].unique())
    unique_dst_ips = tuple(_all_dst_ips[:50])
    _skipped_geo = len(_all_dst_ips) - len(unique_dst_ips)
    locations = [d for ip in unique_dst_ips if (d := _make_loc(ip)) is not None]

    if locations:
        map_df = pd.DataFrame(locations)
        col_map, col_asn = st.columns([3, 1])
        
        with col_map:
            if _skipped_geo > 0:
                st.caption(f"ℹ️ Showing first 50 of {len(_all_dst_ips)} destination IPs on map.")
            fig_map = px.scatter_geo(
                map_df, lat="lat", lon="lon",
                hover_name="ip", hover_data={"city": True, "country": True, "lat": False, "lon": False, "isp": True, "asn": True},
                projection="natural earth",
                size_max=15,
            )
            fig_map.update_traces(marker=dict(size=10, color="#FF4B4B", line=dict(width=1, color="white")))
            fig_map.update_layout(
                template="plotly_dark",
                margin=dict(l=0, r=0, t=30, b=0),
                geo=dict(bgcolor="#0e1117", showland=True, landcolor="#1a1d23",
                         showocean=True, oceancolor="#0e1117",
                         showcountries=True, countrycolor="#444"),
            )
            st.plotly_chart(fig_map, width="stretch")
            
        with col_asn:
            st.markdown("**Top ISPs / Cloud**")
            asn_counts = map_df["isp"].value_counts().reset_index()
            asn_counts.columns = ["ISP", "Count"]
            st.dataframe(asn_counts.head(10), width="stretch", hide_index=True)
    else:
        st.info("No public destination IPs resolved yet. Geo-location populates as packets flow in.")

    st.markdown("---")

    # ── KPI Metrics ───────────────────────────────────────────────────────────
    total_packets = len(df)
    total_bytes   = df["length"].sum()
    total_mb      = total_bytes / (1024 * 1024)

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("📦 Total Packets", f"{total_packets:,}")
    k2.metric("📊 Data Captured", f"{total_mb:.4f} MB")
    k3.metric("🖥 Unique Source IPs", df["src_ip"].nunique())
    k4.metric("🌐 Unique Dest IPs",   df["dst_ip"].nunique())

    st.markdown("---")

    # ── Security Alerts & Threat Intelligence ─────────────────────────────────
    st.subheader("🚨 Security Intel & Alerts")
    alert_col, track_col = st.columns([1, 1])

    with alert_col:
        # Pre-aggregate suspicious port hits (avoids O(n) iterrows)
        susp_hits = (
            df[df["dst_port"].isin(SUSPICIOUS_PORTS) | df["src_port"].isin(SUSPICIOUS_PORTS)]
            .drop_duplicates(subset=["src_ip", "dst_ip", "dst_port"])
        )
        for row in susp_hits.itertuples(index=False):
            port = row.dst_port if row.dst_port in SUSPICIOUS_PORTS else row.src_port
            label = SUSPICIOUS_PORTS[port]
            msg = f"Suspicious Port {port} ({label}): {row.src_ip} ↔ {row.dst_ip}"
            st.error(f"🔴 **{msg}**")
            database.insert_alert("error", "Suspicious Port", msg, row.src_ip, row.dst_ip)

        # Port scan detection
        _now = pd.Timestamp.now(tz=None)
        _window_start = _now - pd.Timedelta(seconds=PORTSCAN_WINDOW_S)
        _ts = df["timestamp"]
        _recent = df[(_ts.dt.tz_localize(None) if _ts.dt.tz else _ts) >= _window_start]  # type: ignore
        port_scans = _recent.groupby("src_ip")["dst_port"].nunique().reset_index()
        scanners = port_scans[port_scans["dst_port"] > PORTSCAN_THRESHOLD]
        for row in scanners.itertuples(index=False):
            msg = f"Port Scan: {row.src_ip} hit {row.dst_port} unique ports in {PORTSCAN_WINDOW_S}s"
            st.error(f"🔴 **{msg}**")
            database.insert_alert("error", "Port Scan", msg, row.src_ip, "")

        # Blocklist hits
        bad_srcs = set(df["src_ip"].unique()) & set(BLOCKLIST_IPS)
        bad_dsts = set(df["dst_ip"].unique()) & set(BLOCKLIST_IPS)
        for bad_ip in bad_srcs | bad_dsts:
            msg = f"Malicious IP {bad_ip} on Threat Blocklist"
            st.error(f"🔴 **{msg}**")
            database.insert_alert("error", "Blocklist Hit", msg, bad_ip, "")

        # ML anomaly detection with joblib-persisted model
        ml_data = df.groupby("src_ip").agg(
            packet_count=("id", "count"),
            avg_payload_size=("length", "mean"),
            unique_ports=("dst_port", "nunique"),
        ).reset_index()

        anomalies = pd.DataFrame()
        if len(ml_data) >= 5:
            _n_ips = len(ml_data)
            _prev_n = st.session_state.get("ml_trained_on", -999)
            # Retrain only when IP count shifts by >10% or >50 IPs, and no more than once per 60 s
            _ip_delta = abs(_n_ips - _prev_n)
            _ip_threshold = max(50, int(_n_ips * 0.10))
            _last_train_t = st.session_state.get("ml_last_train_time", 0)
            _now_t = time.time()
            _need_retrain = (
                "ml_model" not in st.session_state
                or (_ip_delta > _ip_threshold and (_now_t - _last_train_t) >= 60)
            )
            # Try loading a persisted model first
            if "ml_model" not in st.session_state and _ML_MODEL_PATH.exists():
                try:
                    st.session_state["ml_model"] = joblib.load(_ML_MODEL_PATH)
                    _need_retrain = _ip_delta > _ip_threshold and (_now_t - _last_train_t) >= 60
                except Exception:
                    pass

            if _need_retrain:
                _ui_contam = st.session_state.get("ui_contamination", ML_CONTAMINATION)
                _model = IsolationForest(contamination=_ui_contam, random_state=42)
                _model.fit(ml_data[["packet_count", "avg_payload_size", "unique_ports"]])
                st.session_state["ml_model"]      = _model
                st.session_state["ml_trained_on"] = _n_ips
                st.session_state["ml_last_train_time"] = _now_t
                try:
                    joblib.dump(_model, _ML_MODEL_PATH)
                except Exception:
                    pass

            ml_data["anomaly"] = st.session_state["ml_model"].predict(
                ml_data[["packet_count", "avg_payload_size", "unique_ports"]]
            )
            ml_data["anomaly_score"] = st.session_state["ml_model"].score_samples(
                ml_data[["packet_count", "avg_payload_size", "unique_ports"]]
            )
            anomalies = ml_data[ml_data["anomaly"] == -1]
            for row in anomalies.itertuples(index=False):
                msg = (
                    f"ML Anomaly: {row.src_ip} "
                    f"(Pkts: {row.packet_count} | Avg: {row.avg_payload_size:.0f}B | Ports: {row.unique_ports})"
                )
                st.warning(f"🤖 **{msg}**")
                database.insert_alert("warning", "ML Anomaly", msg, row.src_ip, "")

        # ── Unified Threat Confidence Score (ML5 & ML6) ────────────────────────
        if len(ml_data) >= 5:
            st.markdown("**🎯 Unified Threat Confidence Score**")
            risk_df = ml_data.copy()
            # Normalise ML anomaly score to 0-100
            _min, _max = risk_df["anomaly_score"].min(), risk_df["anomaly_score"].max()
            if _max > _min:
                risk_df["ML Score"] = (
                    100 * (1 - (risk_df["anomaly_score"] - _min) / (_max - _min))
                ).round(0).astype(int)
            else:
                risk_df["ML Score"] = 50
                
            # ML5: Calculate Primary Reason for Anomaly
            def get_anomaly_reason(row):
                if row["anomaly"] != -1:
                    return "Normal Traffic"
                reasons = []
                if row["packet_count"] > ml_data["packet_count"].mean() * 2:
                    reasons.append("High Packet Rate")
                if row["avg_payload_size"] > ml_data["avg_payload_size"].mean() * 1.5:
                    reasons.append("Large Payloads")
                if row["unique_ports"] > ml_data["unique_ports"].mean() + 5:
                    reasons.append("Port Scanning")
                return " & ".join(reasons) if reasons else "Unusual Pattern"
                
            risk_df["Primary Reason"] = risk_df.apply(get_anomaly_reason, axis=1)

            # ML6: Unified Threat Confidence Score
            risk_df["Confidence Score"] = risk_df["ML Score"]
            # Apply heuristic modifiers
            risk_df.loc[risk_df["src_ip"].isin(BLOCKLIST_IPS), "Confidence Score"] += 50
            risk_df.loc[risk_df["src_ip"].isin(scanners["src_ip"].tolist()), "Confidence Score"] += 30
            risk_df["Confidence Score"] = risk_df["Confidence Score"].clip(0, 100)
            
            risk_display = (
                risk_df[["src_ip", "Confidence Score", "ML Score", "Primary Reason", "packet_count", "unique_ports"]]
                .sort_values("Confidence Score", ascending=False)
                .head(10)
                .rename(columns={"src_ip": "Source IP", "packet_count": "Packets", "unique_ports": "Unique Ports"})
            )
            st.dataframe(risk_display, width="stretch", hide_index=True)

        if susp_hits.empty and scanners.empty and not bad_srcs and not bad_dsts and anomalies.empty:
            st.success("✅ No security threats detected.")

    with track_col:
        if "tcp_flags" in df.columns:
            st.markdown("**TCP Connection States**")
            tcp_df = df[df["protocol"] == "TCP"].dropna(subset=["tcp_flags"])  # type: ignore
            connections = tcp_df.groupby(["src_ip", "dst_ip", "dst_port"]).last().reset_index()
            connections["State"] = "ESTABLISHED"
            connections.loc[connections["tcp_flags"].str.contains("F|R", na=False), "State"] = "CLOSED"
            connections.loc[connections["tcp_flags"] == "S", "State"] = "SYN_SENT"
            active_conns = connections[connections["State"] != "CLOSED"][["src_ip", "dst_ip", "dst_port", "State"]]
            if not active_conns.empty:
                st.dataframe(active_conns.head(10), width="stretch", hide_index=True)
            else:
                st.info("No active TCP connections.")

        # ── Alert History ──────────────────────────────────────────────────────
        st.markdown("**📜 Alert History (last 20)**")
        hist_df = database.get_alerts(limit=20)
        if not hist_df.empty:
            st.dataframe(
                hist_df[["timestamp", "severity", "category", "src_ip", "detail"]]
                .rename(columns={
                    "timestamp": "Time", "severity": "Sev",
                    "category": "Category", "src_ip": "Src IP", "detail": "Detail",
                }),
                width="stretch", hide_index=True, height=200,
            )
        else:
            st.caption("No alerts recorded yet.")

    st.markdown("---")

    # ── Charts ────────────────────────────────────────────────────────────────
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("📈 Bandwidth & Packet Rate Over Time")
        df_time = df.set_index("timestamp")
        bw_df = df_time["length"].resample("1s").agg(["sum", "count"]).reset_index()
        bw_df.rename(columns={"sum": "Bytes/sec", "count": "Pkts/sec"}, inplace=True)
        if not bw_df.empty:
            max_bw = bw_df["Bytes/sec"].max()
            if max_bw > BW_SPIKE_THRESHOLD:
                st.error(f"⚠️ High Bandwidth Spike Detected: **{max_bw / 1024 / 1024:.2f} MB/s**")
        fig_bw = go.Figure()
        fig_bw.add_trace(go.Scatter(
            x=bw_df["timestamp"], y=bw_df["Bytes/sec"],
            name="Bytes/sec", fill="tozeroy",
            line=dict(color="#00C8FF", width=2), fillcolor="rgba(0,200,255,0.1)",
        ))
        fig_bw.add_trace(go.Scatter(
            x=bw_df["timestamp"], y=bw_df["Pkts/sec"],
            name="Pkts/sec", yaxis="y2",
            line=dict(color="#FF9F43", width=1, dash="dot"),
        ))
        fig_bw.update_layout(
            template="plotly_dark", margin=dict(l=0, r=0, t=30, b=0),
            yaxis=dict(title="Bytes/sec"),
            yaxis2=dict(title="Pkts/sec", overlaying="y", side="right"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig_bw, width="stretch")

    with chart_col2:
        st.subheader("🥧 Protocol Distribution")
        proto_counts = df["protocol"].value_counts().reset_index()
        proto_counts.columns = ["Protocol", "Count"]
        fig_pie = px.pie(
            proto_counts, names="Protocol", values="Count", hole=0.45,
            color="Protocol",
            color_discrete_map={"TCP": "#636EFA", "UDP": "#EF553B", "ICMP": "#00CC96", "Other": "#AB63FA"},
        )
        fig_pie.update_layout(template="plotly_dark", margin=dict(l=0, r=0, t=30, b=0))
        st.plotly_chart(fig_pie, width="stretch")

    st.markdown("---")

    # ── Traffic Heatmap ───────────────────────────────────────────────────────
    st.subheader("🔥 Traffic Heatmap (Hour × Weekday)")
    st.caption("Darker = more packets. Useful for spotting off-hours anomalies.")
    heat_df = df.copy()
    heat_df["hour"]    = heat_df["timestamp"].dt.hour
    heat_df["weekday"] = heat_df["timestamp"].dt.day_name()
    _day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    heat_pivot = (
        heat_df.groupby(["weekday", "hour"])["id"]
        .count()
        .unstack(fill_value=0)
        .reindex(_day_order, fill_value=0)
    )
    fig_heat = go.Figure(go.Heatmap(
        z=heat_pivot.values,
        x=[str(h) for h in heat_pivot.columns],
        y=heat_pivot.index.tolist(),
        colorscale="Viridis",
        hovertemplate="Day: %{y}<br>Hour: %{x}:00<br>Packets: %{z}<extra></extra>",
    ))
    fig_heat.update_layout(
        template="plotly_dark",
        margin=dict(l=0, r=0, t=30, b=0),
        xaxis_title="Hour of Day",
        yaxis_title="Weekday",
    )
    st.plotly_chart(fig_heat, width="stretch")

    st.markdown("---")

    # ── DNS Timeline ──────────────────────────────────────────────────────────
    if "info" in df.columns:
        dns_df = df[df["info"].str.startswith("DNS Query:", na=False)].copy()
        if not dns_df.empty:
            st.subheader("🔎 DNS Query Timeline")
            dns_df["domain"] = dns_df["info"].str.replace("DNS Query: ", "", regex=False)
            dns_time = dns_df.set_index("timestamp")["domain"].resample("5s").count().reset_index()
            dns_time.rename(columns={"domain": "DNS Queries / 5s"}, inplace=True)
            fig_dns = px.bar(
                dns_time, x="timestamp", y="DNS Queries / 5s",
                labels={"timestamp": "Time"},
                color_discrete_sequence=["#A29BFE"],
            )
            fig_dns.update_layout(template="plotly_dark", margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig_dns, width="stretch")

            top_domains = dns_df["domain"].value_counts().head(10).reset_index()
            top_domains.columns = ["Domain", "Queries"]
            col_a, col_b = st.columns(2)
            col_a.dataframe(top_domains, width="stretch", hide_index=True)
            with col_b:
                st.caption("Top queried domains (last capture window)")
            st.markdown("---")

    # ── Network Topology Graph ────────────────────────────────────────────────
    with st.expander("🕸️ Network Topology", expanded=False):
        if not enable_heavy_viz:
            st.warning("Enable 'Advanced Visualizations' in the sidebar to view this graph.")
            df_net = pd.DataFrame(columns=['src_ip', 'dst_ip', 'protocol'])
        else:
            st.caption("Visualizing connections between internal and external IPs. Capped at 200 recent packets.")
            df_net = df.tail(200)

        # Use tail(200) instead of tail(1000) — spring_layout is O(n²)
        G: nx.Graph = cast(nx.Graph, nx.from_pandas_edgelist(df_net, 'src_ip', 'dst_ip', edge_attr='protocol', create_using=nx.Graph))

        if not G.nodes:
            st.info("Not enough data to build topology graph.")
        else:
            node_fingerprint = frozenset(list(G.nodes))
            if st.session_state.get("topo_fingerprint") != node_fingerprint:
                st.session_state["topo_pos"] = nx.spring_layout(G, seed=42)
                st.session_state["topo_fingerprint"] = node_fingerprint
            pos = st.session_state["topo_pos"]

            edge_x: list[float | None] = []
            edge_y: list[float | None] = []
            for edge in G.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])

            edge_trace = go.Scatter(
                x=edge_x, y=edge_y,
                line=dict(width=0.5, color='#888'),
                hoverinfo='none',
                mode='lines'
            )

            node_x = []
            node_y = []
            node_text = []
            node_size = []
            degrees = dict(G.degree)

            for node in list(G.nodes):
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                node_text.append(f"IP: {node}<br>Connections: {degrees[node]}")
                node_size.append(10 + (degrees[node] * 2))

            node_trace = go.Scatter(
                x=node_x, y=node_y,
                mode='markers+text',
                text=[n if degrees[n] > 5 else "" for n in list(G.nodes)],
                textposition="bottom center",
                hoverinfo='text',
                hovertext=node_text,
                marker=dict(
                    showscale=True,
                    colorscale='YlGnBu',
                    color=[degrees[n] for n in list(G.nodes)],
                    size=node_size,
                    colorbar=dict(title="Connections"),
                    line_width=2
                )
            )

            fig_net = go.Figure(data=[edge_trace, node_trace],
                         layout=go.Layout(
                            showlegend=False,
                            hovermode='closest',
                            margin=dict(b=0, l=0, r=0, t=0),
                            plot_bgcolor='rgba(0,0,0,0)',
                            paper_bgcolor='rgba(0,0,0,0)',
                            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                         )
            fig_net.update_layout(template="plotly_dark")
            st.plotly_chart(fig_net, width="stretch")

    st.markdown("---")

    # ── Data Flow Sankey Diagram ──────────────────────────────────────────────
    with st.expander("🌊 Data Flow Sankey Diagram", expanded=False):
        if not enable_heavy_viz:
            st.warning("Enable 'Advanced Visualizations' in the sidebar to view this diagram.")
            sankey_df = pd.DataFrame()
        else:
            st.caption("Traffic flow from Source IP → Destination IP → Destination Port")
            
            # Top 100 rows for clarity to avoid a messy diagram
            sankey_df = df.tail(100).groupby(["src_ip", "dst_ip", "dst_port"]).size().to_frame("count").reset_index()
        
        if not sankey_df.empty:
            all_src = sankey_df["src_ip"].unique().tolist()
            all_dst = sankey_df["dst_ip"].unique().tolist()
            all_port = [f"Port {p}" for p in sankey_df["dst_port"].unique()]
            
            node_labels = list(dict.fromkeys(all_src + all_dst + all_port))
            
            source_indices = []
            target_indices = []
            values = []
            
            for _, row in sankey_df.iterrows():
                src_idx = node_labels.index(row["src_ip"])
                dst_idx = node_labels.index(row["dst_ip"])
                port_idx = node_labels.index(f"Port {row['dst_port']}")
                
                source_indices.append(src_idx)
                target_indices.append(dst_idx)
                values.append(row["count"])
                
                source_indices.append(dst_idx)
                target_indices.append(port_idx)
                values.append(row["count"])
                
            fig_sankey = go.Figure(data=[go.Sankey(
                node=dict(
                    pad=15, thickness=20,
                    line=dict(color="black", width=0.5),
                    label=node_labels,
                    color="blue"
                ),
                link=dict(
                    source=source_indices,
                    target=target_indices,
                    value=values
                )
            )])
            fig_sankey.update_layout(template="plotly_dark", margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig_sankey, width="stretch")
        else:
            st.info("Not enough data to build Sankey diagram.")

    st.markdown("---")

    # ── Anomalous Port Usage Heatmap ──────────────────────────────────────────
    with st.expander("🚪 Port Usage Heatmap (Src IP × Dest Port)", expanded=False):
        st.caption("Visually highlights if a single source is scanning or hitting many unusual ports. Capped to top 15 IPs × top 20 ports.")
        
        # Cap to recent 500 rows, then restrict to top 15 src IPs and top 20 dst ports
        _ph_df = df.tail(500)
        _top_srcs = _ph_df["src_ip"].value_counts().head(15).index
        _top_ports = _ph_df["dst_port"].value_counts().head(20).index
        port_heat_df = (
            _ph_df[_ph_df["src_ip"].isin(_top_srcs) & _ph_df["dst_port"].isin(_top_ports)]
            .groupby(["src_ip", "dst_port"]).size().to_frame("count").reset_index()
        )
        if not port_heat_df.empty:
            port_pivot = port_heat_df.pivot(index="src_ip", columns="dst_port", values="count").fillna(0)
            
            fig_port_heat = go.Figure(go.Heatmap(
                z=port_pivot.values,
                x=[str(p) for p in port_pivot.columns],
                y=port_pivot.index.tolist(),
                colorscale="Plasma",
            ))
            fig_port_heat.update_layout(
                template="plotly_dark",
                margin=dict(l=0, r=0, t=30, b=0),
                xaxis_title="Destination Port",
                yaxis_title="Source IP",
            )
            st.plotly_chart(fig_port_heat, width="stretch")
        else:
            st.info("No port usage data available.")

    st.markdown("---")

    # ── Top 5 Talkers ─────────────────────────────────────────────────────────
    st.subheader("🏆 Top 5 Talkers (Source IPs)")
    top_talkers = (
        df.groupby("src_ip")["length"].sum()
        .reset_index()
        .sort_values("length", ascending=False)
        .head(5)
        .rename(columns={"src_ip": "Source IP", "length": "Total Bytes"})
    )
    tab_col, bar_col = st.columns(2)
    with tab_col:
        st.dataframe(top_talkers, width="stretch", hide_index=True)
    with bar_col:
        fig_bar = px.bar(top_talkers, x="Source IP", y="Total Bytes", color="Source IP", text_auto=".2s")
        fig_bar.update_layout(template="plotly_dark", margin=dict(l=0, r=0, t=30, b=0), showlegend=False)
        st.plotly_chart(fig_bar, width="stretch")

    st.markdown("---")

    # ── Conversation View ─────────────────────────────────────────────────────
    st.subheader("💬 Conversation View")
    st.caption("Top sessions grouped by (src → dst, port, protocol), sorted by total bytes.")
    conv_df = (
        df.groupby(["src_ip", "dst_ip", "dst_port", "protocol"])
        .agg(
            Packets=("id", "count"),
            Bytes=("length", "sum"),
            First_Seen=("timestamp", "min"),
            Last_Seen=("timestamp", "max"),
        )
        .reset_index()
        .sort_values("Bytes", ascending=False)
        .head(20)
        .rename(columns={
            "src_ip": "Src IP", "dst_ip": "Dst IP",
            "dst_port": "Dst Port", "protocol": "Proto",
        })
    )
    conv_df["Duration"] = (conv_df["Last_Seen"] - conv_df["First_Seen"]).dt.total_seconds().round(1).astype(str) + "s"
    st.dataframe(
        conv_df[["Src IP", "Dst IP", "Dst Port", "Proto", "Packets", "Bytes", "Duration"]],
        width="stretch", hide_index=True,
    )

    st.markdown("---")

    # ── Live Packet Table ─────────────────────────────────────────────────────
    st.subheader("📋 Live Packet Stream")
    st.caption("Most recent 200 packets — filtered by your Display Filter above.")

    display_cols = ["id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "service", "length", "info"]
    available_cols = [c for c in display_cols if c in df.columns]

    pkt_table = (
        df[available_cols]
        .tail(200)
        .sort_values("timestamp", ascending=False)  # type: ignore
        .rename(columns={
            "id":        "ID",
            "timestamp": "Time",
            "src_ip":    "Source IP",
            "src_port":  "Src Port",
            "dst_ip":    "Dest IP",
            "dst_port":  "Dst Port",
            "protocol":  "Protocol",
            "service":   "Service",
            "length":    "Bytes",
            "info":      "Info",
        })
    )

    selection = st.dataframe(
        pkt_table,
        width="stretch",
        hide_index=True,
        height=300,
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "Time":  st.column_config.DatetimeColumn("Time", format="HH:mm:ss.SSS"),
            "Bytes": st.column_config.NumberColumn("Bytes", format="%d B"),
            "Info":  st.column_config.TextColumn("Info"),
        },
    )

    if selection and selection.selection.rows:  # type: ignore
        selected_idx = selection.selection.rows[0]  # type: ignore
        selected_row = pkt_table.iloc[selected_idx]

        st.markdown("#### 🔎 Packet Inspector")
        colA, colB, colC = st.columns(3)
        colA.write(f"**ID:** {selected_row.get('ID', 'N/A')}")
        colA.write(f"**Time:** {selected_row.get('Time')}")
        colA.write(f"**Protocol:** {selected_row.get('Protocol')}")
        colA.write(f"**Length:** {selected_row.get('Bytes')} Bytes")

        colB.write(f"**Source:** {selected_row.get('Source IP')}:{selected_row.get('Src Port', 0)}")
        colB.write(f"**Dest:** {selected_row.get('Dest IP')}:{selected_row.get('Dst Port', 0)}")

        info_val = selected_row.get('Info')
        colC.write(f"**Dissected Info:** {info_val if pd.notna(info_val) and info_val != '' else '—'}")

        orig_row = df[df["id"] == selected_row.get("ID")]
        if not orig_row.empty and "tcp_flags" in orig_row.columns:
            flags = orig_row.iloc[0]["tcp_flags"]
            if pd.notna(flags) and flags:
                colC.write(f"**TCP Flags:** `{flags}`")

    # ── TLS/SNI Deep Dive ─────────────────────────────────────────────────────
    if "sni" in df.columns:
        valid_snis = df[df["sni"].notna() & (df["sni"] != "")]
        if not valid_snis.empty:
            st.markdown("---")
            st.subheader("🔐 TLS/SNI Deep Dive")
            
            sni_col1, sni_col2 = st.columns(2)
            
            with sni_col1:
                snis = valid_snis["sni"].value_counts().reset_index()
                snis.columns = ["Domain (SNI)", "Connections"]
                st.markdown("**Top Requested HTTPS Domains**")
                st.dataframe(snis.head(15), width="stretch", hide_index=True)
                
            with sni_col2:
                st.markdown("**SNI Distribution**")
                fig_sni = px.pie(
                    snis.head(10), names="Domain (SNI)", values="Connections", hole=0.4,
                    color_discrete_sequence=px.colors.qualitative.Bold,
                )
                fig_sni.update_layout(template="plotly_dark", margin=dict(l=0, r=0, t=30, b=0))
                st.plotly_chart(fig_sni, width="stretch")

    # ── SNMP / Device Health ──────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("📡 SNMP Device Health")

    snmp_devices = database.get_snmp_devices()

    if not snmp_devices:
        st.info(
            "No SNMP data yet. Add device IPs in the **🖧 SNMP Device Polling** "
            "sidebar panel and press **▶ Start**."
        )
    else:
        selected_device = st.selectbox(
            "Select Device", snmp_devices, key="snmp_device_select"
        )
        snmp_df = database.get_snmp_metrics(device_ip=selected_device, limit=500)

        if snmp_df.empty:
            st.info("No SNMP metrics available for this device yet.")
        else:
            device_name = snmp_df["device_name"].iloc[-1] if "device_name" in snmp_df.columns else selected_device
            cpu_latest  = snmp_df["cpu_pct"].iloc[-1]    if "cpu_pct"    in snmp_df.columns else 0.0

            # ── KPI row ───────────────────────────────────────────────────────
            sk1, sk2, sk3 = st.columns(3)
            sk1.metric("🖥 Device",    device_name)
            sk2.metric("⚡ CPU Load", f"{cpu_latest:.1f}%")
            sk3.metric("🔌 Interfaces", snmp_df["if_index"].nunique())

            # ── Alerts ────────────────────────────────────────────────────────
            if SNMP_LINK_ALERT:
                latest_status = snmp_df.sort_values("timestamp").groupby("if_name")["if_status"].last()
                down_ifaces = latest_status[latest_status != 1].index.tolist()
                for iface in down_ifaces:
                    st.error(f"🔴 **Link Down**: Interface `{iface}` on `{device_name}` is DOWN")
                    database.insert_alert("error", "Link Down", f"Interface {iface} on {device_name} is DOWN", str(selected_device), "")

            if cpu_latest > SNMP_CPU_ALERT:
                st.warning(
                    f"⚠️ **High CPU**: `{device_name}` at **{cpu_latest:.1f}%** "
                    f"(threshold: {SNMP_CPU_ALERT:.0f}%)"
                )
                database.insert_alert("warning", "High CPU", f"{device_name} CPU at {cpu_latest:.1f}%", str(selected_device), "")

            # ── SNMP z-score anomaly detection on BW / errors ─────────────────
            iface_agg = (
                snmp_df.groupby("if_name")
                .agg(avg_in_bps=("in_bps", "mean"), avg_out_bps=("out_bps", "mean"),
                     total_errors=("in_errors", "last"))
                .reset_index()
            )
            for col in ["avg_in_bps", "avg_out_bps", "total_errors"]:
                _mean = iface_agg[col].mean()
                _std  = iface_agg[col].std()
                if _std and _std > 0:
                    iface_agg[f"{col}_z"] = (iface_agg[col] - _mean) / _std
                    _outliers = iface_agg[iface_agg[f"{col}_z"].abs() > 2.5]
                    for row in _outliers.itertuples(index=False):
                        msg = f"SNMP Anomaly ({col}) on {row.if_name}: z={getattr(row, col+'_z'):.1f}"
                        st.warning(f"🤖 **{msg}**")
                        database.insert_alert("warning", "SNMP Anomaly", msg, str(selected_device), "")

            # ── Multi-device BW comparison ────────────────────────────────────
            if len(snmp_devices) > 1:
                st.markdown("**📊 Multi-Device Bandwidth Comparison**")
                all_snmp_df = database.get_snmp_metrics(limit=500)
                fig_multi = go.Figure()
                for dev in snmp_devices:
                    dev_df = all_snmp_df[all_snmp_df["device_ip"] == dev]
                    if not dev_df.empty:
                        bw_total = dev_df.groupby("timestamp")[["in_bps", "out_bps"]].sum().reset_index()
                        fig_multi.add_trace(go.Scatter(
                            x=bw_total["timestamp"],
                            y=bw_total["in_bps"] + bw_total["out_bps"],
                            name=dev, mode="lines",
                        ))
                fig_multi.update_layout(
                    template="plotly_dark",
                    margin=dict(l=0, r=0, t=30, b=0),
                    xaxis_title="Time",
                    yaxis_title="Total BW (Bytes/sec)",
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                )
                st.plotly_chart(fig_multi, width="stretch")

            # ── Bandwidth chart ───────────────────────────────────────────────
            st.markdown("**Interface Bandwidth (bytes/sec)**")
            bw_interfaces = snmp_df["if_name"].unique()
            fig_bw_snmp = go.Figure()
            for iface in bw_interfaces:
                iface_df = snmp_df[snmp_df["if_name"] == iface]
                fig_bw_snmp.add_trace(go.Scatter(
                    x=iface_df["timestamp"], y=iface_df["in_bps"],
                    name=f"{iface} IN", mode="lines",
                    line=dict(width=2),
                ))
                fig_bw_snmp.add_trace(go.Scatter(
                    x=iface_df["timestamp"], y=iface_df["out_bps"],
                    name=f"{iface} OUT", mode="lines",
                    line=dict(width=2, dash="dot"),
                ))
            fig_bw_snmp.update_layout(
                template="plotly_dark",
                margin=dict(l=0, r=0, t=30, b=0),
                xaxis_title="Time",
                yaxis_title="Bytes / sec",
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            )
            st.plotly_chart(fig_bw_snmp, width="stretch")

            # ── Error rate chart ──────────────────────────────────────────────
            latest_errors = (
                snmp_df.groupby("if_name")
                .agg(in_errors=("in_errors", "last"), out_errors=("out_errors", "last"))
                .reset_index()
            )
            if latest_errors["in_errors"].sum() + latest_errors["out_errors"].sum() > 0:
                st.markdown("**Interface Error Counters (cumulative)**")
                fig_err = go.Figure(data=[
                    go.Bar(name="RX Errors",  x=latest_errors["if_name"], y=latest_errors["in_errors"],  marker_color="#EF553B"),
                    go.Bar(name="TX Errors",  x=latest_errors["if_name"], y=latest_errors["out_errors"], marker_color="#636EFA"),
                ])
                fig_err.update_layout(
                    template="plotly_dark",
                    barmode="group",
                    margin=dict(l=0, r=0, t=30, b=0),
                    xaxis_title="Interface",
                    yaxis_title="Error Count",
                )
                st.plotly_chart(fig_err, width="stretch")

            # ── Interface status table ────────────────────────────────────────
            st.markdown("**Interface Status**")
            status_df = (
                snmp_df.sort_values("timestamp")
                .groupby("if_name")
                .last()[["if_status", "in_bps", "out_bps"]]
                .reset_index()
            )
            status_df["Status"] = status_df["if_status"].map({1: "🟢 UP", 2: "🔴 DOWN"}).fillna("⚪ Unknown")
            status_df["In (B/s)"]  = status_df["in_bps"].map("{:.0f}".format)
            status_df["Out (B/s)"] = status_df["out_bps"].map("{:.0f}".format)
            st.dataframe(
                status_df[["if_name", "Status", "In (B/s)", "Out (B/s)"]].rename(columns={"if_name": "Interface"}),
                width="stretch",
                hide_index=True,
            )

            # ── CPU load chart ────────────────────────────────────────────────
            if snmp_df["cpu_pct"].nunique() > 1:
                st.markdown("**CPU Load Over Time**")
                cpu_df = snmp_df.groupby("timestamp")["cpu_pct"].mean().reset_index()
                fig_cpu = px.line(
                    cpu_df, x="timestamp", y="cpu_pct",
                    labels={"timestamp": "Time", "cpu_pct": "CPU %"},
                )
                fig_cpu.add_hline(
                    y=SNMP_CPU_ALERT, line_dash="dash", line_color="orange",
                    annotation_text=f"Alert threshold ({SNMP_CPU_ALERT:.0f}%)",
                )
                fig_cpu.update_traces(line=dict(color="#00CC96", width=2))
                fig_cpu.update_layout(template="plotly_dark", margin=dict(l=0, r=0, t=30, b=0))
                st.plotly_chart(fig_cpu, width="stretch")


# ── Invoke the fragment (run_every drives the refresh; no manual st.rerun needed)
render_dashboard()


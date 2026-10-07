"""
PacketLens Fix Orchestrator
============================
A multi-agent system using the Google Antigravity SDK that delegates the
14 identified long-term fixes across 5 specialist subagents.

Usage:
    cd /home/felix/TRAFFICANALYZER
    source venv/bin/activate
    pip install google-antigravity pyyaml
    export GEMINI_API_KEY=your_key_here
    python agents/fix_orchestrator.py

Agent breakdown:
    Phase 1 (parallel — different files):
        DB Agent       → database.py  (fixes #1, #8)
        Sniffer Agent  → sniffer.py   (fixes #9, #11)
        Security Agent → app.py + config.yaml (fixes #6, #10)

    Phase 2 (sequential — both touch app.py):
        Reliability Agent → app.py  (fixes #2, #3)
        UX Agent          → app.py  (fixes #4, #5, #7)
"""

import asyncio
import os
from pathlib import Path
try:
    from google.antigravity import Agent, LocalAgentConfig, types  # type: ignore[import-untyped]
except ModuleNotFoundError as _e:
    raise SystemExit(
        "google-antigravity not found. Install it inside the project venv:\n"
        "  source venv/bin/activate && pip install google-antigravity"
    ) from _e

# ── Paths ──────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent

# ── Shared tools given to every subagent ──────────────────────────────────────

def read_project_file(filename: str) -> str:
    """Read the contents of a file in the PacketLens project root.

    Args:
        filename: Relative filename, e.g. 'database.py', 'app.py', 'sniffer.py'.
    """
    path = PROJECT_ROOT / filename
    if not path.exists():
        return f"ERROR: {filename} not found in project root."
    return path.read_text()


def write_project_file(filename: str, content: str) -> str:
    """Write new content to a file in the PacketLens project root.
    Creates the file if it does not already exist.

    Args:
        filename: Relative filename, e.g. 'database.py' or 'config.yaml'.
        content: The full new file content to write.
    """
    path = PROJECT_ROOT / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return f"Written {len(content)} bytes to {filename}"


# ── Subagent factory ───────────────────────────────────────────────────────────
def make_agent(system_instructions: str) -> Agent:
    """Create a subagent with file read/write tools and subagent capability."""
    config = LocalAgentConfig(
        system_instructions=system_instructions,
        tools=[read_project_file, write_project_file],
        capabilities=types.CapabilitiesConfig(
            enable_subagents=True,
        ),
    )
    return Agent(config)


# ══════════════════════════════════════════════════════════════════════════════
# SPECIALIST AGENTS
# ══════════════════════════════════════════════════════════════════════════════

async def run_db_agent() -> str:
    """Fix #1, #8 — SQLite performance: batch inserts, WAL mode, smarter cleanup."""
    agent = make_agent(
        system_instructions=(
            "You are a Python database performance expert specialising in SQLite. "
            "You will be given specific fixes to apply to database.py. "
            "Always read the file first, then write the complete corrected version. "
            "Never break existing function signatures — callers must not need to change."
        )
    )
    async with agent:
        response = await agent.chat(
            "Read database.py from the PacketLens project. Then apply these two fixes:\n\n"
            "FIX 1 — BATCH INSERTS + WAL MODE:\n"
            "  - Add `PRAGMA journal_mode=WAL` to init_db() so concurrent reads never block writes.\n"
            "  - Add a module-level `_batch: list = []` and `_BATCH_SIZE = 50` constant.\n"
            "  - Change insert_packet() to append to `_batch` first.\n"
            "  - Add a flush_batch() function that bulk-inserts using executemany() then clears _batch.\n"
            "  - insert_packet() should call flush_batch() only when len(_batch) >= _BATCH_SIZE.\n"
            "  - Keep all existing function signatures unchanged.\n\n"
            "FIX 2 — SMARTER CLEANUP:\n"
            "  - In cleanup_old_records(), first do `SELECT COUNT(*) FROM packets`.\n"
            "  - Only execute the expensive DELETE if count > limit.\n"
            "  - This avoids a slow subquery DELETE on every 2-second Streamlit refresh.\n\n"
            "Write the fully corrected database.py when done."
        )
        return await response.text()


async def run_sniffer_agent() -> str:
    """Fix #11, #9 partial — Replace sudo doc with cap_net_raw; add logging."""
    agent = make_agent(
        system_instructions=(
            "You are a Linux systems and Python networking expert. "
            "You fix Python scripts that use Scapy for packet capture. "
            "Always read the target file first, then produce a corrected version."
        )
    )
    async with agent:
        response = await agent.chat(
            "Read sniffer.py from the PacketLens project. Apply these two fixes:\n\n"
            "FIX 1 — STRUCTURED LOGGING:\n"
            "  - Replace all bare print() calls with Python's standard logging module.\n"
            "  - Configure a FileHandler writing to 'sniffer.log' in the project root "
            "    and a StreamHandler for the console. Use INFO for normal messages "
            "    and ERROR for exceptions.\n"
            "  - In the packet_callback except block, change `pass` to "
            "    `logging.debug('Packet parse error', exc_info=True)`.\n\n"
            "FIX 2 — DOCUMENT cap_net_raw:\n"
            "  - Add a comment block at the top of main() explaining the sudo alternative:\n"
            "      sudo setcap cap_net_raw=eip $(which python3)\n"
            "  - If a PermissionError is caught, log this command as a hint.\n\n"
            "Write the fully corrected sniffer.py when done."
        )
        return await response.text()


async def run_security_agent() -> str:
    """Fix #6, #10 — Port scan time-window + config.yaml for threat intel."""
    agent = make_agent(
        system_instructions=(
            "You are a cybersecurity Python developer who specialises in network threat detection. "
            "You improve security heuristics to reduce false positives. "
            "Always read existing files before modifying them."
        )
    )
    async with agent:
        response = await agent.chat(
            "Read app.py from the PacketLens project. Apply these two fixes:\n\n"
            "FIX 1 — PORT SCAN TIME WINDOW (around the scan_threshold = 15 block):\n"
            "  - Change the port scan detector to only count unique destination ports "
            "    seen by each src_ip within the LAST 30 SECONDS, not across all captured data.\n"
            "  - Filter df to the last 30 seconds using: "
            "    recent = df[df['timestamp'] >= (pd.Timestamp.now() - pd.Timedelta(seconds=30))]\n"
            "  - Run the groupby on 'recent' instead of 'df'.\n\n"
            "FIX 2 — EXTERNALIZE THREAT INTEL TO config.yaml:\n"
            "  - Create config.yaml in the project root with:\n"
            "      thresholds:\n"
            "        port_scan_unique_ports: 15\n"
            "        bandwidth_spike_bytes_per_sec: 5000000\n"
            "        circular_log_limit: 10000\n"
            "      threat_intel:\n"
            "        suspicious_ports:\n"
            "          4444: Metasploit\n"
            "          1337: Leet\n"
            "          31337: BackOrifice\n"
            "          6667: IRC/Botnet\n"
            "        blocklist_ips:\n"
            "          - '185.159.82.15'\n"
            "          - '45.144.225.10'\n"
            "          - '193.163.125.138'\n"
            "  - In app.py, load config.yaml with `import yaml; cfg = yaml.safe_load(open('config.yaml'))` "
            "    at startup and replace all hardcoded threat intel values with cfg references.\n\n"
            "Write both the corrected app.py and the new config.yaml when done."
        )
        return await response.text()


async def run_reliability_agent() -> str:
    """Fix #3, #2 — PID lockfile survival + ML model caching."""
    agent = make_agent(
        system_instructions=(
            "You are a Python reliability and state-management expert familiar with Streamlit. "
            "You fix session_state fragility issues and caching problems. "
            "Always read the target file first before making changes. "
            "Preserve ALL existing functionality; only add/modify the specific fix areas."
        )
    )
    async with agent:
        response = await agent.chat(
            "Read app.py from the PacketLens project. Apply these two fixes:\n\n"
            "FIX 1 — PID LOCKFILE (near the sniffer_pid session_state block):\n"
            "  - Define LOCKFILE = Path('sniffer.pid') at the top of the file.\n"
            "  - When Start is pressed, write the PID to LOCKFILE as text.\n"
            "  - On every page load, if LOCKFILE exists: read the PID, try os.kill(pid, 0). "
            "    If OSError, the process is dead — delete LOCKFILE and set sniffer_pid=None.\n"
            "  - When Stop is pressed, also delete LOCKFILE if it exists.\n\n"
            "FIX 2 — CACHE THE ML MODEL (near the IsolationForest block):\n"
            "  - Store the trained model in st.session_state['ml_model'] and "
            "    the training IP count in st.session_state['ml_trained_on'].\n"
            "  - Only retrain if the current unique src_ip count differs by more than 2 "
            "    from st.session_state['ml_trained_on'] (or if 'ml_model' is not set).\n"
            "  - Use the cached model for predict() on refreshes where retraining is skipped.\n\n"
            "Write the fully corrected app.py when done."
        )
        return await response.text()


async def run_ux_agent() -> str:
    """Fix #4, #5, #7 — Map df_raw, build_locations simplify, PCAP import guard."""
    agent = make_agent(
        system_instructions=(
            "You are a Streamlit UX developer who writes clean, correct Python. "
            "You fix data pipeline bugs and add user-friendly confirmation dialogs. "
            "Always read the target file before making changes. "
            "Preserve ALL existing functionality outside the specific fix areas."
        )
    )
    async with agent:
        response = await agent.chat(
            "Read app.py from the PacketLens project. Apply these three fixes:\n\n"
            "FIX 1 — MAP USES FILTERED DF:\n"
            "  - Find the line: unique_dst_ips = tuple(sorted(df['dst_ip'].unique()))\n"
            "  - Change 'df' to 'df_raw' so the geo map always shows all captured "
            "    public IPs regardless of any active Display Filter.\n\n"
            "FIX 2 — SIMPLIFY build_locations:\n"
            "  - The build_locations function adds a redundant caching layer on top of "
            "    the already-cached get_ip_location. Remove the build_locations function.\n"
            "  - Replace it with a direct comprehension:\n"
            "    def _loc_dict(ip):\n"
            "        loc = get_ip_location(ip)\n"
            "        return {'ip':ip,'lat':loc[0],'lon':loc[1],'country':loc[2],'city':loc[3]} if loc else None\n"
            "    locations = [d for ip in unique_dst_ips if (d := _loc_dict(ip)) is not None]\n\n"
            "FIX 3 — PCAP IMPORT CONFIRMATION:\n"
            "  - In the PCAP Import section, BEFORE calling database.clear_db(), add:\n"
            "      st.sidebar.warning('This will DELETE all live capture data!')\n"
            "      confirmed = st.sidebar.checkbox('I understand, proceed with import')\n"
            "  - Wrap the clear_db() call and subprocess.run() in `if confirmed:`.\n"
            "  - If not confirmed, show st.sidebar.info('Check the box above to confirm.')\n\n"
            "Write the fully corrected app.py when done."
        )
        return await response.text()


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    print("=" * 60)
    print("🔬 PacketLens Fix Orchestrator — Starting")
    print("=" * 60)
    print(f"Project root: {PROJECT_ROOT}\n")

    # Agents touching DIFFERENT files → safe to run in parallel (Phase 1)
    # Agents both touching app.py     → must run sequentially (Phase 2)
    parallel_agents = {
        "🗄️  DB Agent":      run_db_agent,
        "🔍 Sniffer Agent":  run_sniffer_agent,
        "🚨 Security Agent": run_security_agent,
    }
    sequential_agents = {
        "🔒 Reliability Agent": run_reliability_agent,
        "🎨 UX Agent":          run_ux_agent,
    }

    # ── Phase 1: run in parallel ───────────────────────────────────────────────
    print("Phase 1: Parallel agents (DB, Sniffer, Security)...")
    print("-" * 60)
    parallel_results = await asyncio.gather(
        *[fn() for fn in parallel_agents.values()],
        return_exceptions=True,
    )
    for name, result in zip(parallel_agents.keys(), parallel_results):
        if isinstance(result, Exception):
            print(f"\n{name}: FAILED — {result}")
        else:
            result_str = str(result)
            preview = result_str[:400] + "..." if len(result_str) > 400 else result_str
            print(f"\n{name}: Done\n{preview}")

    # ── Phase 2: run sequentially (both modify app.py) ────────────────────────
    print("\nPhase 2: Sequential agents (Reliability → UX)...")
    print("-" * 60)
    for name, fn in sequential_agents.items():
        print(f"\n{name}: Running...")
        try:
            result = await fn()
            preview = result[:400] + "..." if len(result) > 400 else result
            print(f"{name}: Done\n{preview}")
        except Exception as e:
            print(f"{name}: FAILED — {e}")

    print("\n" + "=" * 60)
    print("All agents finished.")
    print("Run `git diff` to review every change before testing.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())

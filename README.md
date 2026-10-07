# PacketLens 🔍
**Real-Time Network Traffic Analyzer**

PacketLens is a lightweight, Python-based application designed to passively intercept, decode, and visualize local network traffic in real-time. It solves the "information overload" problem by automatically aggregating raw packet data into an intuitive, web-based graphical dashboard.

## ✨ Features
- **Live Traffic Dashboard**: Monitor your network traffic using an interactive web interface built with Streamlit and Plotly.
- **Top Talkers**: Live-updating charts identifying which IPs are consuming the most bandwidth.
- **Protocol Distribution**: Visual breakdown of TCP vs UDP traffic.
- **Advanced Visualizations**: Network Topology mapping and Data Flow Sankey diagrams (optimizable for low-end machines).
- **Lightweight Backend**: Uses Scapy for packet sniffing and SQLite for thread-safe metadata logging (automatically discards payloads for privacy and memory safety).

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Linux or Windows (Linux recommended for raw socket access)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/felixgift254-source/Packetlens.git
   cd Packetlens
   ```
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the App
The application is split into a background sniffer and a frontend dashboard.

1. **Start the Dashboard:**
   ```bash
   streamlit run app.py
   ```
   Open `http://localhost:8501` in your browser.

2. **Start the Sniffer:**
   To capture packets, the sniffer needs raw socket privileges.
   ```bash
   # Option A: Run with sudo
   sudo ./venv/bin/python sniffer.py -i <your_network_interface>

   # Option B (Linux only): Grant capabilities to avoid sudo
   sudo setcap cap_net_raw=eip ./venv/bin/python3
   python sniffer.py -i <your_network_interface>
   ```
   *Replace `<your_network_interface>` with your active network card, e.g., `eth0` or `wlan0`.*

## ⚙️ Memory & Performance Optimizations
Running continuous packet capture alongside a dashboard can be demanding on systems with lower RAM (e.g., 4GB). PacketLens is optimized out of the box with circular logging limits and refresh rate toggles to keep CPU and memory footprint low. Heavy visualizations (like Network Topology) are disabled by default and can be toggled on via the dashboard sidebar.

## 📄 License
This project is for educational and network administration purposes. All packet payloads are immediately dropped to ensure privacy compliance.

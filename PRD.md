# 📄 PRODUCT REQUIREMENTS DOCUMENT (PRD)
**Product Name:** Real-Time Network Traffic Analyzer (Project Code: *PacketLens*)
**Document Version:** 1.0
**Date:** June 2026
**Target Platform:** Linux/Windows (Python Desktop/Local Web App)

---

## 1. Product Overview
### 1.1 Purpose
The Network Traffic Analyzer is a lightweight, Python-based application designed to passively intercept, decode, and visualize local network traffic in real-time. It aims to solve the "information overload" problem present in existing tools like Wireshark by automatically aggregating raw packet data into an intuitive, web-based graphical dashboard.

### 1.2 Tech Stack
* **Language:** Python 3.10+
* **Backend Sniffing Engine:** `Scapy`
* **Data Processing & Storage:** `Pandas`, `SQLite3` (or memory queues)
* **Frontend UI:** `Streamlit`, `Plotly`

---

## 2. Target Audience
* **Network Administrators in SMEs:** Needing quick visibility into bandwidth hogs and protocol usage without paying for enterprise software.
* **Cybersecurity / IT Students:** Needing a visual, easy-to-understand tool to learn how TCP/IP traffic flows across a network.

---

## 3. User Stories
* **US1:** As a user, I want to type in my network interface (e.g., `eth0` or `wlan0`) so the system knows where to listen.
* **US2:** As a user, I want to click a "Start" and "Stop" button in a web browser to control the packet capture without touching the terminal.
* **US3:** As an IT Admin, I want to see a live updating list/chart of "Top Talkers" (IPs sending the most data) so I can identify who is consuming network bandwidth.
* **US4:** As a student, I want to see a pie chart showing the percentage of TCP vs. UDP traffic to understand my network's protocol distribution.
* **US5:** As a user, I want to see a live line-graph of total bandwidth (Bytes/sec) over time to spot sudden spikes in data transfer.

---

## 4. Functional Requirements
*These define exactly what the system MUST do.*

| Req ID | Feature | Description | Priority |
| :--- | :--- | :--- | :--- |
| **FR1** | **Interface Selection** | The UI must provide a text input or dropdown to define the Network Interface Card (NIC) to sniff on. | High (P0) |
| **FR2** | **Capture Controls** | The UI must have explicit `Start Capture` and `Stop Capture` states. | High (P0) |
| **FR3** | **Packet Decoding** | The backend must decapsulate Layer 3 (IPv4) and Layer 4 (TCP/UDP) headers. | High (P0) |
| **FR4** | **Metadata Extraction** | The system must extract: `Timestamp`, `Source IP`, `Destination IP`, `Protocol`, and `Length (Bytes)`. | High (P0) |
| **FR5** | **Payload Discarding** | The system must immediately drop the packet payload to save memory and ensure privacy compliance. | High (P0) |
| **FR6** | **Data Logging** | The extracted metadata must be written to a thread-safe database (`SQLite`) or Pandas DataFrame in real-time. | High (P0) |
| **FR7** | **KPI Display** | The dashboard must display total packets captured and total data volume (MB). | Medium (P1) |
| **FR8** | **Live Graphing** | The dashboard must automatically refresh every 2-3 seconds, querying the database and redrawing the Plotly charts. | High (P0) |

---

## 5. Non-Functional Requirements
*These define system performance and constraints.*

* **NFR1 - Performance:** The sniffing thread must be separated from the UI thread. The UI refreshing must not cause the Scapy sniffer to drop packets on a standard 50-100 Mbps connection.
* **NFR2 - Error Handling:** The parser must gracefully handle malformed packets (e.g., packets missing an IP layer like ARP broadcasts) using `try/except` blocks without crashing the application.
* **NFR3 - Storage Management (Circular Logging):** To prevent hard drive/RAM overflow, the SQLite database must auto-delete records older than a specific timeframe (e.g., flush data every 10,000 rows or every 1 hour).
* **NFR4 - Usability:** The user must not be required to write CLI commands once the Streamlit server is launched.

---

## 6. System Architecture (Data Flow)
To satisfy **NFR1**, the system will use a multi-process or multi-threaded architecture:

1. **Thread 1 (The Sniffer):** `scapy.sniff()` runs continuously in the background. It calls a callback function `process_packet(packet)` which extracts the 5 metadata fields and executes an `INSERT INTO` SQL command.
2. **The Bridge (SQLite):** Acts as the thread-safe middleman.
3. **Thread 2 (The UI):** `streamlit run app.py` acts as the frontend. It executes a `SELECT * FROM packets` query every 2 seconds, loads the data into a Pandas DataFrame, and renders the Plotly graphs.

---

## 7. Out of Scope
To ensure the project is delivered on time, the following features are explicitly excluded from Version 1.0:
* Decryption of HTTPS/TLS payloads (No Man-in-the-Middle).
* Analysis of IPv6 traffic (strictly limited to IPv4).
* Active Intrusion Prevention (e.g., modifying firewall rules to block IPs).
* Wireless frame capture (802.11 monitor mode/WiFi password cracking).

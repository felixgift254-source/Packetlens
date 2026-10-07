"""
PacketLens — Real-Time Network Traffic Sniffer
===============================================
Captures live traffic (or replays a PCAP) and stores extracted metadata
into the shared SQLite database for the Streamlit dashboard to display.

Privilege note
--------------
Scapy requires raw-socket access. You have two options:

  Option A — run with sudo (simple but grants full root):
      sudo python3 sniffer.py -i eth0

  Option B — grant only the minimum required Linux capability (recommended):
      sudo setcap cap_net_raw=eip $(which python3)
      python3 sniffer.py -i eth0   # no sudo needed after this

  To revoke the capability later:
      sudo setcap -r $(which python3)
"""

import argparse
import logging
import sys
from pathlib import Path
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP  # type: ignore[attr-defined]
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName, TLSCertificate
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR
import database
from datetime import datetime

# ── Logging setup ─────────────────────────────────────────────────────────────
_LOG_FILE = Path(__file__).parent / "sniffer.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(_LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("packetlens.sniffer")


def packet_callback(packet):
    try:
        src_ip = None
        dst_ip = None
        protocol = "Other"
        src_port = 0
        dst_port = 0
        sni = None
        info = None
        tcp_flags = None
        length = len(packet)

        # ── Layer 3: IP / IPv6 / ARP ──────────────────────────────────────────
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        elif ARP in packet:
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            protocol = "ARP"
            op = "Request" if packet[ARP].op == 1 else "Reply"
            sender_mac = packet[ARP].hwsrc
            info = f"ARP {op} (MAC: {sender_mac})"
            # ── ARP spoofing detection ─────────────────────────────────────
            if packet[ARP].op == 2:  # ARP Reply carries IP→MAC mapping
                conflict = database.check_and_update_arp(src_ip, sender_mac)
                if conflict:
                    logger.warning("ARP SPOOF DETECTED: %s", conflict)
                    database.insert_alert(
                        severity="critical",
                        category="ARP Spoofing",
                        src_ip=src_ip,
                        detail=conflict,
                    )
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            database.insert_packet(timestamp, src_ip, dst_ip,
                                   src_port, dst_port, protocol, length,
                                   sni, info, tcp_flags)
            return

        if src_ip and dst_ip:
            # ── Layer 4: TCP ──────────────────────────────────────────────────
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                tcp_flags = str(packet[TCP].flags)

                # HTTP method + path
                if packet.haslayer(HTTPRequest):
                    try:
                        host   = packet[HTTPRequest].Host.decode("utf-8", errors="ignore")   if packet[HTTPRequest].Host   else ""
                        path   = packet[HTTPRequest].Path.decode("utf-8", errors="ignore")   if packet[HTTPRequest].Path   else ""
                        method = packet[HTTPRequest].Method.decode("utf-8", errors="ignore") if packet[HTTPRequest].Method else ""
                        info = f"HTTP {method} {host}{path}"
                    except Exception:
                        pass

                # HTTPS Server Name Indication (SNI) from TLS ClientHello
                if packet.haslayer(TLSClientHello):
                    hello = packet[TLSClientHello]
                    if hello.haslayer(TLS_Ext_ServerName):
                        servernames = hello[TLS_Ext_ServerName].servernames
                        if servernames:
                            sni = servernames[0].servername.decode("utf-8", errors="ignore")
                            info = f"HTTPS SNI: {sni}"
                elif packet.haslayer(TLSCertificate):
                    try:
                        cert_msg = packet[TLSCertificate]
                        if cert_msg.certs and len(cert_msg.certs) > 0:
                            cert = cert_msg.certs[0][1]
                            info = f"TLS Cert: {cert.subject}"
                    except Exception:
                        pass

            # ── Layer 4: UDP ──────────────────────────────────────────────────
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

                if packet.haslayer(DNSQR):
                    try:
                        qname = packet[DNSQR].qname.decode("utf-8", errors="ignore")
                        info = f"DNS Query: {qname}"
                        # ── Suspicious DNS domain detection ───────────────────
                        _SUSPICIOUS_DOMAINS = (
                            ".ru", ".cn", ".tk", ".pw", ".top", ".xyz",
                            "bit.ly", "t.co", "tinyurl.com",  # URL shorteners
                        )
                        _SHORT_LABELS = [
                            p for p in qname.rstrip(".").split(".")
                            if len(p) <= 3 and p.isalnum()
                        ]
                        if any(qname.endswith(d) for d in _SUSPICIOUS_DOMAINS):
                            database.insert_alert(
                                severity="warning",
                                category="Suspicious DNS",
                                src_ip=src_ip or "",
                                dst_ip=dst_ip or "",
                                detail=f"DNS query to suspicious domain: {qname}",
                            )
                    except Exception:
                        pass

            # ── Layer 4: ICMP ─────────────────────────────────────────────────
            elif ICMP in packet:
                protocol = "ICMP"
                icmp_types = {
                    0: "Echo Reply",
                    3: "Dest Unreachable",
                    8: "Echo Request",
                    11: "Time Exceeded",
                }
                itype = packet[ICMP].type
                info = icmp_types.get(itype, f"Type {itype}")

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            database.insert_packet(timestamp, src_ip, dst_ip,
                                   src_port, dst_port, protocol, length,
                                   sni, info, tcp_flags)

    except Exception:
        # Log parse errors at DEBUG level — won't flood the log but are traceable
        logger.debug("Packet parse error", exc_info=True)


def main():
    # ── Privilege note printed at startup ─────────────────────────────────────
    logger.info(
        "Tip: avoid running with sudo by granting the minimum capability once:\n"
        "     sudo setcap cap_net_raw=eip $(which python3)"
    )

    parser = argparse.ArgumentParser(
        description="PacketLens — Real-Time Network Traffic Sniffer"
    )
    parser.add_argument("-i", "--interface",
                        help="Network interface to sniff on (e.g., eth0, wlan0)",
                        default="")
    parser.add_argument("-f", "--filter",
                        help="BPF capture filter (e.g., 'tcp port 80')",
                        default="")
    parser.add_argument("-r", "--read",
                        help="Read from offline PCAP file instead of live capture",
                        default="")
    args = parser.parse_args()

    database.init_db()

    if args.read:
        logger.info("Parsing offline PCAP: %s", args.read)
    else:
        if not args.interface:
            logger.error("Interface (-i) must be provided for live sniffing.")
            sys.exit(1)
        logger.info("Starting live sniffer on interface '%s'…", args.interface)
        logger.info("Press Ctrl+C to stop.")

    try:
        if args.read:
            sniff(offline=args.read, filter=args.filter,
                  prn=packet_callback, store=False)
            logger.info("Offline processing complete.")
        else:
            sniff(iface=args.interface, filter=args.filter,
                  prn=packet_callback, store=False)
    except KeyboardInterrupt:
        logger.info("Stopping sniffer (KeyboardInterrupt).")
    except PermissionError:
        logger.error(
            "Permission denied — Scapy requires raw-socket access.\n"
            "  Option A: run with sudo\n"
            "  Option B: sudo setcap cap_net_raw=eip $(which python3)"
        )
        sys.exit(1)
    except Exception:
        logger.error("Sniffing error", exc_info=True)
        sys.exit(1)
    finally:
        # Flush any buffered packets that haven't been written yet
        database.flush_remaining()
        logger.info("Sniffer shut down cleanly.")


if __name__ == "__main__":
    main()

"""
traffic/pcap_reader.py

Reads a real .pcap/.pcapng capture file (e.g., from Wireshark, tcpdump, or
your live_capture.py output) and converts it into the same packet-record
format used by the synthetic generator, grouped into fixed-size time
windows per source IP (treated as "device").

Usage:
    from traffic.pcap_reader import read_pcap_windows
    windows = read_pcap_windows("capture.pcap", window_seconds=10.0)
    # windows -> list of {"device": {...}, "packets": [...], "window_seconds": ...}
"""

from scapy.all import rdpcap, TCP, UDP, IP
from collections import defaultdict


def _flags_to_str(tcp_layer):
    if tcp_layer is None:
        return ""
    f = tcp_layer.flags
    return str(f)


def read_pcap_windows(pcap_path: str, window_seconds: float = 10.0):
    """
    Parses a pcap file and buckets packets into per-source-IP, per-time-window
    packet lists ready for feature_extraction.extract_features().

    Each unique source IP is treated as a "device" (device_id = its IP,
    since we usually don't have vendor/type metadata for arbitrary pcaps --
    pair this with your device-fingerprinting module if you have one).
    """
    packets = rdpcap(pcap_path)
    if len(packets) == 0:
        return []

    start_time = float(packets[0].time)
    buckets = defaultdict(list)  # (src_ip, window_index) -> [packet_records]

    for pkt in packets:
        if IP not in pkt:
            continue
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        size = len(pkt)
        t = float(pkt.time)
        window_index = int((t - start_time) // window_seconds)

        if TCP in pkt:
            proto = "TCP"
            dst_port = int(pkt[TCP].dport)
            flags = _flags_to_str(pkt[TCP])
        elif UDP in pkt:
            proto = "UDP"
            dst_port = int(pkt[UDP].dport)
            flags = ""
        else:
            proto = "OTHER"
            dst_port = 0
            flags = ""

        record = {
            "timestamp": t,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": proto,
            "size": size,
            "flags": flags,
            "auth_failed": False,  # pcap alone can't tell us this without app-layer parsing
        }
        buckets[(src_ip, window_index)].append(record)

    windows = []
    for (src_ip, window_index), pkt_list in buckets.items():
        windows.append({
            "device": {"device_id": src_ip, "ip_address": src_ip, "mac_address": "Unknown",
                       "device_type": "Unknown (pcap)", "vendor": "Unknown", "first_seen": "Unknown"},
            "packets": pkt_list,
            "window_seconds": window_seconds,
            "true_label": None,  # unknown -- this is real traffic, not labeled synthetic data
        })

    return windows


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 pcap_reader.py <path_to_pcap>")
        sys.exit(1)
    result = read_pcap_windows(sys.argv[1])
    print(f"Parsed {len(result)} device/time-window buckets from {sys.argv[1]}")

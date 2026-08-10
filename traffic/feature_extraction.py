"""
traffic/feature_extraction.py

Converts a window of raw per-packet/flow records for a single device into
a fixed-length numeric feature vector used by both the ML anomaly detector
and the rule-based attack classifier.

This is the shared contract between:
  - traffic/synthetic_generator.py  (demo/training data)
  - traffic/pcap_reader.py          (offline pcap analysis)
  - traffic/live_capture.py         (live sniffing with scapy)

All three produce a list of "packet records" (dicts) per time window per
device; this module reduces that list into one feature row.
"""

from collections import Counter
import statistics

FEATURE_NAMES = [
    "packet_rate",          # packets per second in this window
    "byte_rate",            # bytes per second in this window
    "unique_dst_ips",       # number of distinct destination IPs contacted
    "unique_dst_ports",     # number of distinct destination ports contacted
    "port_entropy",         # Shannon entropy of destination port distribution
    "syn_ratio",            # fraction of packets that are TCP SYN (no ACK)
    "udp_ratio",            # fraction of packets that are UDP
    "avg_packet_size",      # average packet size in bytes
    "failed_auth_count",    # count of failed-login-like events in window
    "new_dst_ratio",        # fraction of destinations never seen before for this device
]


def _entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    ent = 0.0
    for count in counter.values():
        p = count / total
        ent -= p * (p and __import__("math").log2(p))
    return ent


def extract_features(packets: list, window_seconds: float, known_destinations: set = None) -> dict:
    """
    packets: list of dicts, each with keys:
        timestamp (float, epoch seconds)
        src_ip, dst_ip (str)
        dst_port (int)
        protocol ("TCP" | "UDP" | "OTHER")
        size (int, bytes)
        flags (str, e.g. "S", "SA", "A", "" ) -- TCP flags, empty for UDP
        auth_failed (bool) -- True if this packet represents a failed login attempt
                              (e.g. observed at application layer / honeypot)

    known_destinations: set of (dst_ip) previously seen for this device, used
                         to compute new_dst_ratio. Optional.

    Returns a dict of {feature_name: value}, matching FEATURE_NAMES.
    """
    known_destinations = known_destinations or set()

    if not packets:
        return {name: 0.0 for name in FEATURE_NAMES}

    n = len(packets)
    total_bytes = sum(p["size"] for p in packets)
    dst_ips = Counter(p["dst_ip"] for p in packets)
    dst_ports = Counter(p["dst_port"] for p in packets)

    syn_count = sum(1 for p in packets if p.get("flags") == "S")
    udp_count = sum(1 for p in packets if p.get("protocol") == "UDP")
    failed_auth = sum(1 for p in packets if p.get("auth_failed"))

    new_dsts = sum(1 for p in packets if p["dst_ip"] not in known_destinations)

    features = {
        "packet_rate": n / max(window_seconds, 0.001),
        "byte_rate": total_bytes / max(window_seconds, 0.001),
        "unique_dst_ips": len(dst_ips),
        "unique_dst_ports": len(dst_ports),
        "port_entropy": _entropy(dst_ports),
        "syn_ratio": syn_count / n,
        "udp_ratio": udp_count / n,
        "avg_packet_size": statistics.mean(p["size"] for p in packets),
        "failed_auth_count": failed_auth,
        "new_dst_ratio": new_dsts / n,
    }
    return features


def features_to_vector(features: dict) -> list:
    """Order a features dict into a fixed-order numeric vector for the ML model."""
    return [features[name] for name in FEATURE_NAMES]

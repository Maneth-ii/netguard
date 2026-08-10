"""
intelligence/rule_classifier.py

The ML model (IsolationForest) tells us WHETHER a window is anomalous, but
not WHAT KIND of attack it looks like -- that requires domain knowledge,
so we use a transparent rule-based classifier here. This mirrors how real
security tools combine unsupervised ML (for novelty/outlier detection)
with rule/signature-based classification (for attack attribution) --
and it's fully explainable, which is valuable when defending a course
project or writing forensic reports.

classify_attack_type() is only called on windows the ML model has already
flagged as anomalous (result["is_anomaly"] == True).
"""

THRESHOLDS = {
    "ddos_packet_rate": 100,       # packets/sec -- flood-level traffic
    "port_scan_unique_ports": 20,  # distinct dst ports contacted in one window
    "port_scan_syn_ratio": 0.7,    # mostly SYN packets, few completed connections
    "brute_force_failed_auth": 5,  # failed logins in one window
    "c2_min_packets": 5,           # minimum packets to consider beacon-like regularity
    "c2_max_packets": 30,          # C2 beacons are usually low-volume, not floods
}


def classify_attack_type(features: dict) -> str:
    """
    Returns one of the alert_type strings defined in
    intelligence/attack_mapping.json, or "unclassified_anomaly" if the
    anomaly doesn't match any known pattern (still gets a report, but
    flagged for manual analyst review).
    """
    if features["failed_auth_count"] >= THRESHOLDS["brute_force_failed_auth"]:
        return "brute_force_login"

    if features["packet_rate"] >= THRESHOLDS["ddos_packet_rate"]:
        return "ddos_traffic"

    if (features["unique_dst_ports"] >= THRESHOLDS["port_scan_unique_ports"]
            and features["syn_ratio"] >= THRESHOLDS["port_scan_syn_ratio"]):
        return "port_scan"

    # C2 beacons: low-volume, regular traffic to a small number of
    # destinations the device hasn't talked to before -- distinct from
    # a flood (high packet_rate) or a scan (many distinct ports/high SYN ratio).
    if (features["unique_dst_ips"] <= 2
            and features["unique_dst_ports"] <= 3
            and features["new_dst_ratio"] > 0.5
            and features["packet_rate"] < THRESHOLDS["ddos_packet_rate"]):
        return "c2_communication"

    return "unclassified_anomaly"

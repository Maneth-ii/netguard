"""
traffic/live_capture.py

Live packet capture using scapy's sniff(). This is the "real" data source
for a deployed system -- run this on a machine/router/Raspberry Pi with
access to the network interface you want to monitor (e.g., a mirrored/SPAN
port, or the IoT VLAN interface).

NOT runnable in a sandboxed environment without a real network interface
and root/CAP_NET_RAW privileges -- included here for your actual
deployment (course lab machine, home router, Raspberry Pi gateway, etc.)

Usage (run with sudo):
    sudo python3 traffic/live_capture.py --iface eth0 --window 10

This continuously prints/yields window batches in the exact same format
produced by synthetic_generator.py and pcap_reader.py, so it plugs
directly into the same detection pipeline (main.py / app.py) without any
changes to downstream code.
"""

import time
import argparse
from collections import defaultdict

from scapy.all import sniff, TCP, UDP, IP


def _flags_to_str(tcp_layer):
    return str(tcp_layer.flags) if tcp_layer is not None else ""


class LiveWindowCollector:
    """
    Buffers sniffed packets and yields (device, packets, window_seconds)
    batches every `window_seconds`, one batch per distinct source IP seen
    in that window -- same shape as synthetic_generator/pcap_reader output.
    """

    def __init__(self, window_seconds: float = 10.0, on_window_ready=None):
        self.window_seconds = window_seconds
        self.on_window_ready = on_window_ready or (lambda batches: None)
        self._buckets = defaultdict(list)
        self._window_start = time.time()

    def _packet_callback(self, pkt):
        if IP not in pkt:
            return
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        size = len(pkt)

        if TCP in pkt:
            proto, dst_port, flags = "TCP", int(pkt[TCP].dport), _flags_to_str(pkt[TCP])
        elif UDP in pkt:
            proto, dst_port, flags = "UDP", int(pkt[UDP].dport), ""
        else:
            proto, dst_port, flags = "OTHER", 0, ""

        record = {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": ip_layer.dst,
            "dst_port": dst_port,
            "protocol": proto,
            "size": size,
            "flags": flags,
            "auth_failed": False,
        }
        self._buckets[src_ip].append(record)

        if time.time() - self._window_start >= self.window_seconds:
            self._flush()

    def _flush(self):
        batches = []
        for src_ip, packets in self._buckets.items():
            batches.append({
                "device": {"device_id": src_ip, "ip_address": src_ip, "mac_address": "Unknown",
                           "device_type": "Unknown (live)", "vendor": "Unknown", "first_seen": "Unknown"},
                "packets": packets,
                "window_seconds": self.window_seconds,
                "true_label": None,
            })
        if batches:
            self.on_window_ready(batches)
        self._buckets = defaultdict(list)
        self._window_start = time.time()

    def run(self, iface: str = None, count: int = 0):
        """Blocking call -- starts sniffing. count=0 means run until Ctrl+C."""
        print(f"[live_capture] Sniffing on iface={iface or 'default'}, "
              f"window={self.window_seconds}s. Requires root privileges.")
        sniff(iface=iface, prn=self._packet_callback, store=False, count=count)
        self._flush()  # flush any remaining partial window


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live IoT traffic capture")
    parser.add_argument("--iface", default=None, help="Network interface to sniff (e.g. eth0)")
    parser.add_argument("--window", type=float, default=10.0, help="Window size in seconds")
    args = parser.parse_args()

    def print_batch(batches):
        for b in batches:
            print(f"[window] device={b['device']['device_id']} packets={len(b['packets'])}")

    collector = LiveWindowCollector(window_seconds=args.window, on_window_ready=print_batch)
    collector.run(iface=args.iface)

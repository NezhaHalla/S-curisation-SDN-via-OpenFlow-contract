"""
Traffic Monitor — Collects statistics and detects security threats.

Detection:
    - DDoS: High packet rate from a single source
    - Port Scan: Single source contacting many destinations
    - Traffic anomaly: Sudden spike on a port

Stats are collected via OpenFlow multipart requests every MONITOR_INTERVAL seconds.
"""

import time
from collections import defaultdict


# Detection thresholds
DDOS_PACKET_THRESHOLD = 100      # packets per interval from one source
DDOS_BYTE_THRESHOLD = 100000    # bytes per interval from one source
PORT_SCAN_THRESHOLD = 5          # unique destinations in one interval
MONITOR_INTERVAL = 10            # seconds between stat collections


class TrafficMonitor:
    """Monitors network traffic and detects security threats."""

    def __init__(self, topology_manager, logger):
        self.topo = topology_manager
        self.logger = logger

        # Per-source traffic tracking: {src_mac: {packets, bytes, ...}}
        self.host_stats = defaultdict(lambda: {
            'prev_packets': 0,
            'prev_bytes': 0,
            'total_packets': 0,
            'total_bytes': 0,
            'destinations': set(),
        })

        # Port statistics: {(dpid, port): {...}}
        self.port_stats = defaultdict(lambda: {
            'prev_rx_packets': 0,
            'prev_tx_packets': 0,
        })

        # Flow stats from last collection: {(dpid, eth_src, eth_dst): {packets, bytes}}
        self.flow_cache = {}

        # Detected threats
        self.alerts = []
        self.alert_callbacks = []

        self.logger.info("[MONITOR] Traffic monitor initialized")
        self.logger.info("[MONITOR] Thresholds: DDoS=%d pkt, Scan=%d dests, "
                         "Interval=%ds",
                         DDOS_PACKET_THRESHOLD, PORT_SCAN_THRESHOLD,
                         MONITOR_INTERVAL)

    def register_alert_callback(self, callback):
        """Register a function to call when a threat is detected."""
        self.alert_callbacks.append(callback)

    def process_flow_stats(self, dpid, body):
        """
        Process flow statistics from a switch.
        Track per-source packet/byte counts.
        """
        for stat in body:
            if stat.priority < 10:
                continue

            match_fields = stat.match
            if 'eth_src' in match_fields and 'eth_dst' in match_fields:
                src_mac = match_fields['eth_src']
                dst_mac = match_fields['eth_dst']
            elif 'eth_dst' in match_fields:
                dst_mac = match_fields['eth_dst']
                src_mac = None
            else:
                continue

            # Store in flow cache for analysis
            key = (dpid, src_mac, dst_mac)
            self.flow_cache[key] = {
                'packets': stat.packet_count,
                'bytes': stat.byte_count,
            }

    def process_port_stats(self, dpid, body):
        """Process port statistics from a switch. Detect port-level anomalies."""
        for stat in body:
            port_no = stat.port_no

            # Skip special ports
            if port_no > 65000:
                continue

            port_key = (dpid, port_no)
            prev = self.port_stats[port_key]

            rx_rate = stat.rx_packets - prev['prev_rx_packets']

            self.port_stats[port_key] = {
                'prev_rx_packets': stat.rx_packets,
                'prev_tx_packets': stat.tx_packets,
            }

            if rx_rate > DDOS_PACKET_THRESHOLD and prev['prev_rx_packets'] > 0:
                # Check if this port connects to a host
                host_mac = self._find_host_on_port(dpid, port_no)
                if host_mac:
                    self._raise_alert(
                        'DDOS_DETECTED',
                        'High traffic from %s on s%d port %d: '
                        '%d packets/interval' %
                        (host_mac, dpid, port_no, rx_rate),
                        src_mac=host_mac,
                        dpid=dpid,
                        port=port_no,
                        pkt_rate=rx_rate,
                    )

    def _find_host_on_port(self, dpid, port_no):
        """Find which host MAC is connected to a specific switch port."""
        for mac, info in self.topo.mac_to_host.items():
            if info['dpid'] == dpid and info['port'] == port_no:
                return mac
        return None

    def analyze_traffic(self):
        """
        Analyze collected flow stats to detect threats.
        Called after each monitoring interval.
        """
        # Aggregate per-source stats from flow cache
        src_totals = defaultdict(lambda: {
            'packets': 0, 'bytes': 0, 'destinations': set()
        })

        for (dpid, src_mac, dst_mac), stats in self.flow_cache.items():
            if src_mac is None:
                continue
            src_totals[src_mac]['packets'] += stats['packets']
            src_totals[src_mac]['bytes'] += stats['bytes']
            src_totals[src_mac]['destinations'].add(dst_mac)

        # Compare with previous interval
        for src_mac, current in src_totals.items():
            prev = self.host_stats[src_mac]

            pkt_delta = current['packets'] - prev['prev_packets']
            byte_delta = current['bytes'] - prev['prev_bytes']
            num_dests = len(current['destinations'])

            # Update previous values
            self.host_stats[src_mac]['prev_packets'] = current['packets']
            self.host_stats[src_mac]['prev_bytes'] = current['bytes']
            self.host_stats[src_mac]['total_packets'] = current['packets']
            self.host_stats[src_mac]['total_bytes'] = current['bytes']

            # ── DDoS Detection ──
            if pkt_delta > DDOS_PACKET_THRESHOLD:
                self._raise_alert(
                    'DDOS_DETECTED',
                    'DDoS from %s: %d packets in last interval '
                    '(threshold: %d)' %
                    (src_mac, pkt_delta, DDOS_PACKET_THRESHOLD),
                    src_mac=src_mac,
                    pkt_rate=pkt_delta,
                    byte_rate=byte_delta,
                )

            # ── Port Scan Detection ──
            if num_dests > PORT_SCAN_THRESHOLD:
                self._raise_alert(
                    'PORT_SCAN_DETECTED',
                    'Port scan from %s: %d unique destinations '
                    '(threshold: %d)' %
                    (src_mac, num_dests, PORT_SCAN_THRESHOLD),
                    src_mac=src_mac,
                    dest_count=num_dests,
                )

        # Clear flow cache for next interval
        self.flow_cache = {}

    def _raise_alert(self, alert_type, message, **details):
        """Record a security alert and notify callbacks."""
        alert = {
            'type': alert_type,
            'message': message,
            'timestamp': time.time(),
            'details': details,
        }
        self.alerts.append(alert)
        self.logger.warning("[ALERT] %s: %s", alert_type, message)

        # Notify registered callbacks (e.g., mitigation engine)
        for callback in self.alert_callbacks:
            callback(alert)

    def get_alerts(self, limit=50):
        """Get recent alerts."""
        return self.alerts[-limit:]

    def get_stats_summary(self):
        """Get a summary of current stats."""
        return {
            'hosts_tracked': len(self.host_stats),
            'total_alerts': len(self.alerts),
            'ports_tracked': len(self.port_stats),
        }
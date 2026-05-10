"""
Traffic Monitor — Collects flow/port statistics and detects threats.

Detection capabilities:
    - DDoS: High packet rate from a single source (> threshold)
    - Port Scan: Single source contacting many destinations
    - Traffic anomaly: Sudden spike in traffic volume

Statistics are collected periodically via OpenFlow multipart requests.
"""

import time
from collections import defaultdict


# Detection thresholds
DDOS_PACKET_THRESHOLD = 500      # packets per interval from one source
DDOS_BYTE_THRESHOLD = 500000     # bytes per interval from one source
PORT_SCAN_THRESHOLD = 10         # unique destinations in one interval
MONITOR_INTERVAL = 10            # seconds between stat collections


class TrafficMonitor:
    """Monitors network traffic and detects security threats."""

    def __init__(self, topology_manager, logger):
        self.topo = topology_manager
        self.logger = logger

        # Traffic counters: {src_mac: {packets, bytes, destinations}}
        self.traffic_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'prev_packets': 0,
            'prev_bytes': 0,
            'destinations': set(),
        })

        # Port statistics: {(dpid, port): {rx_packets, tx_packets, ...}}
        self.port_stats = defaultdict(lambda: {
            'rx_packets': 0, 'tx_packets': 0,
            'rx_bytes': 0, 'tx_bytes': 0,
            'prev_rx_packets': 0, 'prev_tx_packets': 0,
        })

        # Detected threats
        self.alerts = []

        # Blocked hosts
        self.blocked_hosts = set()

        self.logger.info("[MONITOR] Traffic monitor initialized")
        self.logger.info("[MONITOR] Thresholds: DDoS=%d pkt/interval, "
                         "PortScan=%d destinations",
                         DDOS_PACKET_THRESHOLD, PORT_SCAN_THRESHOLD)

    def process_flow_stats(self, body):
        """
        Process flow statistics reply from a switch.
        Called when the controller receives OFPFlowStatsReply.
        """
        for stat in body:
            # Skip table-miss and ARP rules
            if stat.priority < 10:
                continue

            # Extract match fields
            if 'eth_dst' not in stat.match:
                continue

            dst_mac = stat.match['eth_dst']
            eth_src = stat.match.get('eth_src', 'unknown')

            # Update counters (we track by destination for now)
            self.traffic_stats[dst_mac]['packets'] = stat.packet_count
            self.traffic_stats[dst_mac]['bytes'] = stat.byte_count

    def process_port_stats(self, dpid, body):
        """
        Process port statistics reply from a switch.
        Called when the controller receives OFPPortStatsReply.
        """
        for stat in body:
            port_key = (dpid, stat.port_no)
            prev = self.port_stats[port_key]

            # Calculate rates (delta since last check)
            rx_rate = stat.rx_packets - prev['prev_rx_packets']
            tx_rate = stat.tx_packets - prev['prev_tx_packets']

            # Update stored values
            self.port_stats[port_key] = {
                'rx_packets': stat.rx_packets,
                'tx_packets': stat.tx_packets,
                'rx_bytes': stat.rx_bytes,
                'tx_bytes': stat.tx_bytes,
                'prev_rx_packets': stat.rx_packets,
                'prev_tx_packets': stat.tx_packets,
            }

            # Check for anomalous traffic rate on this port
            if rx_rate > DDOS_PACKET_THRESHOLD:
                self._raise_alert(
                    'HIGH_TRAFFIC',
                    'High traffic rate on s%d port %d: %d packets/interval' %
                    (dpid, stat.port_no, rx_rate),
                    dpid=dpid, port=stat.port_no, rate=rx_rate
                )

    def check_host_traffic(self, src_mac, dst_mac, packet_count, byte_count):
        """
        Check if a specific host's traffic is anomalous.
        Called per-flow when analyzing statistics.
        """
        stats = self.traffic_stats[src_mac]

        # Calculate rate (delta)
        pkt_rate = packet_count - stats['prev_packets']
        byte_rate = byte_count - stats['prev_bytes']

        # Track destinations
        stats['destinations'].add(dst_mac)

        # Update previous values
        stats['prev_packets'] = packet_count
        stats['prev_bytes'] = byte_count
        stats['packets'] = packet_count
        stats['bytes'] = byte_count

        # ── DDoS Detection ──
        if pkt_rate > DDOS_PACKET_THRESHOLD:
            self._raise_alert(
                'DDOS_DETECTED',
                'Possible DDoS from %s: %d packets/interval (threshold: %d)' %
                (src_mac, pkt_rate, DDOS_PACKET_THRESHOLD),
                src_mac=src_mac, pkt_rate=pkt_rate, byte_rate=byte_rate
            )
            return 'DDOS'

        if byte_rate > DDOS_BYTE_THRESHOLD:
            self._raise_alert(
                'DDOS_DETECTED',
                'Possible DDoS from %s: %d bytes/interval (threshold: %d)' %
                (src_mac, byte_rate, DDOS_BYTE_THRESHOLD),
                src_mac=src_mac, pkt_rate=pkt_rate, byte_rate=byte_rate
            )
            return 'DDOS'

        # ── Port Scan Detection ──
        if len(stats['destinations']) > PORT_SCAN_THRESHOLD:
            self._raise_alert(
                'PORT_SCAN_DETECTED',
                'Possible port scan from %s: %d unique destinations' %
                (src_mac, len(stats['destinations'])),
                src_mac=src_mac,
                dest_count=len(stats['destinations'])
            )
            return 'PORT_SCAN'

        return None

    def _raise_alert(self, alert_type, message, **details):
        """Record a security alert."""
        alert = {
            'type': alert_type,
            'message': message,
            'timestamp': time.time(),
            'details': details
        }
        self.alerts.append(alert)
        self.logger.warning("[ALERT] %s: %s", alert_type, message)

    def get_alerts(self, limit=50):
        """Get recent alerts."""
        return self.alerts[-limit:]

    def get_stats_summary(self):
        """Get a summary of traffic statistics."""
        return {
            'total_hosts_tracked': len(self.traffic_stats),
            'total_alerts': len(self.alerts),
            'blocked_hosts': list(self.blocked_hosts),
            'port_stats_count': len(self.port_stats),
        }

    def reset_interval_stats(self):
        """Reset per-interval counters (called after each monitoring cycle)."""
        for mac, stats in self.traffic_stats.items():
            stats['destinations'] = set()


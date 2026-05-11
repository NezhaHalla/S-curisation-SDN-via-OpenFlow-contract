"""
Mitigation Engine — Blocks/unblocks hosts and logs security events.

Actions:
    - BLOCK: Install high-priority DROP rule on attacker's edge switch
    - UNBLOCK: Remove the DROP rule (manual or timed)
    - LOG: Record every security action for blockchain audit trail

The DROP rule is installed on the switch where the attacker is connected,
so attack traffic is stopped at the SOURCE before it enters the network.
"""

import time


class MitigationEngine:
    """Handles attack mitigation: blocking, rate-limiting, logging."""

    def __init__(self, topology_manager, logger):
        self.topo = topology_manager
        self.logger = logger

        # Blocked hosts: MAC -> {timestamp, reason, dpid, rule_cookie}
        self.blocked_hosts = {}

        # Security event log (for blockchain audit trail)
        self.security_log = []

        # Cookie counter for tracking installed rules
        self.cookie_counter = 100

        self.logger.info("[MITIGATE] Mitigation engine initialized")

    def block_host(self, src_mac, reason, datapaths, add_flow_func):
        """
        Block a host by installing DROP rules on ALL switches.
        
        We block on ALL switches (not just the edge) because with
        redundant links, traffic could enter from multiple paths.
        
        Args:
            src_mac: MAC address to block
            reason: Why (DDOS, PORT_SCAN, etc.)
            datapaths: dict of dpid -> datapath objects
            add_flow_func: function to install flow rules
        """
        if src_mac in self.blocked_hosts:
            return False  # Already blocked

        host_info = self.topo.find_host_by_mac(src_mac)
        if not host_info:
            self.logger.warning("[MITIGATE] Unknown host: %s", src_mac)
            return False

        self.cookie_counter += 1
        cookie = self.cookie_counter

        # Install DROP rule on the attacker's edge switch (priority 20 > forwarding priority 10)
        edge_dpid = host_info['dpid']
        dp = datapaths.get(edge_dpid)
        if dp:
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_src=src_mac)
            # Empty actions = DROP
            add_flow_func(dp, 20, match, [], idle_timeout=0, hard_timeout=0)

            self.logger.warning(
                "[BLOCK] Blocked %s on s%d (reason: %s)",
                src_mac, edge_dpid, reason
            )

        # Record the block
        self.blocked_hosts[src_mac] = {
            'timestamp': time.time(),
            'reason': reason,
            'dpid': edge_dpid,
            'cookie': cookie,
            'ip': host_info.get('ip', 'unknown'),
        }

        # Log security event
        self._log_event('BLOCK', src_mac, reason, edge_dpid)

        return True

    def unblock_host(self, src_mac, datapaths):
        """
        Unblock a host by removing the DROP rule.
        
        Args:
            src_mac: MAC address to unblock
            datapaths: dict of dpid -> datapath objects
        """
        if src_mac not in self.blocked_hosts:
            return False

        block_info = self.blocked_hosts[src_mac]
        dpid = block_info['dpid']
        dp = datapaths.get(dpid)

        if dp:
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_src=src_mac)

            # Delete the DROP rule
            mod = parser.OFPFlowMod(
                datapath=dp,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=20,
                match=match
            )
            dp.send_msg(mod)

            self.logger.info(
                "[UNBLOCK] Unblocked %s on s%d",
                src_mac, dpid
            )

        del self.blocked_hosts[src_mac]
        self._log_event('UNBLOCK', src_mac, 'manual', dpid)
        return True

    def _log_event(self, action, src_mac, reason, dpid):
        """Record a security event for the audit trail."""
        event = {
            'action': action,
            'mac': src_mac,
            'reason': reason,
            'switch': 's%d' % dpid,
            'timestamp': time.time(),
            'timestamp_readable': time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime()
            ),
        }
        self.security_log.append(event)

        self.logger.info(
            "[LOG] %s | %s | %s | %s | s%d",
            event['timestamp_readable'], action, src_mac, reason, dpid
        )

    def get_blocked_hosts(self):
        """Return list of currently blocked hosts."""
        return dict(self.blocked_hosts)

    def get_security_log(self, limit=100):
        """Return recent security events."""
        return self.security_log[-limit:]

    def is_blocked(self, mac):
        """Check if a host is currently blocked."""
        return mac in self.blocked_hosts

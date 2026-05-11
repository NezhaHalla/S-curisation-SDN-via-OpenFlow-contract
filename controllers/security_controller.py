"""
SDN Security Controller — Main Controller
==========================================
Orchestrates all security modules:
    - TopologyManager: network graph + host database
    - ArpProxy: ARP without broadcasting
    - TrafficMonitor: stats collection + threat detection
    - MitigationEngine: block/unblock attackers + audit log

Usage:
    osken-manager controllers/security_controller.py
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types ,arp
from os_ken.lib import hub

from topology_manager import TopologyManager
from arp_proxy import ArpProxy
from traffic_monitor import TrafficMonitor, MONITOR_INTERVAL
from mitigation_engine import MitigationEngine


class SecurityController(app_manager.OSKenApp):
    """Main SDN Security Controller with detection and mitigation."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.flows_installed = False
        self.blocks_this_interval = 0  

        # Initialize modules
        self.topo = TopologyManager(self.logger)
        self.arp_proxy = ArpProxy(self.topo, self.logger)
        self.monitor = TrafficMonitor(self.topo, self.logger)
        self.mitigator = MitigationEngine(self.topo, self.logger)

        # Connect detection to mitigation
        self.monitor.register_alert_callback(self._handle_alert)

        self.logger.info("=" * 60)
        self.logger.info("  SDN SECURITY CONTROLLER v2.0")
        self.logger.info("  Modules: Topology | ARP Proxy | Monitor | Mitigator")
        self.logger.info("  Waiting for 7 switches to connect...")
        self.logger.info("=" * 60)

    # ══════════════════════════════════════════════════════════
    #  ALERT HANDLING — connects detection to mitigation
    # ══════════════════════════════════════════════════════════

    def _handle_alert(self, alert):
        """
        Called when TrafficMonitor detects a threat.
        Rate-limited: max 1 auto-block per monitoring interval
        to avoid blocking victims (false positives).
        """
        alert_type = alert['type']
        details = alert['details']
        src_mac = details.get('src_mac')

        if not src_mac:
            return

        # Skip if already blocked
        if self.mitigator.is_blocked(src_mac):
            return

        # Only auto-block ONE host per interval (avoid blocking victims)
        if self.blocks_this_interval >= 1:
            self.logger.info(
                "[ACTION] Alert for %s deferred — already blocked 1 host "
                "this interval (possible victim)", src_mac)
            return

        if alert_type == 'DDOS_DETECTED':
            self.logger.warning(
                "[ACTION] DDoS detected from %s — BLOCKING", src_mac)
            self.mitigator.block_host(
                src_mac, 'DDOS', self.datapaths, self._add_flow)
            self.blocks_this_interval += 1

        elif alert_type == 'PORT_SCAN_DETECTED':
            self.logger.warning(
                "[ACTION] Port scan detected from %s — BLOCKING", src_mac)
            self.mitigator.block_host(
                src_mac, 'PORT_SCAN', self.datapaths, self._add_flow)
            self.blocks_this_interval += 1

    # ══════════════════════════════════════════════════════════
    #  SWITCH CONNECTION
    # ══════════════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """New switch: clear old rules, install base rules."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.datapaths[dpid] = datapath
        self.logger.info("[SWITCH] s%s connected (%d/7)",
                         dpid, len(self.datapaths))

        # Delete all existing flow rules
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch()
        )
        datapath.send_msg(mod)

        # ARP -> controller
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_ctrl = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, 5, match_arp, actions_ctrl)

        # Default: DROP
        self._add_flow(datapath, 0, parser.OFPMatch(), [])

        # All switches? Install proactive rules + start monitoring
        if len(self.datapaths) >= 7 and not self.flows_installed:
            self._install_all_flows()
            hub.spawn(self._monitor_loop)

    # ══════════════════════════════════════════════════════════
    #  PROACTIVE FLOW INSTALLATION
    # ══════════════════════════════════════════════════════════

    def _install_all_flows(self):
        """Install shortest-path forwarding rules on every switch."""
        self.logger.info("[FLOWS] All 7 switches connected!")
        self.logger.info("[FLOWS] Installing shortest-path rules...")

        count = 0
        for mac, host_info in self.topo.mac_to_host.items():
            dst_dpid = host_info['dpid']
            dst_port = host_info['port']

            for dpid in range(1, 8):
                dp = self.datapaths.get(dpid)
                if not dp:
                    continue

                parser = dp.ofproto_parser

                if dpid == dst_dpid:
                    out_port = dst_port
                else:
                    path = self.topo.get_path(dpid, dst_dpid)
                    if not path or len(path) < 2:
                        continue
                    out_port = self.topo.get_next_hop_port(dpid, path[1])
                    if out_port is None:
                        continue

                match = parser.OFPMatch(eth_dst=mac)
                actions = [parser.OFPActionOutput(out_port)]
                self._add_flow(dp, 10, match, actions)
                count += 1

        self.flows_installed = True
        self.logger.info("[FLOWS] Done! %d rules installed", count)

        # Log paths between edge switches
        self.logger.info("[PATHS] Shortest paths:")
        edges = [4, 5, 6, 7]
        for i in range(len(edges)):
            for j in range(i + 1, len(edges)):
                path = self.topo.get_path(edges[i], edges[j])
                if path:
                    self.logger.info("  s%d <-> s%d : %s",
                        edges[i], edges[j],
                        " -> ".join(["s" + str(s) for s in path]))

    # ══════════════════════════════════════════════════════════
    #  TRAFFIC MONITORING
    # ══════════════════════════════════════════════════════════

    def _monitor_loop(self):
        """Periodically request stats and analyze traffic."""
        self.logger.info("[MONITOR] Started (interval: %ds)", MONITOR_INTERVAL)
        while True:
            hub.sleep(MONITOR_INTERVAL)
            self.blocks_this_interval = 0   
            for dpid, dp in self.datapaths.items():
                self._request_stats(dp)
            hub.sleep(2)
            self.monitor.analyze_traffic()

    def _request_stats(self, datapath):
        """Send flow and port stats requests to a switch."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Flow stats
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # Port stats
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply."""
        dpid = ev.msg.datapath.id
        self.monitor.process_flow_stats(dpid, ev.msg.body)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Handle port statistics reply."""
        dpid = ev.msg.datapath.id
        self.monitor.process_port_stats(dpid, ev.msg.body)

    # ══════════════════════════════════════════════════════════
    #  PACKET-IN (ARP only)
    # ══════════════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle ARP requests: proxy reply + track for port scan detection."""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth or eth.ethertype != ether_types.ETH_TYPE_ARP:
            return

        # Track ARP requests for port scan detection
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            self.monitor.record_arp_request(arp_pkt.src_ip, arp_pkt.dst_ip)

        # Let ARP proxy handle the reply
        self.arp_proxy.handle_arp(datapath, in_port, msg.data)

    # ══════════════════════════════════════════════════════════
    #  HELPER
    # ══════════════════════════════════════════════════════════

    def _add_flow(self, datapath, priority, match, actions,
                   idle_timeout=0, hard_timeout=0):
        """Install a flow rule on a switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)
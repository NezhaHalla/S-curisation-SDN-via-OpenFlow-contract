"""
SDN Security Controller — Main Controller
==========================================
Orchestrates all security modules:
    - TopologyManager: network graph + host database
    - ArpProxy: handles ARP without broadcasting
    - TrafficMonitor: collects stats + detects DDoS/port scans

Usage:
    osken-manager controllers/security_controller.py
"""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types
from os_ken.lib import hub

import networkx as nx

# Our modules
from controllers.topology_manager import TopologyManager
from controllers.arp_proxy import ArpProxy
from controllers.traffic_monitor import TrafficMonitor, MONITOR_INTERVAL


class SecurityController(app_manager.OSKenApp):
    """Main SDN Security Controller."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.flows_installed = False

        # Initialize modules
        self.topo = TopologyManager(self.logger)
        self.arp_proxy = ArpProxy(self.topo, self.logger)
        self.monitor = TrafficMonitor(self.topo, self.logger)

        self.logger.info("=" * 60)
        self.logger.info("  SDN SECURITY CONTROLLER STARTED")
        self.logger.info("  Modules: Topology, ARP Proxy, Traffic Monitor")
        self.logger.info("  Waiting for 7 switches to connect...")
        self.logger.info("=" * 60)

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

        # All switches connected? Install proactive rules + start monitoring
        if len(self.datapaths) >= 7 and not self.flows_installed:
            self._install_all_flows()
            # Start the traffic monitoring thread
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
    #  TRAFFIC MONITORING (Part 2)
    # ══════════════════════════════════════════════════════════

    def _monitor_loop(self):
        """Periodically request statistics from all switches."""
        self.logger.info("[MONITOR] Started (interval: %ds)", MONITOR_INTERVAL)
        while True:
            hub.sleep(MONITOR_INTERVAL)
            for dpid, dp in self.datapaths.items():
                self._request_stats(dp)
            self.monitor.reset_interval_stats()

    def _request_stats(self, datapath):
        """Send flow and port stats requests to a switch."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Request flow stats
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # Request port stats
        req = parser.OFPPortStatsRequest(
            datapath, 0, ofproto.OFPP_ANY
        )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply."""
        body = ev.msg.body
        self.monitor.process_flow_stats(body)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Handle port statistics reply."""
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        self.monitor.process_port_stats(dpid, body)

    # ══════════════════════════════════════════════════════════
    #  PACKET-IN (ARP only)
    # ══════════════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle ARP requests via the ARP proxy module."""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth or eth.ethertype != ether_types.ETH_TYPE_ARP:
            return

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
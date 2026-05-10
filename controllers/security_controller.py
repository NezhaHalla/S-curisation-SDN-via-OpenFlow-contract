"""
SDN Security Controller - Part 1: Proactive Shortest-Path Forwarding
=====================================================================
Key idea: We KNOW the topology and host locations, so we pre-install
ALL forwarding rules at startup. No flooding, no learning, no storms.

Flow:
    1. Controller starts with pre-defined topology + hosts
    2. Switches connect -> base rules installed (ARP->controller, drop rest)
    3. All 7 switches connected -> shortest-path rules on ALL switches
    4. ARP requests -> controller replies instantly (ARP proxy)
    5. Data traffic -> forwarded by switch rules (no controller needed)

Usage:
    osken-manager controllers/security_controller.py
"""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, arp

import networkx as nx


class SecurityController(app_manager.OSKenApp):
    """SDN Security Controller with proactive shortest-path forwarding."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.topology_graph = nx.Graph()
        self.port_map = {}
        self.hosts = {}
        self.mac_to_host = {}
        self.flows_installed = False

        # Security tracking (for Phase 2)
        self.blocked_hosts = set()
        self.security_log = []

        self._build_topology()
        self._define_hosts()

        self.logger.info("=" * 60)
        self.logger.info("  SDN SECURITY CONTROLLER STARTED")
        self.logger.info("  Mode: Proactive shortest-path forwarding")
        self.logger.info("  Waiting for 7 switches to connect...")
        self.logger.info("=" * 60)

    def _build_topology(self):
        """Define switch topology. Port numbers from: mininet> links"""
        for dpid in range(1, 8):
            self.topology_graph.add_node(dpid)

        links = [
            (1, 1, 2, 1),   # s1-eth1 <-> s2-eth1
            (1, 2, 3, 1),   # s1-eth2 <-> s3-eth1
            (2, 2, 4, 1),   # s2-eth2 <-> s4-eth1
            (2, 3, 5, 1),   # s2-eth3 <-> s5-eth1
            (3, 2, 6, 1),   # s3-eth2 <-> s6-eth1
            (3, 3, 7, 1),   # s3-eth3 <-> s7-eth1
            (2, 4, 3, 4),   # s2-eth4 <-> s3-eth4  (redundant)
            (5, 2, 3, 5),   # s5-eth2 <-> s3-eth5  (redundant)
            (6, 2, 2, 5),   # s6-eth2 <-> s2-eth5  (redundant)
        ]

        for sw_a, port_a, sw_b, port_b in links:
            self.topology_graph.add_edge(sw_a, sw_b)
            self.port_map[(sw_a, sw_b)] = port_a
            self.port_map[(sw_b, sw_a)] = port_b

    def _define_hosts(self):
        """Pre-define all host locations. From: mininet> links"""
        host_defs = [
            ('10.0.0.1', '00:00:00:00:00:01', 4, 2),
            ('10.0.0.2', '00:00:00:00:00:02', 4, 3),
            ('10.0.0.3', '00:00:00:00:00:03', 5, 3),
            ('10.0.0.4', '00:00:00:00:00:04', 5, 4),
            ('10.0.0.5', '00:00:00:00:00:05', 6, 3),
            ('10.0.0.6', '00:00:00:00:00:06', 6, 4),
            ('10.0.0.7', '00:00:00:00:00:07', 7, 2),
            ('10.0.0.8', '00:00:00:00:00:08', 7, 3),
        ]
        for ip, mac, dpid, port in host_defs:
            self.hosts[ip] = {'mac': mac, 'dpid': dpid, 'port': port}
            self.mac_to_host[mac] = {'ip': ip, 'dpid': dpid, 'port': port}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """New switch: clear old rules, install base rules."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.datapaths[dpid] = datapath
        self.logger.info("[SWITCH] s%s connected (%d/7)", dpid, len(self.datapaths))

        # Delete ALL existing flow rules (clean slate)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch()
        )
        datapath.send_msg(mod)

        # ARP packets -> send to controller (for ARP proxy)
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions_ctrl = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, 5, match_arp, actions_ctrl)

        # Default: DROP everything (no flooding = no storms)
        self._add_flow(datapath, 0, parser.OFPMatch(), [])

        # All switches connected? Install proactive rules!
        if len(self.datapaths) >= 7 and not self.flows_installed:
            self._install_all_flows()

    def _install_all_flows(self):
        """
        Install forwarding rules on EVERY switch for EVERY host.
        Each switch learns: to reach MAC X, send out port Y.
        """
        self.logger.info("[FLOWS] All 7 switches connected!")
        self.logger.info("[FLOWS] Installing shortest-path rules...")

        count = 0
        for mac, host_info in self.mac_to_host.items():
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
                    try:
                        path = nx.shortest_path(
                            self.topology_graph, dpid, dst_dpid
                        )
                    except nx.NetworkXNoPath:
                        continue
                    next_hop = path[1]
                    out_port = self.port_map.get((dpid, next_hop))
                    if out_port is None:
                        continue

                match = parser.OFPMatch(eth_dst=mac)
                actions = [parser.OFPActionOutput(out_port)]
                self._add_flow(dp, 10, match, actions)
                count += 1

        self.flows_installed = True
        self.logger.info("[FLOWS] Done! %d rules installed", count)

        # Show shortest paths between edge switches
        self.logger.info("[PATHS] Shortest paths:")
        edges = [4, 5, 6, 7]
        for i in range(len(edges)):
            for j in range(i + 1, len(edges)):
                path = nx.shortest_path(
                    self.topology_graph, edges[i], edges[j]
                )
                self.logger.info("  s%d <-> s%d : %s",
                    edges[i], edges[j],
                    " -> ".join(["s" + str(s) for s in path]))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Only ARP requests should reach here."""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth or eth.ethertype != ether_types.ETH_TYPE_ARP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        if not arp_pkt or arp_pkt.opcode != arp.ARP_REQUEST:
            return

        dst_ip = arp_pkt.dst_ip
        if dst_ip not in self.hosts:
            return

        target = self.hosts[dst_ip]
        self.logger.info("[ARP] %s asks: who has %s? -> %s",
                         arp_pkt.src_ip, dst_ip, target['mac'])

        # Build and send ARP reply
        eth_reply = ethernet.ethernet(
            dst=arp_pkt.src_mac,
            src=target['mac'],
            ethertype=ether_types.ETH_TYPE_ARP
        )
        arp_reply = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=target['mac'],
            src_ip=dst_ip,
            dst_mac=arp_pkt.src_mac,
            dst_ip=arp_pkt.src_ip
        )
        reply = packet.Packet()
        reply.add_protocol(eth_reply)
        reply.add_protocol(arp_reply)
        reply.serialize()

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=reply.data
        )
        datapath.send_msg(out)

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

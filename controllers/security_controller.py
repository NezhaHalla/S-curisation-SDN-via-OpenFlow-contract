"""
SDN Security Controller — Part 1: Smart Forwarding + ARP Proxy
===============================================================
Features:
    1. Pre-defined topology graph (matches our Mininet topology)
    2. Shortest path forwarding using Dijkstra (no flooding, no loops)
    3. ARP Proxy (controller answers ARP requests directly)
    4. Controller-based broadcast (ARP to all hosts without inter-switch flooding)

Usage:
    osken-manager controllers/security_controller.py
"""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, arp, ipv4

import networkx as nx
from collections import defaultdict


class SecurityController(app_manager.OSKenApp):
    """SDN Security Controller with topology-aware forwarding and ARP proxy."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)

        # Network topology graph
        self.topology_graph = nx.Graph()
        self.port_map = {}
        self._build_topology()

        # Host tracking: IP -> {mac, dpid, port}
        self.hosts = {}

        # Active datapaths: dpid -> datapath object
        self.datapaths = {}

        # Switch-to-switch ports (to distinguish from host ports)
        self.switch_ports = defaultdict(set)

        # Security tracking (for Phase 2)
        self.blocked_hosts = set()
        self.security_log = []

        # Track installed flows to avoid duplicates
        self.installed_flows = set()

        self.logger.info("=" * 60)
        self.logger.info("  SDN SECURITY CONTROLLER STARTED")
        self.logger.info("  Topology: 7 switches, 9 links")
        self.logger.info("=" * 60)

    def _build_topology(self):
        """
        Define the network topology matching our Mininet setup.
        Port numbers verified from 'mininet> links' output.
        """
        for dpid in range(1, 8):
            self.topology_graph.add_node(dpid)

        # (switch_a, port_a, switch_b, port_b) — verified from Mininet
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
            self.switch_ports[sw_a].add(port_a)
            self.switch_ports[sw_b].add(port_b)

        self.logger.info("[TOPOLOGY] %d switches, %d links",
                         self.topology_graph.number_of_nodes(),
                         self.topology_graph.number_of_edges())

    # ══════════════════════════════════════════════════════════
    #  SWITCH CONNECTION
    # ══════════════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss flow entry on new switch."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.datapaths[dpid] = datapath
        self.logger.info("[SWITCH] s%s connected", dpid)

        # Table-miss: send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, 0, match, actions)

    # ══════════════════════════════════════════════════════════
    #  PACKET-IN HANDLER
    # ══════════════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP and IPv6
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.dst.startswith('33:33'):
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # ── Handle ARP ──
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(datapath, in_port, eth, arp_pkt, msg)
            return

        # ── Handle unicast data packets ──
        if dst_mac == 'ff:ff:ff:ff:ff:ff':
            return  # Ignore non-ARP broadcasts

        # Find destination
        dst_host = self._find_host_by_mac(dst_mac)
        if dst_host:
            self._route_packet(datapath, dpid, in_port, dst_mac, dst_host, msg)

    # ══════════════════════════════════════════════════════════
    #  ARP HANDLING
    # ══════════════════════════════════════════════════════════

    def _handle_arp(self, datapath, in_port, eth, arp_pkt, msg):
        """Handle all ARP packets: learn hosts, proxy replies, broadcast requests."""
        dpid = datapath.id
        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac

        # Learn the source host
        if src_ip and src_ip not in self.hosts:
            self.hosts[src_ip] = {
                'mac': src_mac,
                'dpid': dpid,
                'port': in_port
            }
            self.logger.info(
                "[HOST] %s (%s) on s%s port %s",
                src_ip, src_mac, dpid, in_port
            )

        if arp_pkt.opcode == arp.ARP_REQUEST:
            dst_ip = arp_pkt.dst_ip

            if dst_ip in self.hosts:
                # Known host — reply directly (ARP Proxy)
                self._send_arp_reply(datapath, in_port, arp_pkt)
            else:
                # Unknown host — send ARP to all host ports
                self._broadcast_to_hosts(msg.data, dpid, in_port)

        elif arp_pkt.opcode == arp.ARP_REPLY:
            # Route the ARP reply to the destination
            dst_host = self._find_host_by_mac(arp_pkt.dst_mac)
            if dst_host:
                self._route_packet(datapath, dpid, in_port,
                                   arp_pkt.dst_mac, dst_host, msg)

    def _send_arp_reply(self, datapath, in_port, arp_pkt):
        """Generate and send an ARP reply from the controller."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        target_ip = arp_pkt.dst_ip
        target_mac = self.hosts[target_ip]['mac']

        self.logger.info("[ARP PROXY] %s is at %s", target_ip, target_mac)

        eth_reply = ethernet.ethernet(
            dst=arp_pkt.src_mac,
            src=target_mac,
            ethertype=ether_types.ETH_TYPE_ARP
        )
        arp_reply = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=target_mac,
            src_ip=target_ip,
            dst_mac=arp_pkt.src_mac,
            dst_ip=arp_pkt.src_ip
        )
        reply = packet.Packet()
        reply.add_protocol(eth_reply)
        reply.add_protocol(arp_reply)
        reply.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=reply.data
        )
        datapath.send_msg(out)

    def _broadcast_to_hosts(self, data, src_dpid, src_port):
        """
        Send a packet directly to ALL host ports on ALL switches.

        This replaces traditional flooding:
        - No inter-switch flooding (no loops possible)
        - Controller sends directly to each switch's host ports
        - Clean, deterministic, loop-free
        """
        for dpid, dp in self.datapaths.items():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser

            # Get host ports (all ports minus switch-to-switch ports)
            host_ports = set()
            for p in dp.ports.values():
                port_no = p.port_no
                if port_no == ofproto.OFPP_LOCAL:
                    continue
                if port_no not in self.switch_ports.get(dpid, set()):
                    host_ports.add(port_no)

            # Don't send back to the source port
            if dpid == src_dpid:
                host_ports.discard(src_port)

            if not host_ports:
                continue

            actions = [parser.OFPActionOutput(port) for port in host_ports]
            out = parser.OFPPacketOut(
                datapath=dp,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=data
            )
            dp.send_msg(out)

    # ══════════════════════════════════════════════════════════
    #  ROUTING
    # ══════════════════════════════════════════════════════════

    def _route_packet(self, datapath, dpid, in_port, dst_mac, dst_host, msg):
        """Route a packet to a known destination using shortest path."""
        dst_dpid = dst_host['dpid']
        dst_port = dst_host['port']
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if dpid == dst_dpid:
            # Same switch
            out_port = dst_port
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(datapath, 10, match, actions, idle_timeout=300)
            self._send_packet(datapath, msg, in_port, out_port)
        else:
            # Different switch — shortest path
            path = self._get_path(dpid, dst_dpid)
            if path and len(path) >= 2:
                # Only log if this is a new path
                flow_key = (dpid, dst_mac)
                if flow_key not in self.installed_flows:
                    self.installed_flows.add(flow_key)
                    self.logger.info(
                        "[PATH] %s → %s",
                        " → ".join(["s" + str(s) for s in path]),
                        dst_mac
                    )

                self._install_path(path, dst_mac, dst_port)

                # Forward current packet
                out_port = self.port_map.get((path[0], path[1]))
                if out_port:
                    self._send_packet(datapath, msg, in_port, out_port)

    def _get_path(self, src_dpid, dst_dpid):
        """Compute shortest path using Dijkstra."""
        try:
            if src_dpid == dst_dpid:
                return [src_dpid]
            return nx.shortest_path(self.topology_graph, src_dpid, dst_dpid)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def _install_path(self, path, dst_mac, final_port):
        """Install flow rules on every switch along the path."""
        for i in range(len(path)):
            dp = self.datapaths.get(path[i])
            if not dp:
                continue

            parser = dp.ofproto_parser
            ofproto = dp.ofproto

            if i < len(path) - 1:
                out_port = self.port_map.get((path[i], path[i + 1]))
            else:
                out_port = final_port

            if out_port is None:
                continue

            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(dp, 10, match, actions, idle_timeout=300)

    # ══════════════════════════════════════════════════════════
    #  HELPERS
    # ══════════════════════════════════════════════════════════

    def _find_host_by_mac(self, mac):
        """Find host info by MAC address."""
        for ip, info in self.hosts.items():
            if info['mac'] == mac:
                return info
        return None

    def _send_packet(self, datapath, msg, in_port, out_port):
        """Send a single packet out a specific port."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    def _add_flow(self, datapath, priority, match, actions,
                   idle_timeout=0, hard_timeout=0):
        """Install a flow rule on a switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
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
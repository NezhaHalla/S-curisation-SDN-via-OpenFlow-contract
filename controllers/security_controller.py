"""
SDN Security Controller — Part 1: Topology Discovery + Smart Forwarding
========================================================================
This controller replaces the basic L2 switch with intelligent features:

1. TOPOLOGY DISCOVERY: Learns the full network graph (switches + links)
   using LLDP packets. Builds a NetworkX graph of the topology.

2. SHORTEST PATH FORWARDING: Computes optimal paths between hosts
   using Dijkstra's algorithm. Installs precise flow rules instead
   of flooding — this prevents loops and enables redundant links.

3. HOST TRACKING: Learns which host (IP + MAC) is connected to which
   switch and port by inspecting ARP packets.

Architecture:
    packet_in → Is it LLDP? → Yes → Update topology graph
                             → No  → Is it ARP? → Learn host location
                                                 → Compute shortest path
                                                 → Install flow rules along path

Usage:
    osken-manager controllers/security_controller.py
"""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, arp, ipv4, lldp
from os_ken.lib import hub
from os_ken.topology import event as topo_event
from os_ken.topology.api import get_switch, get_link

import networkx as nx
import time
import json
import logging
from collections import defaultdict


class SecurityController(app_manager.OSKenApp):
    """
    SDN Security Controller with topology-aware forwarding.

    Instead of flooding (like L2 switch), this controller:
    1. Discovers the network topology automatically
    2. Computes shortest paths between any two hosts
    3. Installs flow rules along the entire path
    4. Handles redundant links without loops

    Attributes:
        topology_graph: NetworkX graph of the network (switches = nodes, links = edges)
        hosts:          Dictionary mapping IP → {mac, dpid, port}
        mac_to_port:    Dictionary mapping (dpid, mac) → port (for fast lookups)
        datapaths:      Dictionary mapping dpid → datapath object (for sending commands)
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SecurityController, self).__init__(*args, **kwargs)

        # ── Network topology graph ──
        # Nodes = switch dpids, Edges = links between switches
        # We use NetworkX for graph operations (shortest path, etc.)
        self.topology_graph = nx.Graph()

        # ── Host tracking ──
        # Maps IP address → {mac, dpid, port}
        # Example: '10.0.0.1' → {'mac': '00:00:00:00:00:01', 'dpid': 4, 'port': 1}
        self.hosts = {}

        # ── MAC to port mapping (per switch) ──
        # Maps (dpid, mac) → port number
        self.mac_to_port = {}

        # ── Active datapaths (switches) ──
        # Maps dpid → datapath object (needed to send OpenFlow messages)
        self.datapaths = {}

        # ── Traffic statistics (for Phase 2: detection) ──
        self.flow_stats = defaultdict(list)
        self.port_stats = defaultdict(list)

        # ── Blocked hosts (for Phase 3: mitigation) ──
        self.blocked_hosts = set()

        # ── Security event log ──
        self.security_log = []

        self.logger.info("="*60)
        self.logger.info("  SDN SECURITY CONTROLLER STARTED")
        self.logger.info("  Features: Topology Discovery, Shortest Path Forwarding")
        self.logger.info("="*60)

        # Start topology discovery thread
        self.topology_discovery_thread = hub.spawn(self._topology_discovery_loop)

    # ══════════════════════════════════════════════════════════
    #  SWITCH CONNECTION HANDLER
    # ══════════════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle new switch connection — install table-miss flow entry."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Store the datapath reference
        self.datapaths[dpid] = datapath

        self.logger.info("[SWITCH CONNECTED] Switch s%s (dpid=%s)", dpid, dpid)

        # Install table-miss flow entry (send unmatched packets to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

    # ══════════════════════════════════════════════════════════
    #  TOPOLOGY DISCOVERY
    # ══════════════════════════════════════════════════════════

    def _topology_discovery_loop(self):
        """Periodically discover and update the network topology."""
        while True:
            self._update_topology()
            hub.sleep(5)  # Refresh every 5 seconds

    def _update_topology(self):
        """Query os-ken's topology module for current switches and links."""
        try:
            # Get all switches
            switch_list = get_switch(self, None)
            switches = [s.dp.id for s in switch_list]

            # Get all links
            link_list = get_link(self, None)

            # Rebuild the graph
            self.topology_graph.clear()

            # Add switches as nodes
            for dpid in switches:
                self.topology_graph.add_node(dpid)

            # Add links as edges (with port information)
            for link in link_list:
                src_dpid = link.src.dpid
                dst_dpid = link.dst.dpid
                src_port = link.src.port_no
                dst_port = link.dst.port_no

                # Store port info as edge attributes
                self.topology_graph.add_edge(
                    src_dpid, dst_dpid,
                    src_port=src_port,
                    dst_port=dst_port
                )

            if switches:
                self.logger.debug("[TOPOLOGY] %d switches, %d links",
                                  len(switches),
                                  self.topology_graph.number_of_edges())
        except Exception as e:
            self.logger.debug("[TOPOLOGY] Discovery waiting: %s", e)

    def get_path(self, src_dpid, dst_dpid):
        """
        Compute shortest path between two switches using Dijkstra's algorithm.

        Args:
            src_dpid: Source switch datapath ID
            dst_dpid: Destination switch datapath ID

        Returns:
            List of switch dpids forming the path, or None if no path exists.
            Example: [4, 2, 1, 3, 7] means s4 → s2 → s1 → s3 → s7
        """
        try:
            if src_dpid == dst_dpid:
                return [src_dpid]

            if (src_dpid in self.topology_graph and
                    dst_dpid in self.topology_graph):
                path = nx.shortest_path(
                    self.topology_graph,
                    source=src_dpid,
                    target=dst_dpid
                )
                return path
        except nx.NetworkXNoPath:
            self.logger.warning("[PATH] No path from s%s to s%s", src_dpid, dst_dpid)
        except nx.NodeNotFound:
            self.logger.debug("[PATH] Switch not in topology yet")

        return None

    def get_out_port(self, src_dpid, dst_dpid):
        """
        Get the output port on src_dpid to reach dst_dpid.

        Returns:
            Port number, or None if switches are not directly connected.
        """
        if self.topology_graph.has_edge(src_dpid, dst_dpid):
            edge_data = self.topology_graph[src_dpid][dst_dpid]
            return edge_data['src_port']
        return None

    # ══════════════════════════════════════════════════════════
    #  PACKET-IN HANDLER (Main Logic)
    # ══════════════════════════════════════════════════════════

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle packets that the switch doesn't know how to forward."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        # Parse the packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP (used by topology discovery)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Ignore IPv6 multicast (reduces noise)
        if eth.dst.startswith('33:33'):
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # ── Learn the source MAC location ──
        self.mac_to_port[(dpid, src_mac)] = in_port

        # ── Learn host from ARP packets ──
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            if src_ip not in self.hosts:
                self.hosts[src_ip] = {
                    'mac': src_mac,
                    'dpid': dpid,
                    'port': in_port
                }
                self.logger.info(
                    "[HOST DISCOVERED] %s (MAC: %s) on Switch s%s, Port %s",
                    src_ip, src_mac, dpid, in_port
                )

        # ── Forwarding decision ──
        # Check if we know the destination host
        dst_host = None
        for ip, info in self.hosts.items():
            if info['mac'] == dst_mac:
                dst_host = info
                break

        if dst_host is not None:
            # We know the destination! Compute shortest path.
            dst_dpid = dst_host['dpid']
            dst_port = dst_host['port']

            if dpid == dst_dpid:
                # Destination is on the SAME switch
                out_port = dst_port
                self._install_and_forward(
                    datapath, parser, ofproto, msg,
                    in_port, out_port, src_mac, dst_mac
                )
            else:
                # Destination is on a DIFFERENT switch — use shortest path
                path = self.get_path(dpid, dst_dpid)

                if path and len(path) >= 2:
                    self.logger.info(
                        "[PATH COMPUTED] %s → %s : %s",
                        src_mac, dst_mac,
                        " → ".join(["s" + str(s) for s in path])
                    )

                    # Install flow rules along the ENTIRE path
                    self._install_path_flows(
                        path, src_mac, dst_mac, dst_port, msg
                    )
                else:
                    # No path found — flood as fallback
                    self._flood(datapath, parser, ofproto, msg, in_port)
        else:
            # Unknown destination — flood (ARP request will discover it)
            self._flood(datapath, parser, ofproto, msg, in_port)

    # ══════════════════════════════════════════════════════════
    #  FLOW INSTALLATION HELPERS
    # ══════════════════════════════════════════════════════════

    def _install_path_flows(self, path, src_mac, dst_mac, final_port, msg):
        """
        Install flow rules along the entire computed path.

        This is the key difference from L2 switch:
        - L2 switch: installs rules one switch at a time (reactive)
        - Security controller: installs rules on ALL switches at once (proactive)

        Example: Path = [s4, s2, s1, s3, s7], dst_port = 1
            s4: match(dst_mac) → output(port to s2)
            s2: match(dst_mac) → output(port to s1)
            s1: match(dst_mac) → output(port to s3)
            s3: match(dst_mac) → output(port to s7)
            s7: match(dst_mac) → output(port 1 = host port)
        """
        for i in range(len(path)):
            current_dpid = path[i]
            datapath = self.datapaths.get(current_dpid)

            if datapath is None:
                continue

            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            if i < len(path) - 1:
                # Intermediate switch — forward to next switch in path
                next_dpid = path[i + 1]
                out_port = self.get_out_port(current_dpid, next_dpid)
            else:
                # Last switch in path — forward to the host
                out_port = final_port

            if out_port is None:
                continue

            # Install the flow rule
            match = parser.OFPMatch(eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(datapath, priority=10, match=match,
                           actions=actions, idle_timeout=300)

            self.logger.debug(
                "[FLOW INSTALLED] Switch s%s: %s → Port %s",
                current_dpid, dst_mac, out_port
            )

        # Send the current packet on its way (first switch in path)
        first_dpid = path[0]
        first_dp = self.datapaths.get(first_dpid)
        if first_dp:
            if len(path) >= 2:
                out_port = self.get_out_port(path[0], path[1])
            else:
                out_port = final_port

            if out_port:
                parser = first_dp.ofproto_parser
                ofproto = first_dp.ofproto
                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(
                    datapath=first_dp,
                    buffer_id=msg.buffer_id,
                    in_port=msg.match['in_port'],
                    actions=actions,
                    data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                )
                first_dp.send_msg(out)

    def _install_and_forward(self, datapath, parser, ofproto, msg,
                              in_port, out_port, src_mac, dst_mac):
        """Install a flow rule and forward the packet (same switch)."""
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
        actions = [parser.OFPActionOutput(out_port)]
        self._add_flow(datapath, priority=10, match=match,
                       actions=actions, idle_timeout=300)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    def _flood(self, datapath, parser, ofproto, msg, in_port):
        """Flood a packet to all ports (fallback when destination is unknown)."""
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
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
"""
Topology Manager — Network graph and host location database.
Handles: topology definition, host tracking, shortest path computation.
"""

import networkx as nx


class TopologyManager:
    """Manages the network topology graph and host locations."""

    def __init__(self, logger):
        self.logger = logger
        self.topology_graph = nx.Graph()
        self.port_map = {}       # (src_dpid, dst_dpid) -> src_port
        self.hosts = {}          # IP -> {mac, dpid, port}
        self.mac_to_host = {}    # MAC -> {ip, dpid, port}

        self._build_topology()
        self._define_hosts()

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

        self.logger.info("[TOPOLOGY] %d switches, %d links",
                         self.topology_graph.number_of_nodes(),
                         self.topology_graph.number_of_edges())

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

        self.logger.info("[TOPOLOGY] %d hosts defined", len(self.hosts))

    def get_path(self, src_dpid, dst_dpid):
        """Compute shortest path using Dijkstra."""
        try:
            if src_dpid == dst_dpid:
                return [src_dpid]
            return nx.shortest_path(self.topology_graph, src_dpid, dst_dpid)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def get_next_hop_port(self, src_dpid, dst_dpid):
        """Get output port on src_dpid to reach dst_dpid."""
        return self.port_map.get((src_dpid, dst_dpid))

    def find_host_by_mac(self, mac):
        """Look up host info by MAC address."""
        return self.mac_to_host.get(mac)

    def find_host_by_ip(self, ip):
        """Look up host info by IP address."""
        return self.hosts.get(ip)

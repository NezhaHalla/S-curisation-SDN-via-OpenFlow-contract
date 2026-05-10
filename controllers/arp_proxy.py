"""
ARP Proxy — Handles ARP requests without broadcasting.
The controller answers ARP requests directly from its host database.
"""

from os_ken.lib.packet import packet, ethernet, ether_types, arp


class ArpProxy:
    """Handles ARP requests by replying from a known host database."""

    def __init__(self, topology_manager, logger):
        self.topo = topology_manager
        self.logger = logger

    def handle_arp(self, datapath, in_port, pkt_data):
        """
        Process an ARP packet. Returns True if handled, False otherwise.

        Only handles ARP REQUEST for known hosts.
        ARP REPLY is ignored (forwarded by flow rules).
        """
        pkt = packet.Packet(pkt_data)
        arp_pkt = pkt.get_protocol(arp.arp)

        if not arp_pkt or arp_pkt.opcode != arp.ARP_REQUEST:
            return False

        dst_ip = arp_pkt.dst_ip
        target = self.topo.find_host_by_ip(dst_ip)

        if target is None:
            return False

        self.logger.info("[ARP] %s asks: who has %s? -> %s",
                         arp_pkt.src_ip, dst_ip, target['mac'])

        self._send_reply(datapath, in_port, arp_pkt, target)
        return True

    def _send_reply(self, datapath, in_port, arp_pkt, target):
        """Build and send an ARP reply packet."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        eth_reply = ethernet.ethernet(
            dst=arp_pkt.src_mac,
            src=target['mac'],
            ethertype=ether_types.ETH_TYPE_ARP
        )
        arp_reply = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=target['mac'],
            src_ip=arp_pkt.dst_ip,
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

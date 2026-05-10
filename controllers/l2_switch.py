"""
L2 Learning Switch Controller (Basic SDN Brain)
================================================
This is the simplest useful SDN controller. It makes switches behave
like normal Ethernet switches by "learning" which host is on which port.

How it works:
    1. A packet arrives at a switch, and the switch doesn't know where to send it
    2. The switch sends the packet to the controller (packet_in event)
    3. The controller looks at the source MAC address and records:
       "MAC address X is reachable via port Y on switch Z"
    4. The controller checks if it knows the destination MAC:
       - If YES: Install a flow rule → "send packets for MAC X out port Y"
       - If NO:  Flood the packet out all ports (the destination will reply,
                 and then we'll learn its port)

Usage:
    osken-manager controllers/l2_switch.py
"""

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet
from os_ken.lib import hub


class L2Switch(app_manager.OSKenApp):
    """
    A simple L2 learning switch.

    Attributes:
        mac_to_port: Dictionary mapping (switch_id) → {mac_address: port_number}
                     This is the "memory" of the controller — it remembers
                     which MAC address is connected to which port on each switch.
    """

    # Tell os-ken we want to use OpenFlow 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)

        # The MAC address table: {switch_id: {mac: port}}
        # Example: {1: {'00:00:00:00:00:01': 1, '00:00:00:00:00:02': 2}}
        # This means: on switch 1, MAC ...01 is on port 1, MAC ...02 is on port 2
        self.mac_to_port = {}

        self.logger.info("L2 Switch Controller started")

    # ──────────────────────────────────────────────
    # EVENT: Switch connects to the controller
    # ──────────────────────────────────────────────
    # This fires when a switch first connects.
    # We install a "table-miss" flow entry: if no rule matches a packet,
    # send it to the controller. Without this, unmatched packets are dropped.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle new switch connection — install table-miss flow entry."""

        datapath = ev.msg.datapath       # The switch that connected
        ofproto = datapath.ofproto       # OpenFlow protocol constants
        parser = datapath.ofproto_parser  # Tool to build OpenFlow messages

        self.logger.info("Switch %s connected (dpid=%s)",
                         datapath.id, datapath.id)

        # Table-miss flow entry:
        # Match: everything (empty match = wildcard)
        # Action: send to controller
        # Priority: 0 (lowest — only triggers if no other rule matches)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

    # ──────────────────────────────────────────────
    # EVENT: A packet arrives that no flow rule matches
    # ──────────────────────────────────────────────
    # This is the core logic — learning + forwarding.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle a packet that the switch doesn't know how to forward."""

        msg = ev.msg
        datapath = msg.datapath          # Which switch sent this packet
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']   # Which port the packet came in on

        # Parse the packet to extract Ethernet header
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets (used for topology discovery, not our concern here)
        if eth.ethertype == 0x88cc:
            return

        dst_mac = eth.dst    # Where the packet wants to go
        src_mac = eth.src    # Where the packet came from
        dpid = datapath.id   # Switch ID (datapath ID)

        # ── LEARN: Record the source MAC and its port ──
        # "On switch {dpid}, MAC {src_mac} is reachable via port {in_port}"
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        self.logger.info("LEARN: Switch s%s | MAC %s → Port %s",
                         dpid, src_mac, in_port)

        # ── FORWARD: Decide where to send the packet ──
        if dst_mac in self.mac_to_port[dpid]:
            # We know the destination! Send to the correct port.
            out_port = self.mac_to_port[dpid][dst_mac]
            self.logger.info("FORWARD: Switch s%s | %s → %s via Port %s",
                             dpid, src_mac, dst_mac, out_port)
        else:
            # We don't know the destination yet. Flood to all ports.
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("FLOOD: Switch s%s | %s → %s (unknown destination)",
                             dpid, src_mac, dst_mac)

        actions = [parser.OFPActionOutput(out_port)]

        # ── INSTALL FLOW RULE: So next time, the switch handles it directly ──
        # Only install a rule if we know the exact output port (not flooding)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self._add_flow(datapath, priority=1, match=match, actions=actions)

        # ── Send the current packet out ──
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=60):
        """
        Helper: Install a flow rule on a switch.

        Args:
            datapath:     The switch to install the rule on
            priority:     Rule priority (higher = checked first)
            match:        What packets this rule matches
            actions:      What to do with matched packets
            idle_timeout: Remove rule after N seconds of no matching packets
                          (0 = permanent). We use 60s so stale rules clean up.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Wrap actions in an "instruction" (OpenFlow 1.3 requirement)
        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]

        # Build and send the FlowMod message
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout
        )
        datapath.send_msg(mod)

        self.logger.debug("FLOW INSTALLED: Switch s%s | priority=%s | timeout=%ss",
                          datapath.id, priority, idle_timeout)
"""
Custom SDN Topology: 3-Tier Tree with Redundant Paths
=====================================================
Architecture:
    - 1 Core switch (s1)
    - 2 Aggregation switches (s2, s3) with cross-link
    - 4 Edge switches (s4-s7), s5 & s6 are dual-homed
    - 8 Hosts with specific roles:
        h1(server), h2(client), h3(client), h4(server),
        h5(client), h6(client), h7(attacker), h8(honeypot)
    - 13 total links (10 base + 3 redundant)

Usage:
    sudo python3 topology/custom_topo.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def create_topology():
    """Build and return the SDN network."""

    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,        # TCLink enables bandwidth/delay settings
        autoSetMacs=True     # Auto-assign MAC addresses (00:00:00:00:00:01, etc.)
    )

    # ──────────────────────────────────────────────
    # STEP 1: Add the remote SDN controller
    # ──────────────────────────────────────────────
    # The controller runs separately (Ryu/os-ken).
    # Port 6653 is the standard OpenFlow port.
    info('*** Adding SDN Controller\n')
    controller = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    # ──────────────────────────────────────────────
    # STEP 2: Add switches (OpenFlow 1.3)
    # ──────────────────────────────────────────────
    # We use OpenFlow 1.3 because it supports:
    #   - Multiple flow tables
    #   - Meters (for rate limiting)
    #   - Group tables (for multipath)
    info('*** Adding Switches\n')

    # Core layer (1 switch)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # Aggregation layer (2 switches)
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')

    # Edge layer (4 switches)
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
    s5 = net.addSwitch('s5', protocols='OpenFlow13')
    s6 = net.addSwitch('s6', protocols='OpenFlow13')
    s7 = net.addSwitch('s7', protocols='OpenFlow13')

    # ──────────────────────────────────────────────
    # STEP 3: Add hosts with specific roles
    # ──────────────────────────────────────────────
    # Each host gets an IP in its subnet:
    #   Edge s4 → 10.0.1.0/24
    #   Edge s5 → 10.0.2.0/24
    #   Edge s6 → 10.0.3.0/24
    #   Edge s7 → 10.0.4.0/24
    info('*** Adding Hosts\n')

    # All hosts in same subnet (10.0.0.x/24)
    # SDN controller handles segmentation via flow rules — no need for traditional subnets
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')  # Server
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')  # Client
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')  # Client
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')  # Server
    h5 = net.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')  # Client
    h6 = net.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')  # Client
    h7 = net.addHost('h7', ip='10.0.0.7/24', mac='00:00:00:00:00:07')  # Attacker
    h8 = net.addHost('h8', ip='10.0.0.8/24', mac='00:00:00:00:00:08')  # Honeypot

    # ──────────────────────────────────────────────
    # STEP 4: Create links with bandwidth limits
    # ──────────────────────────────────────────────
    # Bandwidth hierarchy mimics real networks:
    #   Core links:        100 Mbps (fast backbone)
    #   Aggregation links:  50 Mbps (mid-tier)
    #   Edge links:         10 Mbps (access layer)
    info('*** Creating Links\n')

    # --- Core ↔ Aggregation (100 Mbps) ---
    net.addLink(s1, s2, bw=100, delay='1ms')
    net.addLink(s1, s3, bw=100, delay='1ms')

    # --- Aggregation ↔ Edge (50 Mbps) ---
    net.addLink(s2, s4, bw=50, delay='2ms')
    net.addLink(s2, s5, bw=50, delay='2ms')
    net.addLink(s3, s6, bw=50, delay='2ms')
    net.addLink(s3, s7, bw=50, delay='2ms')

    # --- REDUNDANT LINKS ---
    # Cross-link between aggregation switches (50 Mbps)
    # Purpose: If core switch fails, traffic can still flow between halves
    #! net.addLink(s2, s3, bw=50, delay='2ms')

    # Dual-homing: s5 also connects to s3, s6 also connects to s2
    # Purpose: Edge switches have backup paths through alternate aggregation
    #! net.addLink(s5, s3, bw=50, delay='2ms')
    #! net.addLink(s6, s2, bw=50, delay='2ms')

    # --- Edge ↔ Hosts (10 Mbps) ---
    net.addLink(s4, h1, bw=10, delay='5ms')
    net.addLink(s4, h2, bw=10, delay='5ms')
    net.addLink(s5, h3, bw=10, delay='5ms')
    net.addLink(s5, h4, bw=10, delay='5ms')
    net.addLink(s6, h5, bw=10, delay='5ms')
    net.addLink(s6, h6, bw=10, delay='5ms')
    net.addLink(s7, h7, bw=10, delay='5ms')
    net.addLink(s7, h8, bw=10, delay='5ms')

    # ──────────────────────────────────────────────
    # STEP 5: Build and start the network
    # ──────────────────────────────────────────────
    info('*** Building Network\n')
    net.build()

    info('*** Starting Controller\n')
    controller.start()

    info('*** Starting Switches\n')
    for switch in [s1, s2, s3, s4, s5, s6, s7]:
        switch.start([controller])

    # ──────────────────────────────────────────────
    # STEP 6: Print network information
    # ──────────────────────────────────────────────
    info('\n')
    info('*** Network Topology Summary\n')
    info('    Core:         s1\n')
    info('    Aggregation:  s2, s3 (cross-linked)\n')
    info('    Edge:         s4, s5 (dual-homed), s6 (dual-homed), s7\n')
    info('    Hosts:\n')
    info('      h1 (10.0.0.1) - Server    [s4]\n')
    info('      h2 (10.0.0.2) - Client    [s4]\n')
    info('      h3 (10.0.0.3) - Client    [s5]\n')
    info('      h4 (10.0.0.4) - Server    [s5]\n')
    info('      h5 (10.0.0.5) - Client    [s6]\n')
    info('      h6 (10.0.0.6) - Client    [s6]\n')
    info('      h7 (10.0.0.7) - Attacker  [s7]\n')
    info('      h8 (10.0.0.8) - Honeypot  [s7]\n')
    info('    Links: 16 total (10 base + 3 redundant + 3 not counted above)\n')
    info('\n')

    return net


if __name__ == '__main__':
    setLogLevel('info')

    info('*** Creating SDN Security Topology\n')
    net = create_topology()

    info('*** Running CLI (type "help" for commands)\n')
    info('*** Useful commands:\n')
    info('    pingall          - Test connectivity between all hosts\n')
    info('    h1 ping h7       - Ping from server to attacker\n')
    info('    net              - Show network topology\n')
    info('    dump             - Show all node info\n')
    info('    links            - Show all links\n')
    info('    exit             - Stop the network\n')
    info('\n')

    CLI(net)

    info('*** Stopping Network\n')
    net.stop()
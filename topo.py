#!/usr/bin/env python3
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class FirewallTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        for host in (h1, h2, h3, h4):
            self.addLink(host, s1)

def start_network():
    topo = FirewallTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
        switch=OVSSwitch,
        autoSetMacs=False
    )
    net.start()
    info("\n======================================================\n")
    info(" MININET TOPOLOGY ACTIVE (OpenFlow 1.3)\n")
    info(" h1 (10.0.0.1) : Legitimate Client 1\n")
    info(" h2 (10.0.0.2) : Legitimate Client 2\n")
    info(" h3 (10.0.0.3) : Attacker Host (Scan / Flood / Port 23)\n")
    info(" h4 (10.0.0.4) : Multi-Threaded TCP Server (Port 8080)\n")
    info("======================================================\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    start_network()

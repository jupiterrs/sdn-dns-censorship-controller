from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel


class SampleTopo(Topo):
    def build(self):
        switches = ["s1", "s2"]
        hosts = ["h1", "h2", "h3"]
        links = [
            ("s1", "s2", 1),
            ("s1", "h1", 1),
            ("s1", "h2", 1),
            ("s2", "h3", 1),
        ]

        for s in switches:
            self.addSwitch(s)

        for h in hosts:
            self.addHost(h)

        for u, v, c in links:
            self.addLink(u, v)


def run():
    topo = SampleTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6633),
    )
    net.start()
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()

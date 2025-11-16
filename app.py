# sdn_dns_censorship/app.py
from pox.core import core
import pox.openflow.libopenflow_01 as of
from scapy.all import Ether, IP, DNS, UDP, IPAddr

from .routing import RoutingEngine
from .dns_censor import DnsCensor
from .firewall import FirewallManager
from . import config

log = core.getLogger()


class SdnDnsCensorshipApp(object):
    def __init__(self, net=None):
        # net could be loaded or passed from an external script;
        # for now, you can hardcode or mock it
        self.routing = RoutingEngine(net) if net is not None else None
        self.firewall = FirewallManager(blocked_ports=config.HTTP_PORTS)
        self.dns_censor = DnsCensor(self, self.routing, self.firewall, config)
        self.switches = []

    def _handle_connection_up(self, event):
        self.switches.append(event)
        switchname = f"s{event.dpid}"
        self._add_rule(switchname, event.connection)

    def _handle_packet_in(self, event):
        switchname = f"s{event.dpid}"
        packet = event.parsed
        if not packet.parsed:
            return

        # reconstruct scapy packet
        raw = event.ofp.data
        src_pkt = Ether(raw)

        # filter non DNS
        if not (
            src_pkt.haslayer(IP) and src_pkt.haslayer(UDP) and src_pkt.haslayer(DNS)
        ):
            return

        eth = src_pkt[Ether]
        ip = src_pkt[IP]
        udp = src_pkt[UDP]
        dns = src_pkt[DNS]

        if dns.qr == 0 and udp.dport == config.DNS_PORT:
            self.dns_censor.handle_query(
                switchname, event, event.connection, eth, ip, udp, dns
            )
        elif dns.qr == 1 and udp.sport == config.DNS_PORT:
            self.dns_censor.handle_response(
                switchname, event, event.connection, eth, ip, udp, dns
            )

    def _add_rule(self, switchname, connection):
        forwarding_table = self.routing.fw_table.get(switchname, {})

        for host_name, out_port in forwarding_table.items():
            ip = IPAddr(self.routing.host_ip[host_name])
            msg1 = of.ofp_flow_mod()
            msg1.match.dl_type = 0x0800
            msg1.priority = 10
            msg1.match.nw_dst = ip
            msg1.actions.append(of.ofp_action_output(port=out_port))
            connection.send(msg1)

            msg2 = of.ofp_flow_mod()
            msg2.match.dl_type = 0x0806
            msg2.priority = 10
            msg2.match.nw_dst = ip
            msg2.actions.append(of.ofp_action_output(port=out_port))
            connection.send(msg2)

        msg3 = of.ofp_flow_mod()
        msg3.match.dl_type = 0x0800
        msg3.priority = 20
        msg3.match.nw_proto = 17
        msg3.match.tp_dst = 53

        msg3.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        connection.send(msg3)


def launch():
    app = SdnDnsCensorshipApp()
    core.openflow.addListenerByName("ConnectionUp", app._handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", app._handle_PacketIn)

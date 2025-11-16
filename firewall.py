import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr


class FirewallManager:
    def __init__(self, blocked_ports=None):
        self.blocked_ports = blocked_ports or {80}

    def install_http_block(self, conn, ip_str):
        ipaddr = IPAddr(ip_str)
        for port in self.blocked_ports:
            # server dst
            msg1 = of.ofp_flow_mod()
            msg1.priority = 40
            msg1.match.dl_type = 0x0800
            msg1.match.nw_proto = 6
            msg1.match.nw_dst = ipaddr
            msg1.match.tp_dst = port
            conn.send(msg1)

            # server src
            msg2 = of.ofp_flow_mod()
            msg2.priority = 40
            msg2.match.dl_type = 0x0800
            msg2.match.nw_proto = 6
            msg2.match.nw_src = ipaddr
            msg2.match.tp_src = port
            conn.send(msg2)

    def remove_http_block(self, conn, ip_str):
        ipaddr = IPAddr(ip_str)
        for port in self.blocked_ports:
            msg1 = of.ofp_flow_mod()
            msg1.command = of.OFPFC_DELETE
            msg1.match.dl_type = 0x0800
            msg1.match.nw_proto = 6
            msg1.match.nw_dst = ipaddr
            msg1.match.tp_dst = port
            conn.send(msg1)

            msg2 = of.ofp_flow_mod()
            msg2.command = of.OFPFC_DELETE
            msg2.match.dl_type = 0x0800
            msg2.match.nw_proto = 6
            msg2.match.nw_src = ipaddr
            msg2.match.tp_src = port
            conn.send(msg2)

from collections import defaultdict
from scapy.all import Ether, IP, UDP, DNS, DNSRR
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr


class DNSCensor:
    """
    Executes all DNS-related logic:
    1) Parses DNS queries/responses using Scapy
    2) Deciding when and how to censor a domain when they can either change dynamically or stay the same
    3) Tracking pending queries to inspect responses
    4) Extracting IP addresses from DNS responses
    5) Installing/removing HTTP blocking rules via firewall
    6) Sending empty DNS responses back to clients
    """

    def __init__(self, controller, routing, firewall, config=None):
        self.controller = controller  # to reach other switches
        self.routing = routing  # for fw_table, host_ip_map
        self.firewall = firewall  # for blocking/unblocking HTTP
        self.config = config

        # Map keeps track of queries, waits for DNS responses:
        # key: (client_ip, client_port, dns_ip, dns_port, dns_id)
        # value: { "in_port" : int, "domain" : str}
        #
        # We use this to match DNS responses with the original requests
        # and to know which domain that response belongs to.
        self.pending_block = {}

        # Domain-IP mappings for when we need to update them during dynamic updates
        self.domain_ip_map = {}
        self.ip_domain_map = defaultdict(set)

        # Stores all currently blocked IP addresses
        self.blocked_ips = set()

    def handle_query(self, switchname, event, connection, eth, ip, udp, dns):
        print("Got DNS wowowowowow")
        query = dns.qd.qname.decode().rstrip(".")

        print("DNS query with ", query)
        client_ip = str(ip.src)
        dns_ip = str(ip.dst)
        client_port = udp.sport
        dns_port = udp.dport
        dns_id = dns.id

        if query == "gooogle-block.com":
            print("Censoring with", query)
            new_dns_response = DNS(
                id=dns.id,
                qr=1,
                opcode=dns.opcode,
                aa=0,
                tc=0,
                rd=dns.rd,
                ra=0,
                z=0,
                rcode=0,
                qd=dns.qd,
                qdcount=1,
                an=None,
                ancount=0,
                nscount=0,
                arcount=0,
            )
            new_eth = Ether(src=eth.dst, dst=eth.src)
            new_ip = IP(src=ip.dst, dst=ip.src)
            new_udp = UDP(sport=udp.dport, dport=udp.sport)
            new_packet = bytes(new_eth / new_ip / new_udp / new_dns_response)

            msg = of.ofp_packet_out()
            msg.data = new_packet
            msg.in_port = of.OFPP_NONE
            msg.actions.append(of.ofp_action_output(port=event.port))
            connection.send(msg)
            return

        block_domain = getattr(self.config, "BLOCK_DOMAIN_SINGLE", "task6-block.com")
        block_prefix = getattr(self.config, "BLOCK_PREFIX", "task7-block-")

        should_track = False

        if query == block_domain:
            print("Dynamic blocking query (exact) for", query)
            should_track = True

        elif query.startswith(block_prefix) and query.endswith(".com"):
            print("Dynamic blocking query (prefix-style) for", query)
            should_track = True

        if should_track:
            # Install a rule that sends the corresponding response back to controller
            track = of.ofp_flow_mod()
            track.priority = 30
            track.match.dl_type = 0x0800
            track.match.nw_proto = 17
            track.match.nw_src = IPAddr(dns_ip)  # DNS server -> client
            track.match.nw_dst = IPAddr(client_ip)
            track.match.tp_src = 53
            track.match.tp_dst = client_port
            track.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            connection.send(track)

            key = (client_ip, client_port, dns_ip, dns_port, dns_id)
            self.pending_blocks[key] = {
                "in_port": event.port,
                "domain": query,
            }

        # Forward the original DNS query using routing info
        host_name = self.routing.host_ip_map.get(dns_ip)
        if host_name is None:
            # Unknown DNS server
            return

        out_port = self.routing.fw_table[switchname][host_name]

        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=out_port))
        connection.send(msg)

        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=out_port))
        connection.send(msg)
        return


def handle_response(self, switchname, event, connection, eth, ip, udp, dns):
    print("Handling DNS response wowowowowow")
    query = dns.qd.qname.decode().rstrip(".")

    print("DNS response", query)
    client_ip = str(ip.dst)
    dns_ip = str(ip.src)
    client_port = udp.dport
    dns_port = udp.sport
    dns_id = dns.id

    key = (client_ip, client_port, dns_ip, dns_port, dns_id)
    entry = self.pending_blocks.pop(key, None)

    # If this response wasn't for a query we are tracking, ignore or route normally
    if entry is None:
        return

    original_domain = entry["domain"]
    in_port = entry["in_port"]

    block_domain = getattr(self.config, "BLOCK_DOMAIN_SINGLE", "task6-block.com")
    block_prefix = getattr(self.config, "BLOCK_PREFIX", "task7-block-")

    # 1) Extract the IP from the DNS answer
    blocked_ip = self._extract_a_record_ip(dns)

    if original_domain == block_domain:
        if blocked_ip is not None:
            print("Blocking HTTP for", blocked_ip)
            self.blocked_ips.add(blocked_ip)

            self.firewall.install_http_block(connection, blocked_ip)

        # Send empty response to client
        print("Censoring domain", original_domain)
        new_dns_response = DNS(
            id=dns.id,
            qr=1,
            opcode=dns.opcode,
            aa=0,
            tc=0,
            rd=dns.rd,
            ra=0,
            z=0,
            rcode=0,
            qd=dns.qd,
            qdcount=1,
            an=None,
            ancount=0,
            nscount=0,
            arcount=0,
        )
        new_eth = Ether(src=eth.src, dst=eth.dst)
        new_ip = IP(src=ip.src, dst=ip.dst)
        new_udp = UDP(sport=udp.sport, dport=udp.dport)
        new_packet = bytes(new_eth / new_ip / new_udp / new_dns_response)

        msg = of.ofp_packet_out()
        msg.data = new_packet
        msg.in_port = of.OFPP_NONE
        msg.actions.append(of.ofp_action_output(port=in_port))
        connection.send(msg)
        return

    # 2) Track multiple domains per IP, dynamic changes
    if original_domain.startswith(block_prefix) and original_domain.endswith(".com"):
        print("Handling dynamic block for", original_domain)

        old_ip = self.domain_ip_map.get(original_domain)
        ips_to_block = set()
        ips_to_unblock = set()

        # If the domain's IP changed, we might need to unmap the old IP
        if old_ip is not None and old_ip != blocked_ip:
            self.ip_domain_map[old_ip].discard(original_domain)
            if not self.ip_domain_map[old_ip]:
                del self.ip_domain_map[old_ip]
                if old_ip in self.blocked_ips:
                    self.blocked_ips.remove(old_ip)
                    ips_to_unblock.add(old_ip)

        # Update new mapping if present
        if blocked_ip is not None:
            self.domain_ip_map[original_domain] = blocked_ip
            self.ip_domain_map[blocked_ip].add(original_domain)

            if blocked_ip not in self.blocked_ips:
                self.blocked_ips.add(blocked_ip)
                ips_to_block.add(blocked_ip)
        else:
            self.domain_ip_map[original_domain] = None

        # Apply block/unblock on all switches the controller knows
        for sw in self.controller.switches:
            conn_sw = sw.connection
            for ip_str in ips_to_block:
                print("Blocking IP (dynamic)", ip_str)
                self.firewall.install_http_block(conn_sw, ip_str)

            for ip_str in ips_to_unblock:
                print("Unblocking IP (dynamic)", ip_str)
                self.firewall.remove_http_block(conn_sw, ip_str)

        # Send empty response to client
        print("Censoring domain", original_domain)
        new_dns_response = DNS(
            id=dns.id,
            qr=1,
            opcode=dns.opcode,
            aa=0,
            tc=0,
            rd=dns.rd,
            ra=0,
            z=0,
            rcode=0,
            qd=dns.qd,
            qdcount=1,
            an=None,
            ancount=0,
            nscount=0,
            arcount=0,
        )
        new_eth = Ether(src=eth.src, dst=eth.dst)
        new_ip = IP(src=ip.src, dst=ip.dst)
        new_udp = UDP(sport=udp.sport, dport=udp.dport)
        new_packet = bytes(new_eth / new_ip / new_udp / new_dns_response)

        msg = of.ofp_packet_out()
        msg.data = new_packet
        msg.in_port = of.OFPP_NONE
        msg.actions.append(of.ofp_action_output(port=in_port))
        connection.send(msg)
        return

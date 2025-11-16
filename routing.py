from collections import defaultdict
import heapq


class RoutingEngine:
    def __init__(self, net):
        self.net = net
        self.graph = defaultdict(list)
        self.port_map = {}
        self.host_ip = {}
        self.host_ip_map = {}
        self.fw_table = self._compute_forwarding_table()

    def _build_from_net(self, net):
        for host_name, host_data in net["hosts"].items():
            self.host_ip[host_name] = host_data["IP"]
            self.host_ip_map[host_data["IP"]] = host_name

            for n1, p1, n2, p2, cost in host_data["links"]:
                self.graph[n1].append((n2, cost))
                self.graph[n2].append((n1, cost))
                self.port_map[(n1, n2)] = p1
                self.port_map[(n2, n1)] = p2

        for sw_name, sw_data in net["switches"].items():
            for n1, p1, n2, p2, cost in sw_data["links"]:
                self.graph[n1].append((n2, cost))
                self.graph[n2].append((n1, cost))
                self.port_map[(n1, n2)] = p1
                self.port_map[(n2, n1)] = p2

    def _dijkstra(self, s):
        dist = {node: float("inf") for node in self.graph.keys()}
        next_node = {node: None for node in self.graph.keys()}

        dist[s] = 0
        pq = [(0, s)]

        while pq:
            d, u = heapq.heappop(pq)

            if d != dist[u]:
                continue

            for v, cost in self.graph.get(u, []):
                if d + cost < dist[v]:
                    dist[v] = d + cost

                    if u == s:
                        next_node[v] = v

                    else:
                        next_node[v] = next_node[u]

                    heapq.heappush(pq, (dist[v], v))

        return dist, next_node

    def _compute_forwarding_table(self):
        """
        Build fw_table that has the following
        """
        fw_table = {}

        for sw_name in self.net["switches"].keys():
            dist, next_node = self._dijkstra(sw_name)
            sw_fw_table = {}

            for host_name in self.net["hosts"].keys():
                if next_node.get(host_name) is None:
                    continue

                n_host = next_node[host_name]
                port = self.port_map[(sw_name, n_host)]
                sw_fw_table[host_name] = port

            fw_table[sw_name] = sw_fw_table

        return fw_table

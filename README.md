# SDN DNS Censorship Controller

This project implements DNS-based censorship and dynamic HTTP blocking using an SDN controller built with POX, Mininet, Scapy, and OpenFlow. 
It demonstrates how a programmable SDN controller can intercept DNS queries, 
analyze DNS responses, and install OpenFlow rules to block HTTP traffic to censored domains or IP addresses. Overall, the project tries to model/realize a simple real-world scenario to understand how hosts and switches communicate with the controller to follow software-defined networking (SDN), as switches would have a lot more complexity in implementing if they each had to a) know the shortest possible path to send a packet in real-time, 
b) always precompute short paths. What the controller does is implements those features to make sure that switches only need to know how to forward packets to specific ports.
We use Dijkstra's algorithm inside the controller to construct forwarding table for each switch to operate on.

---

## Features

- Shortest-path routing using Dijkstra’s algorithm  
- DNS query interception  
- DNS response inspection using Scapy  
- Synthetic “empty answer” DNS responses for censored domains  
- Dynamic HTTP blocking (port 80) based on DNS A-record results  
- Automatic update when domain–IP mappings change  

---

## Requirements

- Linux (tested on Arch Linux)
- Python 3
- POX controller
- Mininet (manual install)
- Open vSwitch
- Scapy

Install Scapy:

```bash
pip install scapy
```

---

## Running the Controller

Open two terminals.

### Terminal 1 — Start POX

```bash
cd ~/pox
./pox.py log.level --DEBUG openflow.of_01 --port=6633 sdn_dns_app
```

You should see switch connection logs once Mininet starts.

---

## Running Mininet

### Terminal 2

```bash
cd topology
sudo python3 sample_topology.py
```

Inside the Mininet CLI:

```bash
mininet> pingall
```

Expected:

```
0% dropped
```

---

## Testing DNS Censorship

```
mininet> h1 dig @10.0.0.3 gooogle.com
mininet> h1 dig @10.0.0.3 gooogle.com
mininet> h1 curl http://<returned-ip>/
mininet> h1 dig @10.0.0.3 gooogle.com
```

The controller:

- Tracks the domain’s IP  
- Blocks any HTTP traffic to that IP  
- Removes the block when the DNS mapping changes  

---

## Notes

- POX emits warnings under Python ≥ 3.10; these are expected.
- DNS parse errors shown by POX's internal parser are expected and harmless because Scapy handles real parsing.
- All DNS censorship logic uses Scapy layers.

---

## License

MIT License

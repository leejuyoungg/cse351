# Simple Virtual IP Router

CSE351 Computer Networks — Programming Assignment 4
Ulsan National Institute of Science and Technology (UNIST)

## Overview
Implementation of a virtual IP router in a Mininet-based network testbed.
The router handles Ethernet, IPv4, ARP, ICMP, and IP firewall functionality,
forwarding packets correctly across a simulated network topology.

## Implemented Features
- **Packet Forwarding** — Longest prefix match (LPM) routing with TTL decrement and checksum recomputation
- **ARP** — ARP request/reply handling, ARP cache with 15-second timeout, retransmission up to 5 times
- **ICMP** — Echo reply (type 0), Destination unreachable (type 3), Time exceeded (type 11), Port unreachable
- **IP Firewall** — Blacklist-based packet filtering for both inbound and outbound traffic

## Key Functions Implemented
- `sr_handlepacket()` — Core packet handler for Ethernet/IP/ICMP/ARP
- `sr_arpcache_handle_arpreq()` — ARP request queue management and retransmission
- `ip_black_list()` — IP-based firewall filtering

## Network Topology
```
Server1 (192.168.2.2)    Server2 (172.64.3.10)
         \                    /
      eth1 (192.168.2.1)  eth2 (172.64.3.1)
                Router
      eth3 (10.0.1.1)    eth4 (10.0.2.1)
         /                    \
Client1 (10.0.1.100)    Client2 (10.0.2.100)
```

## Language
C

## Build & Run
```bash
make
./sr
```

## Testing
```bash
# In Mininet terminal
mininet> client1 ping -c 3 192.168.2.2
mininet> client1 traceroute 192.168.2.2
mininet> client1 wget 192.168.2.2
```

# Packet Resubmit Example

This repo shows how to handle a "miss packet" by sending it to RSS processing, creating a new flow entry for the packet, and resubmitting the packet to the new flow rule using a "secondary VF" netdev.

Both DPDK and DOCA Flow examples are included.

The following flow chart illustrates the packet processing logic.

```
+------+                                +--------+
| user | --> [VF0] --> [pf0vf0repr] --> |        | port_meta=0
| app  | (1)                            | Root   |-------------> [pf0vf0repr] -> [VF0]
+------+                                | Pipe   | (from uplink)
          +----------> [pf0vf1repr] --> |        |
          |                             +--------+
          |                                 |
          |                 port_meta=[1,2] |     
          |                                 v
          |                             +--------+ (5)
          |                             | Egress | --------------> [pf0repr] -> [uplink]
          |                             | Pipe   | [match: pkt mod]
        [VF1]                           +--------+
         ^                           (2) |
     (4) |                               |
+---------+                              |
|         | <-------- [miss: RSS] -------+
|         |
| daemon  | (3) [new pipe entry]
| process |
|         |
+---------+

1) The user application transmits a packet on its VF0 netdev
   The Root Pipe uses port_meta to detect the origin of the
   packet, and forwards it to the Egress Pipe.
2) The Egress Pipe has no rules to handle this packet, so it
   misses to the RSS Pipe.
3) The RSS processing loop creates a new flow to match the given
   packet.
4) The RSS processing loop then transmits the same packet using
   its own VF1.
5) The new rule in the Egress Pipe matches the resubmitted packet and
   performs a packet mod action before sending along to the
   uplink port.
```

Usage for doca-packet-resubmit:

```
Usage: resubmit-demo [DOCA Flags] [Program Flags]

DOCA Flags:
  -h, --help                        Print a help synopsis
  -v, --version                     Print program version information
  -l, --log-level                   Set the (numeric) log level for the program <10=DISABLE, 20=CRITICAL, 30=ERROR, 40=WARNING, 50=INFO, 60=DEBUG, 70=TRACE>
  --sdk-log-level                   Set the SDK (numeric) log level for the program <10=DISABLE, 20=CRITICAL, 30=ERROR, 40=WARNING, 50=INFO, 60=DEBUG, 70=TRACE>
  -j, --json <path>                 Parse all command flags from an input json file

Program Flags:
  -pf, --phys-func                  PCI BDF of the Physical Function
  -vf, --virt-func                  PCI BDF of the Secondary Virtual Function
  ```
Example:
```
> doca-packet-resubmit -pf CA:00.0 -vf CA:00.2

EAL: Detected CPU lcores: 64
EAL: Detected NUMA nodes: 2
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'PA'
EAL: VFIO support initialized
TELEMETRY: No legacy callbacks, legacy socket not created
EAL: Probe PCI driver: mlx5_pci (15b3:1021) device: 0000:ca:00.0 (socket 1)
EAL: Probe PCI driver: mlx5_pci (15b3:101e) device: 0000:ca:00.2 (socket 1)
[23:04:29:051337][2327813][DOCA][INF][doca_packet_resubmit_main.c:753][main] Detected 4 ports
[23:04:29:152473][2327813][DOCA][WRN][engine_model.c:72][adapt_queue_depth] adapting queue depth to 128.
mlx5_net: [mlx5dr_rule_skip]: Fail to map port ID 65535, ignoring
[23:04:30:392966][2327813][DOCA][INF][doca_packet_resubmit_main.c:252][log_port_start] 
Started doca_flow_port:: port 0: 94:6d:ae:47:a2:d2

[23:04:31:126392][2327813][DOCA][INF][doca_packet_resubmit_main.c:252][log_port_start] 
Started doca_flow_port:: port 1: 8e:74:cd:8f:de:d1

[23:04:31:692724][2327813][DOCA][INF][doca_packet_resubmit_main.c:252][log_port_start] 
Started doca_flow_port:: port 2: ee:b0:01:bd:ef:bf

[23:04:32:801993][2327813][DOCA][WRN][dpdk_port_legacy.c:1238][port_is_switch_manager] failed getting proxy port for port id 3 - rc=-22
[23:04:32:854947][2327813][DOCA][INF][doca_packet_resubmit_main.c:252][log_port_start] 
Started doca_flow_port:: port 3: 76:85:12:3f:b0:a7

[23:04:32:948312][2327813][DOCA][INF][doca_packet_resubmit_main.c:761][main] Starting l-cores...
[23:04:32:948473][2327813][DOCA][INF][doca_packet_resubmit_main.c:765][main] Waiting for signal...
[23:04:32:948475][2327817][DOCA][INF][doca_packet_resubmit_main.c:252][log_port_start] 
l-core polling on port: port 2: ee:b0:01:bd:ef:bf

Static Entry Counters: root_ingress_entry: 0, root_egress_vf0: 0, root_egress_vf1: 0, ingress_entry: 0, to_uplink: 0, rss_pipe: 0, ; egress entry counters: ; Pipe Miss counters: 0, 
Static Entry Counters: root_ingress_entry: 0, root_egress_vf0: 0, root_egress_vf1: 0, ingress_entry: 0, to_uplink: 0, rss_pipe: 0, ; egress entry counters: ; Pipe Miss counters: 0, 
Static Entry Counters: root_ingress_entry: 0, root_egress_vf0: 76, root_egress_vf1: 0, ingress_entry: 0, to_uplink: 52, rss_pipe: 0, ; egress entry counters: 10.20.30.1-flow: 2, 10.20.30.2-flow: 2, 10.20.30.5-flow: 2, 10.20.30.6-flow: 2, 10.20.30.8-flow: 2, 10.20.30.11-flow: 2, 10.20.30.12-flow: 2, 10.20.30.15-flow: 2, 10.20.30.16-flow: 2, 10.20.30.19-flow: 2, 10.20.30.20-flow: 2, 10.20.30.23-flow: 2, 10.20.30.25-flow: 2, 10.20.30.26-flow: 2, 10.20.30.29-flow: 2, 10.20.30.30-flow: 2, 10.20.30.32-flow: 2, 10.20.30.35-flow: 2, 10.20.30.36-flow: 2, 10.20.30.39-flow: 2, 10.20.30.41-flow: 2, 10.20.30.42-flow: 2, 10.20.30.45-flow: 2, 10.20.30.46-flow: 2, 10.20.30.49-flow: 2, 10.20.30.50-flow: 2, ; Pipe Miss counters: 24, 
Signal 2 received, preparing to exit...
```

# Packet Resubmit Example

This repo shows how to handle a "miss packet" by sending it to RSS processing, creating a new flow entry for the packet, and resubmitting the packet to the new flow rule.

Both DPDK and DOCA Flow examples are included.

The following flow chart illustrates the packet processing logic.

```
Application architecture:

                                        +--------+
             [uplink] ----------------> |        |
+------+                                |        |
| user | --> [VF0] --> [pf0vf0repr] --> | Root   | port_meta=0   +----------+
| app  | (1)                            | Pipe   |-------------> | N2H Pipe | ---> [pf0vf0repr] -> [VF0]
+------+                                |        | (from uplink) +----------+
          +---------------------------> |        |
          |                             +--------+
          |                                 |
          |                     port_meta=1 |     
          |                                 v
          |                             +--------+ (5)
          |                             | H2N    | --------------> [pf0repr] -> [uplink]
          |                             | Pipe   | [match: pkt mod]
        [pf0]                           +--------+
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
   the PF.
5) The new rule in the Egress Pipe matches the resubmitted packet and
   performs a packet mod action before sending along to the
   uplink port.
```

Usage for doca-packet-resubmit:

```
Usage: resubmit-demo [DPDK Flags] -- [DOCA Flags]

DPDK RTE EAL Flags: per https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html
  -a                                Accept-list of PCI addresses
  (etc.)

DOCA Flags:
  -h, --help                        Print a help synopsis
  -v, --version                     Print program version information
  -l, --log-level                   Set the (numeric) log level for the program <10=DISABLE, 20=CRITICAL, 30=ERROR, 40=WARNING, 50=INFO, 60=DEBUG, 70=TRACE>
  --sdk-log-level                   Set the SDK (numeric) log level for the program <10=DISABLE, 20=CRITICAL, 30=ERROR, 40=WARNING, 50=INFO, 60=DEBUG, 70=TRACE>
  -j, --json <path>                 Parse all command flags from an input json file
  ```
Example:
```
> build/doca-packet-resubmit -aCA:00.0 -c0xa

EAL: Detected CPU lcores: 64
EAL: Detected NUMA nodes: 2
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'PA'
EAL: VFIO support initialized
TELEMETRY: No legacy callbacks, legacy socket not created
EAL: Probe PCI driver: mlx5_pci (15b3:1021) device: 0000:ca:00.0 (socket 1)
mlx5_net: port 0 ingress traffic is restricted to defined flow rules (isolated mode) since representor matching is disabled
mlx5_net: port 1 ingress traffic is restricted to defined flow rules (isolated mode) since representor matching is disabled
[23:05:59:502879][2078570][DOCA][INF][doca_packet_resubmit_main.c:704][main] Detected 2 ports
mlx5_net: port 0 cannot enable promiscuous mode in flow isolation mode
[23:05:59:525157][2078570][DOCA][INF][dpdk_utils.c:425][port_init] Ingress traffic on port 0 is in isolated mode
mlx5_net: port 0 cannot enable promiscuous mode in flow isolation mode
mlx5_net: port 1 cannot enable promiscuous mode in flow isolation mode
[23:05:59:545083][2078570][DOCA][INF][dpdk_utils.c:425][port_init] Ingress traffic on port 1 is in isolated mode
mlx5_net: port 1 cannot enable promiscuous mode in flow isolation mode
[23:05:59:560403][2078570][DOCA][WRN][engine_model.c:72][adapt_queue_depth] adapting queue depth to 128.
mlx5_net: port 0 cannot enable promiscuous mode in flow isolation mode
[23:06:00:529138][2078570][DOCA][INF][doca_packet_resubmit_main.c:295][log_port_start]
Started doca_flow_port:: port 0: 94:6d:ae:47:a2:d2

mlx5_net: port 1 cannot enable promiscuous mode in flow isolation mode
[23:06:01:037400][2078570][DOCA][INF][doca_packet_resubmit_main.c:295][log_port_start]
Started doca_flow_port:: port 1: 8e:69:dd:c2:fd:30

[23:06:01:088001][2078570][DOCA][INF][doca_packet_resubmit_main.c:712][main] Starting l-cores...
[23:06:01:088157][2078573][DOCA][INF][doca_packet_resubmit_main.c:295][log_port_start]
l-core polling on port: port 0: 94:6d:ae:47:a2:d2

[23:06:01:088163][2078570][DOCA][INF][doca_packet_resubmit_main.c:716][main] Waiting for signal...
Static Entry Counters: root_host_to_net_vf0: 0, rss_pipe: 1, ; egress entry counters: ; Pipe Miss counters: 1,
Static Entry Counters: root_host_to_net_vf0: 0, rss_pipe: 1, ; egress entry counters: ; Pipe Miss counters: 1,
[23:06:09:154524][2078573][DOCA][INF][doca_packet_resubmit_main.c:276][create_flow] Created flow for IP 192.168.99.101->20.1.1.100
[23:06:09:155511][2078573][DOCA][INF][doca_packet_resubmit_main.c:276][create_flow] Created flow for IP 192.168.99.102->20.1.1.100
[23:06:09:156546][2078573][DOCA][INF][doca_packet_resubmit_main.c:276][create_flow] Created flow for IP 192.168.99.103->20.1.1.100
[23:06:09:157605][2078573][DOCA][INF][doca_packet_resubmit_main.c:276][create_flow] Created flow for IP 192.168.99.104->20.1.1.100
[23:06:09:158627][2078573][DOCA][INF][doca_packet_resubmit_main.c:276][create_flow] Created flow for IP 192.168.99.105->20.1.1.100
[23:06:09:159636][2078573][DOCA][INF][doca_packet_resubmit_main.c:276][create_flow] Created flow for IP 192.168.99.106->20.1.1.100
[23:06:09:160648][2078573][DOCA][INF][doca_packet_resubmit_main.c:276][create_flow] Created flow for IP 192.168.99.107->20.1.1.100
[23:06:09:161691][2078573][DOCA][INF][doca_packet_resubmit_main.c:276][create_flow] Created flow for IP 192.168.99.108->20.1.1.100
[23:06:09:162530][2078573][DOCA][INF][doca_packet_resubmit_main.c:276][create_flow] Created flow for IP 192.168.99.109->20.1.1.100
[23:06:09:162952][2078573][DOCA][INF][doca_packet_resubmit_main.c:276][create_flow] Created flow for IP 192.168.99.110->20.1.1.100
Static Entry Counters: root_host_to_net_vf0: 10, rss_pipe: 11, ; egress entry counters: 192.168.99.101-flow: 1, 192.168.99.102-flow: 1, 192.168.99.103-flow: 1, 192.168.99.104-flow: 1, 192.168.99.105-flow: 1, 192.168.99.106-flow: 1, 192.168.99.107-flow: 1, 192.168.99.108-flow: 1, 192.168.99.109-flow: 1, 192.168.99.110-flow: 1, ; Pipe Miss counters: 11,
Static Entry Counters: root_host_to_net_vf0: 10, rss_pipe: 11, ; egress entry counters: 192.168.99.101-flow: 1, 192.168.99.102-flow: 1, 192.168.99.103-flow: 1, 192.168.99.104-flow: 1, 192.168.99.105-flow: 1, 192.168.99.106-flow: 1, 192.168.99.107-flow: 1, 192.168.99.108-flow: 1, 192.168.99.109-flow: 1, 192.168.99.110-flow: 1, ; Pipe Miss counters: 11,
Static Entry Counters: root_host_to_net_vf0: 20, rss_pipe: 11, ; egress entry counters: 192.168.99.101-flow: 2, 192.168.99.102-flow: 2, 192.168.99.103-flow: 2, 192.168.99.104-flow: 2, 192.168.99.105-flow: 2, 192.168.99.106-flow: 2, 192.168.99.107-flow: 2, 192.168.99.108-flow: 2, 192.168.99.109-flow: 2, 192.168.99.110-flow: 2, ; Pipe Miss counters: 11,
Static Entry Counters: root_host_to_net_vf0: 20, rss_pipe: 11, ; egress entry counters: 192.168.99.101-flow: 2, 192.168.99.102-flow: 2, 192.168.99.103-flow: 2, 192.168.99.104-flow: 2, 192.168.99.105-flow: 2, 192.168.99.106-flow: 2, 192.168.99.107-flow: 2, 192.168.99.108-flow: 2, 192.168.99.109-flow: 2, 192.168.99.110-flow: 2, ; Pipe Miss counters: 11,
Static Entry Counters: root_host_to_net_vf0: 20, rss_pipe: 11, ; egress entry counters: 192.168.99.101-flow: 2, 192.168.99.102-flow: 2, 192.168.99.103-flow: 2, 192.168.99.104-flow: 2, 192.168.99.105-flow: 2, 192.168.99.106-flow: 2, 192.168.99.107-flow: 2, 192.168.99.108-flow: 2, 192.168.99.109-flow: 2, 192.168.99.110-flow: 2, ; Pipe Miss counters: 11,
Static Entry Counters: root_host_to_net_vf0: 40, rss_pipe: 11, ; egress entry counters: 192.168.99.101-flow: 4, 192.168.99.102-flow: 4, 192.168.99.103-flow: 4, 192.168.99.104-flow: 4, 192.168.99.105-flow: 4, 192.168.99.106-flow: 4, 192.168.99.107-flow: 4, 192.168.99.108-flow: 4, 192.168.99.109-flow: 4, 192.168.99.110-flow: 4, ; Pipe Miss counters: 11,
Static Entry Counters: root_host_to_net_vf0: 40, rss_pipe: 11, ; egress entry counters: 192.168.99.101-flow: 4, 192.168.99.102-flow: 4, 192.168.99.103-flow: 4, 192.168.99.104-flow: 4, 192.168.99.105-flow: 4, 192.168.99.106-flow: 4, 192.168.99.107-flow: 4, 192.168.99.108-flow: 4, 192.168.99.109-flow: 4, 192.168.99.110-flow: 4, ; Pipe Miss counters: 11,
Signal 2 received, preparing to exit...
[23:06:29:903441][2078570][DOCA][INF][doca_packet_resubmit_main.c:720][main] Shutting down...
```

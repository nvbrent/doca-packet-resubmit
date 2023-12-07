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
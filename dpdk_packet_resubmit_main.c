/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

// Application architecture:
//
// +------+                                +----------+ (5)
// | user | --> [VF0] --> [pf0vf0repr] --> | egress   | -----------------> [p0 uplink]
// | app  | (1)                            | xfer grp | [match: pkt mod]
// +------+                                +----------+
//                                      (2) |    ^
// +---------+ <-------- [miss: RSS] -------+    |
// |         |                                   |
// | daemon  | (3) [new egress flow rule]        |
// | process |                                   |
// |         | ---> [VF1] --> [pf0vf1repr] ------+
// +---------+  (4)
//
// 1) The user application transmits a packet on its VF0 netdev
// 2) The FDB has no rules to handle this ingress packet, so it
//    misses to the VF0 NIC Rx.
//    The NIC Rx domain has a single flow, which sends the packet
//    to RSS.
// 3) The RSS processing loop creates a new flow to match the given
//    packet.
// 4) The RSS processing loop then transmits the same packet using
//    its own VF1.
// 5) The new rule in the FDB matches the resubmitted packet and
//    performs a packet mod action before sending along to the
//    uplink port.
// 

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_malloc.h>

typedef uint8_t ipv6_addr_t[16];

#define MIN_PORTS 4

#define MAX_EGRESS_RULES 16

struct resubmit_app_config
{
    uint16_t nb_ports;

    uint16_t uplink_port_id; // always 0
    uint16_t user_vf_repr_id;
    uint16_t daemon_vf_repr_id;
    uint16_t daemon_vf_id;

    rte_be32_t rewrite_src_ip;

    uint16_t ipv4_egress_group_id;

    struct rte_flow *vf_to_rss;

    int num_egress_rules;
    struct rte_flow *vf_egress[MAX_EGRESS_RULES];
    rte_be32_t egress_src_ip[MAX_EGRESS_RULES];
};

volatile bool force_quit = false;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static void install_signal_handler(void)
{
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
}

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

int port_init(uint16_t port_id, uint16_t nb_queues, struct rte_mempool *mbuf_pool)
{
	int ret = 0;
	uint8_t symmetric_hash_key[] = {
	    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	};
	int symmetric_hash_key_length = sizeof(symmetric_hash_key);
	const uint16_t nb_hairpin_queues = 0;
	const uint16_t rx_rings = nb_queues;
	const uint16_t tx_rings = nb_queues;
	bool isolated = true;
	uint16_t q;
    //uint16_t queue_index;
	//uint16_t rss_queue_list[nb_hairpin_queues];
	struct rte_ether_addr addr;
	struct rte_eth_dev_info dev_info;
	struct rte_flow_error error;
	const struct rte_eth_conf port_conf_default = {
	    .lpbk_mode = false,
	    .rx_adv_conf = {
		    .rss_conf = {
			    .rss_key_len = symmetric_hash_key_length,
			    .rss_key = symmetric_hash_key,
			    .rss_hf = (RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP),
			},
		},
	};
	struct rte_eth_conf port_conf = port_conf_default;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret < 0) {
		printf("Failed getting device (port %u) info, error=%s\n", port_id, strerror(-ret));
		return -1;
	}
	port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;

	/* Configure the Ethernet device */
	ret = rte_eth_dev_configure(port_id, rx_rings + nb_hairpin_queues, tx_rings + nb_hairpin_queues, &port_conf);
	if (ret < 0) {
		printf("Failed to configure the ethernet device - (%d)", ret);
		return -1;
	}
	if (port_conf_default.rx_adv_conf.rss_conf.rss_hf != port_conf.rx_adv_conf.rss_conf.rss_hf) {
		printf("Port %u modified RSS hash function based on hardware support, requested:%#" PRIx64
			     " configured:%#" PRIx64 "\n",
			     port_id, port_conf_default.rx_adv_conf.rss_conf.rss_hf,
			     port_conf.rx_adv_conf.rss_conf.rss_hf);
	}

	/* Enable RX in promiscuous mode for the Ethernet device */
	ret = rte_eth_promiscuous_enable(port_id);
	if (ret < 0) {
		printf("Failed to Enable RX in promiscuous mode - (%d)\n", ret);
		return -1;
	}

	/* Allocate and set up RX queues according to number of cores per Ethernet port */
	for (q = 0; q < rx_rings; q++) {
		ret = rte_eth_rx_queue_setup(port_id, q, RX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
		if (ret < 0) {
			printf("Failed to set up RX queues - (%d)\n", ret);
			return -1;
		}
	}

	/* Allocate and set up TX queues according to number of cores per Ethernet port */
	for (q = 0; q < tx_rings; q++) {
		ret = rte_eth_tx_queue_setup(port_id, q, TX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL);
		if (ret < 0) {
			printf("Failed to set up TX queues - (%d)\n", ret);
			return -1;
		}
	}

	/* Set isolated mode (true or false) before port start */
	ret = rte_flow_isolate(port_id, isolated, &error);
	if (ret < 0) {
		printf("Port %u could not be set isolated mode to %s (%s)\n",
			     port_id, isolated ? "true" : "false", error.message);
		return -1;
	}
	if (isolated)
		printf("Ingress traffic on port %u is in isolated mode\n",
			      port_id);

	/* Start the Ethernet port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		printf("Cannot start port %" PRIu8 ", ret=%d\n", port_id, ret);
		return -1;
	}

	/* Display the port MAC address */
	rte_eth_macaddr_get(port_id, &addr);
	printf("Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		     (unsigned int)port_id, addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], addr.addr_bytes[3],
		     addr.addr_bytes[4], addr.addr_bytes[5]);

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	if (rte_eth_dev_socket_id(port_id) > 0 && rte_eth_dev_socket_id(port_id) != (int)rte_socket_id()) {
		printf("Port %u is on remote NUMA node to polling thread\n", port_id);
		printf("\tPerformance will not be optimal\n");
	}

	return 0;
}

int create_static_flows(struct resubmit_app_config *config)
{
    struct rte_flow_error error = {};

    struct rte_flow_attr attr = {
        .ingress = 1,
    };
    struct rte_flow_item items[] = {
        { RTE_FLOW_ITEM_TYPE_ETH },
        { RTE_FLOW_ITEM_TYPE_END },
    };
    struct rte_flow_action_count count = { };
    uint16_t rss_queues[] = { 0 };
    struct rte_flow_action_rss rss_action = {
        .types = RTE_ETH_RSS_IP,
        .queue_num = 1,
        .queue = rss_queues,
    };
    struct rte_flow_action actions[] = {
        { RTE_FLOW_ACTION_TYPE_COUNT, .conf = &count },
        { RTE_FLOW_ACTION_TYPE_RSS, .conf = &rss_action },
        { RTE_FLOW_ACTION_TYPE_END },
    };
    config->vf_to_rss = rte_flow_create(config->user_vf_repr_id, &attr, items, actions, &error);
    if (error.type) {
        printf("%s: error %d: %s\n", __func__, error.type, error.message);
        return -1;
    }

    return 0;
}

int unexpected_packet_count = 0;

bool create_egress_flow(struct resubmit_app_config *config, struct rte_mbuf *packet)
{
	if (RTE_ETH_IS_IPV4_HDR(packet->packet_type)) {
	    struct rte_ether_hdr *l2_header = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
    	struct rte_ipv4_hdr *ipv4 = (void *)(l2_header + 1);

        char ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ipv4->src_addr, ip_addr, sizeof(ip_addr));

        for (int i=0; i<config->num_egress_rules; i++) {
            if (config->egress_src_ip[i] == ipv4->src_addr) {
                ++unexpected_packet_count;
                printf("Warning: received packet from %s for which we already have a flow\n", ip_addr);
                if (unexpected_packet_count > 3)
                    sleep(1);
                return true;
            }
        }

        if (config->num_egress_rules >= MAX_EGRESS_RULES) {
            printf("Warning: exceeded max number of egress rules %d\n", MAX_EGRESS_RULES);
            return true;
        }

        struct rte_flow_attr attr = {
            .transfer = 1,
        };
        struct rte_flow_item_port_id from_vf0 = { .id = config->user_vf_repr_id };
        struct rte_flow_item_ipv4 ip_spec = {
            .hdr.src_addr = ipv4->src_addr,
        };
        struct rte_flow_item_ipv4 ip_mask = {
            .hdr.src_addr = UINT32_MAX,
        };
        struct rte_flow_item items[] = {
            { RTE_FLOW_ITEM_TYPE_ETH },
            { RTE_FLOW_ITEM_TYPE_PORT_ID, .spec = &from_vf0 },
            { RTE_FLOW_ITEM_TYPE_IPV4, .spec = &ip_spec, .mask = &ip_mask },
            { RTE_FLOW_ITEM_TYPE_END },
        };
        struct rte_flow_action_count count = { };
        struct rte_flow_action_set_ipv4 set_ipv4 = {
            .ipv4_addr = ipv4->src_addr + 0x01010101,
        };
        struct rte_flow_action_port_id to_uplink = {
            .id = config->uplink_port_id,
        };
        struct rte_flow_action actions[] = {
            { RTE_FLOW_ACTION_TYPE_COUNT, .conf = &count },
            { RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC, .conf = &set_ipv4 },
            { RTE_FLOW_ACTION_TYPE_PORT_ID, .conf = &to_uplink },
            { RTE_FLOW_ACTION_TYPE_END },
        };

        struct rte_flow_error error = {};
        config->vf_egress[config->num_egress_rules] = rte_flow_create(config->uplink_port_id, &attr, items, actions, &error);

        if (error.type) {
            printf("%s: error %d: %s\n", __func__, error.type, error.message);
            sleep(1);
            return -1;
        }

        config->egress_src_ip[config->num_egress_rules] = ipv4->src_addr;
        ++config->num_egress_rules;

        printf("Created flow on port %d for IP src %s\n", config->uplink_port_id, ip_addr);

        return true;
    } else {
	    //struct rte_ether_hdr *l2_header = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
		//struct rte_ipv6_hdr *ipv6 = (void *)(l2_header + 1);
        // ...
        return true;
    }
}

void log_port_start(const char *msg, uint16_t port_id)
{
	struct rte_ether_addr mac_addr;
	rte_eth_macaddr_get(port_id, &mac_addr);

	printf("\n%s: port %d: %02x:%02x:%02x:%02x:%02x:%02x\n",
        msg,
		port_id,
		mac_addr.addr_bytes[0],
		mac_addr.addr_bytes[1],
		mac_addr.addr_bytes[2],
		mac_addr.addr_bytes[3],
		mac_addr.addr_bytes[4],
		mac_addr.addr_bytes[5]);
}

#define MAX_BURST_SIZE 16

static int lcore_pkt_proc_func(void *config_voidp)
{
    struct resubmit_app_config *config = config_voidp;
	struct rte_mbuf *mbufs_rx[MAX_BURST_SIZE];
	struct rte_mbuf *mbufs_tx[MAX_BURST_SIZE];

    uint16_t queue_id = 0;
    log_port_start("l-core polling on port", config->user_vf_repr_id);

    while (!force_quit) {
        uint16_t num_rx = rte_eth_rx_burst(config->user_vf_repr_id, queue_id, mbufs_rx, MAX_BURST_SIZE);
        if (num_rx)
            printf("Port %d: Received %d packets\n", config->user_vf_repr_id, num_rx);
        
        uint16_t num_tx = 0;
        for (uint16_t i=0; i<num_rx; i++) {
            if (create_egress_flow(config, mbufs_rx[i])) {
                mbufs_tx[num_tx++] = mbufs_rx[i];
            }
        }

        if (num_tx)
            rte_eth_tx_burst(config->daemon_vf_id, queue_id, mbufs_tx, num_tx);
    }

    return 0;
}

void show_flow_stats_until_exit(struct resubmit_app_config *config)
{
    struct rte_flow_query_count flow_stats = {};
    struct rte_flow_action actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &flow_stats },
        { .type = RTE_FLOW_ACTION_TYPE_END },
    };
    struct rte_flow_error error = {};
    char ip_addr[INET_ADDRSTRLEN];

    while (!force_quit) {
        sleep(2);

        printf("Flow counts: ");
        for (int i=0; i<config->num_egress_rules + 1; i++) {
            struct rte_flow *flow;
            uint16_t port_id;
            char *name;
            if (i==0) {
                flow = config->vf_to_rss;
                printf("Miss-flow: ");
                port_id = config->user_vf_repr_id;
            } else {
                flow = config->vf_egress[i-1];
                inet_ntop(AF_INET, &config->egress_src_ip[i-1], ip_addr, INET_ADDRSTRLEN);
                printf("%s-flow: ", ip_addr);
                port_id = config->uplink_port_id;
            }

            if (rte_flow_query(port_id, flow, actions, &flow_stats, &error) == 0 &&
                flow_stats.hits_set)
            {
                printf("%ld, ", flow_stats.hits);
            } else {
                printf("Err, ");
            }
        }
        printf("\n");
    }
}

#define MBUF_CACHE_SIZE 250
#define NUM_MBUFS 2048

int
main(int argc, char **argv)
{
    struct resubmit_app_config config = {
		.uplink_port_id = 0,
		.user_vf_repr_id = 1,
		.daemon_vf_repr_id = 2,
        .daemon_vf_id = 3,
    };

    int nb_args = rte_eal_init(argc, argv);
    if (nb_args < 0)
        return 1;
    
    argc -= nb_args;
    argv += nb_args;

	install_signal_handler();

	config.nb_ports = rte_eth_dev_count_avail();
    if (config.nb_ports < MIN_PORTS) {
        printf("Warning: nb_ports = %d, requires %d\n", config.nb_ports, MIN_PORTS);
        return -1;
    }

    uint16_t nb_cores = 1; //rte_lcore_count();
    uint32_t total_nb_mbufs = NUM_MBUFS * config.nb_ports * nb_cores;
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", total_nb_mbufs, MBUF_CACHE_SIZE, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        printf("Failed to alloc mempool of size %d entries\n", total_nb_mbufs);
        return -1;
    }

    for (uint16_t i=0; i<config.nb_ports; i++) {
        if (port_init(i, nb_cores, mbuf_pool) < 0) {
            return -1;
        }
    }

    if (create_static_flows(&config) < 0) {
        return -1;
    }

    rte_eal_mp_remote_launch(lcore_pkt_proc_func, &config, SKIP_MAIN);

    show_flow_stats_until_exit(&config);

	uint32_t lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
	}
	
    for (uint16_t i=0; i<config.nb_ports; i++) {
        struct rte_flow_error error = {};
        if (rte_flow_flush(i, &error) < 0) {
            printf("%s: error flushing port %d: %d: %s\n", 
                __func__, i, error.type, error.message);
        }
        rte_eth_dev_close(i);
    }

	return 0;
}

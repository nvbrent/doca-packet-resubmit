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
// +------+                                +--------+
// | user | --> [VF0] --> [pf0vf0repr] --> |        | port_meta=0
// | app  | (1)                            | Root   |-------------> [pf0vf0repr] -> [VF0]
// +------+                                | Pipe   | (from uplink)
//           +----------> [pf0vf1repr] --> |        |
//           |                             +--------+
//           |                                 |
//           |                 port_meta=[1,2] |     
//           |                                 v
//           |                             +--------+ (5)
//           |                             | Egress | --------------> [pf0repr] -> [uplink]
//           |                             | Pipe   | [match: pkt mod]
//         [VF1]                           +--------+
//          ^                           (2) |    ^
//          |                               |    |
// +---------+                              |    |
// |         | <-------- [miss: RSS] -------+    |
// |         |                                   |
// | daemon  | (3) [new pipe entry]              |
// | process |                                   |
// |         | ---> [VF1] --> [pf0vf1repr] ------+
// +---------+  (4)
//
// 1) The user application transmits a packet on its VF0 netdev
//    The Root Pipe uses port_meta to detect the origin of the
//    packet, and forwards it to the Egress Pipe.
// 2) The Egress Pipe has no rules to handle this packet, so it
//    misses to the RSS Pipe.
// 3) The RSS processing loop creates a new flow to match the given
//    packet.
// 4) The RSS processing loop then transmits the same packet using
//    its own VF1.
// 5) The new rule in the Egress Pipe matches the resubmitted packet and
//    performs a packet mod action before sending along to the
//    uplink port.

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <dpdk_utils.h>
#include <doca_dpdk.h>
#include <doca_log.h>
#include <doca_argp.h>
#include <doca_flow.h>
#include <common.h>

DOCA_LOG_REGISTER(RESUBMIT_DEMO);

#define MAX_EGRESS_RULES 256

typedef uint8_t ipv6_addr_t[16];

struct port_t
{
    uint16_t port_id;
    struct doca_flow_port *port;
    struct doca_dev *dev;
};

struct resubmit_app_config
{
	struct application_dpdk_config dpdk_config;

    // Switch ports:
    struct port_t uplink;
    struct port_t user_vf_repr;
    struct port_t daemon_vf_repr;
    // Aux port for packet resubmit:
    struct port_t daemon_vf;

    struct doca_flow_port *switch_port;

    struct doca_flow_pipe *ipv4_egress_pipe;
    struct doca_flow_pipe *rss_pipe;
    struct doca_flow_pipe *ingress_pipe;
    struct doca_flow_pipe *to_uplink_pipe;
    struct doca_flow_pipe *root_pipe;

    struct doca_flow_pipe_entry *rss_pipe_entry;
    struct doca_flow_pipe_entry *ingress_pipe_entry;
    struct doca_flow_pipe_entry *to_uplink_pipe_entry;
    struct doca_flow_pipe_entry *root_pipe_ingress_entry;
    struct doca_flow_pipe_entry *root_pipe_egress_entry;
    struct doca_flow_pipe_entry *root_pipe_egress_entry2;

    int num_egress_rules;
    struct doca_flow_pipe_entry *ipv4_egress_entries[MAX_EGRESS_RULES];
    rte_be32_t egress_src_ip[MAX_EGRESS_RULES];

    int unexpected_packet_count;
};

volatile bool force_quit = false;

struct doca_flow_monitor count = {
    .counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
};


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

static void init_eal_w_no_netdevs(void)
{
    char *eal_params[] = { "exe", "-a00:00.0", "-c0x3" };
    int num_eal_params = sizeof(eal_params) / sizeof(eal_params[0]);
    int ret = rte_eal_init(num_eal_params, eal_params);
	if (ret < 0) {
		DOCA_LOG_ERR("EAL initialization failed");
        exit(1);
	}   
}

static doca_error_t open_doca_devs(struct resubmit_app_config *config)
{
    doca_error_t result;

    result = open_doca_device_with_pci("0000:ca:00.0", NULL, &config->uplink.dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to open dpdk port (%s): %s", "uplink", doca_error_get_descr(result));
        return result;
    }

    result = doca_dpdk_port_probe(config->uplink.dev, "dv_flow_en=2,dv_xmeta_en=4,representor=vf[0-1]");
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to probe dpdk port (%s): %s", "uplink", doca_error_get_descr(result));
        return result;
    }

    result = open_doca_device_with_pci("0000:ca:00.3", NULL, &config->daemon_vf.dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to open dpdk port (%s): %s", "vf", doca_error_get_descr(result));
        return result;
    }

    result = doca_dpdk_port_probe(config->daemon_vf.dev, "dv_flow_en=2");
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to probe dpdk port (%s): %s", "vf", doca_error_get_descr(result));
        return result;
    }
    return result;
}

bool create_flow(struct resubmit_app_config *config, struct rte_mbuf *packet)
{
    // TODO: keep a list of previously-matched IPs and if we see them again,
    // issue a warning and refuse to create another flow

	if (RTE_ETH_IS_IPV4_HDR((packet)->packet_type)) {
	    struct rte_ether_hdr *l2_header = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
    	struct rte_ipv4_hdr *ipv4 = (void *)(l2_header + 1);

        char ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ipv4->src_addr, ip_addr, sizeof(ip_addr));
        
        for (int i=0; i<config->num_egress_rules; i++) {
            if (config->egress_src_ip[i] == ipv4->src_addr) {
                ++config->unexpected_packet_count;
                DOCA_LOG_WARN("Warning: received packet from %s for which we already have a flow", ip_addr);
                if (config->unexpected_packet_count > 3)
                    sleep(1);
                return true;
            }
        }

        if (config->num_egress_rules >= MAX_EGRESS_RULES) {
            printf("Warning: exceeded max number of egress rules %d\n", MAX_EGRESS_RULES);
            return true;
        }

        struct doca_flow_match match = {
            .parser_meta = {
                .outer_l3_type = DOCA_FLOW_L3_META_IPV4,
            },
            .outer = {
                .l3_type = DOCA_FLOW_L3_TYPE_IP4,
                .ip4 = {
                    .src_ip = ipv4->src_addr, // match the src IP from the received packet
                },
            },
        };
        struct doca_flow_actions actions = {
            .outer = {
                .ip4 = {
                    .dst_ip = ipv4->src_addr + 0x01010101,
                },
            },
        };
        doca_flow_pipe_add_entry(
            1, config->ipv4_egress_pipe, &match, &actions, &count, NULL, DOCA_FLOW_NO_WAIT, NULL, 
            &config->ipv4_egress_entries[config->num_egress_rules]);
        
        doca_flow_entries_process(
            config->switch_port, 1, 0, 0);
        
        config->egress_src_ip[config->num_egress_rules] = ipv4->src_addr;
        ++config->num_egress_rules;

        DOCA_LOG_INFO("Created flow for IP src %s", ip_addr);

        return true;
    } else {
	    //struct rte_ether_hdr *l2_header = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
		//struct rte_ipv6_hdr *ipv6 = (void *)(l2_header + 1);
        return true;
    }
}

void log_port_start(const char *msg, uint16_t port_id)
{
	struct rte_ether_addr mac_addr;
	rte_eth_macaddr_get(port_id, &mac_addr);

	DOCA_LOG_INFO("\n%s: port %d: %02x:%02x:%02x:%02x:%02x:%02x\n",
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
    log_port_start("l-core polling on port", config->daemon_vf_repr.port_id);

    while (!force_quit) {
        for (uint16_t port_id = 0; port_id < config->dpdk_config.port_config.nb_ports; port_id++) {
            uint16_t num_rx = rte_eth_rx_burst(port_id, queue_id, mbufs_rx, MAX_BURST_SIZE);
            if (num_rx)
                DOCA_LOG_INFO("Port %d: Received %d packets", port_id, num_rx);
            
            uint16_t num_tx = 0;
            for (uint16_t i=0; i<num_rx; i++) {
                if (create_flow(config, mbufs_rx[i])) {
                    mbufs_tx[num_tx++] = mbufs_rx[i];
                }
            }

            if (num_tx)
                rte_eth_tx_burst(config->daemon_vf.port_id, queue_id, mbufs_tx, num_tx);
        }
    }

    return 0;
}

void port_init(struct port_t *port_obj)
{
	char port_id_str[128];
	snprintf(port_id_str, sizeof(port_id_str), "%d", port_obj->port_id);

	struct doca_flow_port_cfg port_cfg = {
		.port_id = port_obj->port_id,
		.type = DOCA_FLOW_PORT_DPDK_BY_ID,
		.devargs = port_id_str,
        .dev = port_obj->dev,
	};
	doca_error_t res = doca_flow_port_start(&port_cfg, &port_obj->port);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "failed to initialize doca flow port: %d (%s)\n", res, doca_error_get_descr(res));
	}

    log_port_start("Started doca_flow_port:", port_obj->port_id);
}

int
flow_init(struct resubmit_app_config *config)
{
	struct doca_flow_cfg flow_cfg = {
		.mode_args = "switch,hws",
		.queues = config->dpdk_config.port_config.nb_queues,
		.resource.nb_counters = 1024,
		//.cb = check_for_valid_entry,
	};

	doca_error_t res = doca_flow_init(&flow_cfg);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to init DOCA Flow: %d (%s)\n", res, doca_error_get_descr(res));
	}
	DOCA_LOG_DBG("DOCA Flow init done");

    port_init(&config->uplink); // cannot return null    
    port_init(&config->user_vf_repr);
    port_init(&config->daemon_vf_repr);
    port_init(&config->daemon_vf);

    config->switch_port = doca_flow_port_switch_get(config->uplink.port);

	return 0;
}

struct doca_flow_match empty_match = {};

void create_root_pipe(struct resubmit_app_config *config)
{
    struct doca_flow_match match_port_meta = { .parser_meta.port_meta = UINT32_MAX };

    struct doca_flow_pipe_cfg pipe_cfg = {
        .attr = {
            .name = "ROOT",
            .is_root = true,
        },
        .port = config->switch_port,
        .monitor = &count,
        .match = &match_port_meta,
    };
    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PIPE,
    };
    doca_error_t result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &config->root_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create pipe %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }

    match_port_meta.parser_meta.port_meta = 0;
    fwd.next_pipe = config->ingress_pipe;

    result = doca_flow_pipe_add_entry(0, config->root_pipe, &match_port_meta, NULL, NULL, &fwd, DOCA_FLOW_NO_WAIT, NULL, &config->root_pipe_ingress_entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create dummy pipe entry %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }

    match_port_meta.parser_meta.port_meta = 1;
    fwd.next_pipe = config->ipv4_egress_pipe;
    result = doca_flow_pipe_add_entry(0, config->root_pipe, &match_port_meta, NULL, NULL, &fwd, DOCA_FLOW_NO_WAIT, NULL, &config->root_pipe_egress_entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create dummy pipe entry %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }

    match_port_meta.parser_meta.port_meta = 2;
    fwd.next_pipe = config->ipv4_egress_pipe;
    result = doca_flow_pipe_add_entry(0, config->root_pipe, &match_port_meta, NULL, NULL, &fwd, DOCA_FLOW_NO_WAIT, NULL, &config->root_pipe_egress_entry2);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create dummy pipe entry %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }
}

void
create_ingress_ipv4_pipe(struct resubmit_app_config *config)
{
    struct doca_flow_pipe_cfg pipe_cfg = {
        .attr = {
            .name = "ingress_ipv4",
            .domain = DOCA_FLOW_PIPE_DOMAIN_EGRESS,
        },
        .port = config->switch_port,
        .match = &empty_match,
        .monitor = &count,
    };

    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = config->user_vf_repr.port_id,
    };

    doca_error_t result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &config->ingress_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create pipe %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }
    result = doca_flow_pipe_add_entry(0, config->ingress_pipe, NULL, NULL, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &config->ingress_pipe_entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create dummy pipe entry %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }
}

void create_egress_ipv4_match_pipe(struct resubmit_app_config *config)
{
    struct doca_flow_match match = {
        .parser_meta = {
            .outer_l3_type = DOCA_FLOW_L3_META_IPV4,
        },
        .outer = {
            .l3_type = DOCA_FLOW_L3_TYPE_IP4,
            .ip4 = {
                .src_ip = UINT32_MAX,
            },
        },
    };
    struct doca_flow_actions actions = {
        .outer = {
            .l3_type = DOCA_FLOW_L3_TYPE_IP4,
            .ip4 = {
                .dst_ip = UINT32_MAX,
            },
        },
    };
    struct doca_flow_actions *actions_arr[] = { &actions };

    struct doca_flow_pipe_cfg pipe_cfg = {
        .attr = {
            .name = "IPv4_Egress",
            .nb_actions = 1,
            .miss_counter = true,
        },
        .port = config->switch_port,
        .match = &match,
        .monitor = &count,
        .actions = actions_arr,
        .actions_masks = actions_arr,
    };

    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = config->to_uplink_pipe,
    };
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = config->rss_pipe,
    };

    doca_error_t result = doca_flow_pipe_create(&pipe_cfg, &fwd, &fwd_miss, &config->ipv4_egress_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create pipe %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }

    // No default entries
}

void create_to_uplink_pipe(struct resubmit_app_config *config)
{
    struct doca_flow_pipe_cfg pipe_cfg = {
        .attr = {
            .name = "to_uplink",
            .domain = DOCA_FLOW_PIPE_DOMAIN_EGRESS,
        },
        .port = config->switch_port,
        .match = &empty_match,
        .monitor = &count,
    };

    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = config->uplink.port_id,
    };

    doca_error_t result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &config->to_uplink_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create pipe %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }
    result = doca_flow_pipe_add_entry(0, config->to_uplink_pipe, NULL, NULL, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &config->to_uplink_pipe_entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create dummy pipe entry %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }
}

void create_to_rss_pipe(struct resubmit_app_config *config)
{
    struct doca_flow_pipe_cfg pipe_cfg = {
        .attr = {
            .name = "RSS_PIPE",
            .miss_counter = true,
        },
        .port = config->switch_port,
        .match = &empty_match,
        .monitor = &count,
    };

    uint16_t rss_queues[] = { 0 };
    struct doca_flow_fwd fwd_to_rss = {
        .type = DOCA_FLOW_FWD_RSS,
        .rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_IPV6,
        .num_of_queues = 1,
        .rss_queues = rss_queues,
    };

    doca_error_t result = doca_flow_pipe_create(&pipe_cfg, &fwd_to_rss, NULL, &config->rss_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create pipe %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }
    result = doca_flow_pipe_add_entry(0, config->rss_pipe, NULL, NULL, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &config->rss_pipe_entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create dummy pipe entry %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }
}

void
create_pipes(struct resubmit_app_config *config)
{
    doca_error_t result;

    // root_pipe: match(port_meta)
    //   +- port_meta==[0]   --> ingress_ipv4 --> pf0vf0repr // traffic from uplink
    //   +- port_meta==[1,2] --> egress_ipv4 // traffic from VF0, VF1
    //                               +- [match src_ip] --> [pkt mod] --> to_uplink_pipe --> p0 uplink
    //                               +-    [ miss ]    --> rss_pipe --> pf0/RxQ[0] --> vf1/TxQ[0]

    // Create from back to front...
    create_to_rss_pipe(config);
    create_to_uplink_pipe(config);
    create_egress_ipv4_match_pipe(config);
    create_ingress_ipv4_pipe(config);
    create_root_pipe(config);

    result = doca_flow_entries_process(config->switch_port, 0, 0, 0);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to process entries for port %d: %s", config->uplink.port_id, doca_error_get_descr(result));
        exit(1);
    }

    result = doca_flow_entries_process(config->daemon_vf.port, 0, 0, 0);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to process entries for port %d: %s", config->daemon_vf.port_id, doca_error_get_descr(result));
        exit(1);
    }
}

void print_stats(doca_error_t result, struct doca_flow_query *stats)
{
    if (result == DOCA_SUCCESS)
        printf("%ld, ", stats->total_pkts);
    else
        printf("XX, ");
}

void show_flow_stats_until_exit(struct resubmit_app_config *config)
{

    struct doca_flow_pipe_entry *entries_to_query[] = {
        config->root_pipe_ingress_entry,
        config->root_pipe_egress_entry,
        config->root_pipe_egress_entry2,
        config->ingress_pipe_entry,
        config->to_uplink_pipe_entry,
        config->rss_pipe_entry,
    };
    char *entry_names[] = {
        "root_ingress_entry",
        "root_egress_vf0",
        "root_egress_vf1",
        "ingress_entry",
        "to_uplink",
        "rss_pipe",
    };
    int n_entries_to_query = sizeof(entries_to_query) / sizeof(entries_to_query[0]);

    struct doca_flow_pipe *pipe_miss_to_query[] = {
        config->ipv4_egress_pipe,
        //config->root_pipe,
    };
    int n_pipes_to_query = sizeof(pipe_miss_to_query) / sizeof(pipe_miss_to_query[0]);

    while (!force_quit) {
		sleep(3);
        printf("Static Entry Counters: ");
        for (int i=0; i<n_entries_to_query; i++) {
            if (entries_to_query[i]) {
                printf("%s: ", entry_names[i]);
                struct doca_flow_query stats = {};
                print_stats(doca_flow_query_entry(entries_to_query[i], &stats), &stats);
            }
        }
        printf("; egress entry counters: ");
        for (int i=0; i<config->num_egress_rules; i++) {
            char ip_addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &config->egress_src_ip[i], ip_addr, INET_ADDRSTRLEN);
            printf("%s-flow: ", ip_addr);
                struct doca_flow_query stats = {};
                print_stats(doca_flow_query_entry(config->ipv4_egress_entries[i], &stats), &stats);
        }
        printf("; Pipe Miss counters: ");
        for (int i=0; i<n_pipes_to_query; i++) {
            if (pipe_miss_to_query[i]) {
                struct doca_flow_query stats = {};
                print_stats(doca_flow_query_pipe_miss(pipe_miss_to_query[i], &stats), &stats);
            }
        }
        printf("\n");
	}
}

int
main(int argc, char **argv)
{
	struct resubmit_app_config config = {
		.dpdk_config = {
			.port_config = {
				.nb_ports = 0, // updated after dpdk_init()
				.nb_queues = 1,
				.nb_hairpin_q = 1,
                //.isolated_mode = true,
                .enable_mbuf_metadata = true,
			},
		},
		.uplink.port_id = 0,
		.user_vf_repr.port_id = 1,
		.daemon_vf_repr.port_id = 2,
        .daemon_vf.port_id = 3,
	};

	/* Register a logger backend */
	struct doca_log_backend *sdk_log;
	doca_error_t result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS)
		exit(1);

	/* Register a logger backend for internal SDK errors and warnings */
	result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
	if (result != DOCA_SUCCESS)
		exit(1);
	result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
	if (result != DOCA_SUCCESS)
		exit(1);
	
	/* Parse cmdline/json arguments */
	doca_argp_init("resubmit-demo", &config);
	//doca_argp_set_dpdk_program(dpdk_init);
    // additional command line args go here
	doca_argp_start(argc, argv);

	install_signal_handler();

    init_eal_w_no_netdevs();

    open_doca_devs(&config);

	config.dpdk_config.port_config.nb_ports = rte_eth_dev_count_avail(); // attach to the PF and all the available VFs
    DOCA_LOG_INFO("Detected %d ports", config.dpdk_config.port_config.nb_ports);

	dpdk_queues_and_ports_init(&config.dpdk_config);

	flow_init(&config);

    create_pipes(&config);
	
    DOCA_LOG_INFO("Starting l-cores...");

    rte_eal_mp_remote_launch(lcore_pkt_proc_func, &config, SKIP_MAIN);

    DOCA_LOG_INFO("Waiting for signal...");
	
    show_flow_stats_until_exit(&config);

    DOCA_LOG_INFO("Shutting down...");

	uint32_t lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
	}

    doca_flow_port_stop(config.daemon_vf.port);
    doca_flow_port_stop(config.daemon_vf_repr.port);
    doca_flow_port_stop(config.user_vf_repr.port);
    doca_flow_port_stop(config.uplink.port);
	
	doca_flow_destroy();
	doca_argp_destroy();

	return 0;
}

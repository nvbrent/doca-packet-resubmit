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
//                                         +--------+
//              [uplink] ----------------> |        |
// +------+                                |        |
// | user | --> [VF0] --> [pf0vf0repr] --> | Root   | port_meta=0   +----------+
// | app  | (1)                            | Pipe   |-------------> | N2H Pipe | ---> [pf0vf0repr] -> [VF0]
// +------+                                |        | (from uplink) +----------+
//           +---------------------------> |        |
//           |                             +--------+
//           |                                 |
//           |                     port_meta=1 |     
//           |                                 v
//           |                             +--------+ (5)
//           |                             | H2N    | --------------> [pf0repr] -> [uplink]
//           |                             | Pipe   | [match: pkt mod]
//         [pf0]                           +--------+
//          ^                           (2) |
//      (4) |                               |
// +---------+                              |
// |         | <-------- [miss: RSS] -------+
// |         |
// | daemon  | (3) [new pipe entry]
// | process |
// |         |
// +---------+
//
// 1) The user application transmits a packet on its VF0 netdev
//    The Root Pipe uses port_meta to detect the origin of the
//    packet, and forwards it to the Egress Pipe.
// 2) The Egress Pipe has no rules to handle this packet, so it
//    misses to the RSS Pipe.
// 3) The RSS processing loop creates a new flow to match the given
//    packet.
// 4) The RSS processing loop then transmits the same packet using
//    the PF.
// 5) The new rule in the Egress Pipe matches the resubmitted packet and
//    performs a packet mod action before sending along to the
//    uplink port.

#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <dpdk_utils.h>
#include <doca_dpdk.h>
#include <doca_dev.h>
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

    char *pf_pci_str;
    char *vf_pci_str;

    // Switch ports:
    struct port_t uplink;
    struct port_t user_vf_repr;

    struct doca_flow_port *switch_port;

    struct doca_flow_pipe *ipv4_host_to_net_pipe;
    struct doca_flow_pipe *net_to_host_pipe;
    struct doca_flow_pipe *rss_pipe;
    struct doca_flow_pipe *root_pipe;

    struct doca_flow_pipe_entry *rss_pipe_entry;
    struct doca_flow_pipe_entry *net_to_host_entry;
    struct doca_flow_pipe_entry *root_pipe_net_to_host_entry;
    struct doca_flow_pipe_entry *root_pipe_host_to_net_entry;

    uint32_t resubmit_meta_flag;

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

static int disable_dpdk_accept_args(
	int argc, 
	char *argv[], 
	char *dpdk_argv[], 
	char **pci_addr_arg, 
	char **devarg)
{
	bool prev_arg_was_a = false; // indicates prev arg was -a followed by space

	for (int i=0; i<argc; i++) {		
		if (prev_arg_was_a) {
			// This arg should be the PCI BDF.
			// Save it as pci_addr_arg, then
			// replace it with the null PCI address.
			dpdk_argv[i] = strdup("00:00.0");
			*pci_addr_arg = strdup(argv[i]);
			prev_arg_was_a = false;
			continue;
		}

		if (strncmp(argv[i], "-a", 2) != 0) {
			// copy the non-"-a" args
			dpdk_argv[i] = strdup(argv[i]);
			continue;
		}

		if (strlen(argv[i]) == 2) {
			// copy the "-a", next time around replace the arg
			dpdk_argv[i] = strdup(argv[i]);
			prev_arg_was_a = true;
			continue;
		}

		// This arg is the PCI BDF.
		// Save it as pci_addr_arg, then
		// replace it with the null PCI address.
		*pci_addr_arg = strdup(argv[i] + 2); // skip the -a prefix
		dpdk_argv[i] = strdup("-a00:00.0");
	}

	if (!*pci_addr_arg) {
		return -1;
	}

	char * comma = strchr(*pci_addr_arg, ',');
	if (comma) {
		*comma = '\0';
		*devarg = comma + 1;
	} else {
		*devarg = NULL;
	}

    int len = strlen(*pci_addr_arg);
    for (int i=0; i<len; i++) {
        (*pci_addr_arg)[i] = tolower((*pci_addr_arg)[i]);
    }

	return argc;
}

static doca_error_t open_doca_devs(struct resubmit_app_config *config)
{
    doca_error_t result;

    result = open_doca_device_with_pci(config->pf_pci_str, NULL, &config->uplink.dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to open dpdk port (%s): %s", "uplink", doca_error_get_descr(result));
        return result;
    }

    result = doca_dpdk_port_probe(config->uplink.dev,
        "dv_flow_en=2,"
		"dv_xmeta_en=4,"
		"fdb_def_rule_en=0,"
		"vport_match=1,"
		"repr_matching_en=0,"
		"representor=vf0");

    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to probe dpdk port (%s): %s", "uplink", doca_error_get_descr(result));
        return result;
    }

    return result;
}

bool create_flow(struct resubmit_app_config *config, struct rte_mbuf *packet)
{
	if (RTE_ETH_IS_IPV4_HDR((packet)->packet_type)) {
	    struct rte_ether_hdr *l2_header = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
    	struct rte_ipv4_hdr *ipv4 = (void *)(l2_header + 1);

        char src_ip_addr[INET_ADDRSTRLEN];
        char dst_ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ipv4->src_addr, src_ip_addr, sizeof(src_ip_addr));
        inet_ntop(AF_INET, &ipv4->dst_addr, dst_ip_addr, sizeof(dst_ip_addr));
        
        for (int i=0; i<config->num_egress_rules; i++) {
            if (config->egress_src_ip[i] == ipv4->src_addr) {
                ++config->unexpected_packet_count;
                DOCA_LOG_WARN("Warning: received packet %s->%s for which we already have a flow", 
                    src_ip_addr, dst_ip_addr);
                if (config->unexpected_packet_count > 50)
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
            1, config->ipv4_host_to_net_pipe, &match, &actions, &count, NULL, DOCA_FLOW_NO_WAIT, NULL, 
            &config->ipv4_egress_entries[config->num_egress_rules]);
        
        doca_flow_entries_process(
            config->switch_port, 1, 0, 0);
        
        config->egress_src_ip[config->num_egress_rules] = ipv4->src_addr;
        ++config->num_egress_rules;

        uint32_t *pkt_meta = RTE_MBUF_DYNFIELD(packet, rte_flow_dynf_metadata_offs, uint32_t*);

        if (packet->ol_flags & rte_flow_dynf_metadata_mask) {
            DOCA_LOG_INFO("Created flow for IP %s->%s, pkt_meta was 0x%x", 
                src_ip_addr, dst_ip_addr, *pkt_meta);
        } else {
            DOCA_LOG_INFO("Created flow for IP %s->%s", 
                src_ip_addr, dst_ip_addr);
        }

        // Mark the packet so the egress pipe will modify and forward it
        *pkt_meta = config->resubmit_meta_flag;
        packet->ol_flags |= rte_flow_dynf_metadata_mask;

        return true;
    } else {
	    //struct rte_ether_hdr *l2_header = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
		//struct rte_ipv6_hdr *ipv6 = (void *)(l2_header + 1);
        return false;
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
    uint16_t port_id = config->uplink.port_id;
    log_port_start("l-core polling on port", port_id);

    while (!force_quit) {
        uint16_t num_rx = rte_eth_rx_burst(port_id, queue_id, mbufs_rx, MAX_BURST_SIZE);
        // if (num_rx)
        //     DOCA_LOG_INFO("Port %d: Received %d packets", port_id, num_rx);
        
        uint16_t num_tx = 0;
        for (uint16_t i=0; i<num_rx; i++) {
            if (create_flow(config, mbufs_rx[i])) {
                mbufs_tx[num_tx++] = mbufs_rx[i];
            } else {
                rte_pktmbuf_free(mbufs_rx[i]);
            }
        }

        if (num_tx)
            rte_eth_tx_burst(port_id, queue_id, mbufs_tx, num_tx);
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
		.mode_args = "switch,hws,isolated",
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
        .next_pipe = NULL, // specified per entry
    };
    doca_error_t result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &config->root_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create pipe %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }

    // Packets coming from port_id 0 Tx queue will bypass the 
    // ingress/default domain and skip to the egress domain.

    match_port_meta.parser_meta.port_meta = config->uplink.port_id;
    fwd.next_pipe = config->net_to_host_pipe;
    result = doca_flow_pipe_add_entry(0, config->root_pipe, &match_port_meta, NULL, NULL, &fwd, DOCA_FLOW_NO_WAIT, NULL, 
        &config->root_pipe_host_to_net_entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create dummy pipe entry %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }

    match_port_meta.parser_meta.port_meta = config->user_vf_repr.port_id;
    fwd.next_pipe = config->ipv4_host_to_net_pipe;
    result = doca_flow_pipe_add_entry(0, config->root_pipe, &match_port_meta, NULL, NULL, &fwd, DOCA_FLOW_NO_WAIT, NULL, 
        &config->root_pipe_host_to_net_entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create dummy pipe entry %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }
}

void create_net_to_host_pipe(struct resubmit_app_config *config)
{
    struct doca_flow_pipe_cfg pipe_cfg = {
        .attr = {
            .name = "NET_TO_HOST",
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

    doca_error_t result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &config->net_to_host_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create pipe %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }
    result = doca_flow_pipe_add_entry(0, config->net_to_host_pipe, NULL, NULL, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, &config->net_to_host_entry);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create dummy pipe entry %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }
}

void create_ipv4_host_to_net_match_pipe(struct resubmit_app_config *config)
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
            .is_root = true,
            .nb_actions = 1,
            .domain = DOCA_FLOW_PIPE_DOMAIN_EGRESS,
            .miss_counter = true,
        },
        .port = config->switch_port,
        .match = &match,
        .monitor = &count,
        .actions = actions_arr,
        .actions_masks = actions_arr,
    };

    struct doca_flow_fwd fwd = {
        .type = DOCA_FLOW_FWD_PORT,
        .port_id = config->uplink.port_id,
    };
    struct doca_flow_fwd fwd_miss = {
        .type = DOCA_FLOW_FWD_PIPE,
        .next_pipe = config->rss_pipe,
    };

    doca_error_t result = doca_flow_pipe_create(&pipe_cfg, &fwd, &fwd_miss, &config->ipv4_host_to_net_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create pipe %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
        exit(1);
    }

    // No default entries
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
    //   +- port_meta==[0]   --> ipv4_net_to_host --> pf0vf0repr // traffic from uplink
    //   +- port_meta==[1]   --> ipv4_host_to_net // traffic from VF0, VF1
    //                               +- [match src_ip] --> [pkt mod] --> p0 uplink
    //                               +-    [ miss ]    --> rss_pipe --> pf0/RxQ[0] --> vf1/TxQ[0]

    // Create from back to front...
    create_to_rss_pipe(config);
    create_ipv4_host_to_net_match_pipe(config);
    create_net_to_host_pipe(config);
    create_root_pipe(config);

    result = doca_flow_entries_process(config->switch_port, 0, 0, 0);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to process entries for port %d: %s", config->uplink.port_id, doca_error_get_descr(result));
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
        config->root_pipe_net_to_host_entry,
        config->root_pipe_host_to_net_entry,
        config->rss_pipe_entry,
    };
    char *entry_names[] = {
        "root_net_to_host_entry",
        "root_host_to_net_vf0",
        "rss_pipe",
    };
    int n_entries_to_query = sizeof(entries_to_query) / sizeof(entries_to_query[0]);

    struct doca_flow_pipe *pipe_miss_to_query[] = {
        config->ipv4_host_to_net_pipe,
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

bool is_valid_pci_addr_str(char *str)
{
    int len = strlen(str);
    if (len + 1 == DOCA_DEVINFO_PCI_ADDR_SIZE) {
        int dummy[4];
        if (sscanf(str, "%x:%x:%x.%x", &dummy[0], &dummy[1], &dummy[2], &dummy[3]) != 4) {
            return false;
        }
    } else if (len + 1 == DOCA_DEVINFO_PCI_BDF_SIZE) {
        int dummy[3];
        if (sscanf(str, "%x:%x.%x", &dummy[0], &dummy[1], &dummy[2]) != 3) {
            return false;
        }
    } else {
        return false;
    }

    // convert to lower-case hex
    for (int i=0; i < len; i++) {
        if (str[i] >= 'A' && str[i] <= 'F') {
            str[i] = tolower(str[i]);
        }
    }
    return true;
}

doca_error_t set_arg_pf(void *param_voidp, void *config_voidp)
{
    if (!is_valid_pci_addr_str(param_voidp)) {
        DOCA_LOG_ERR("--pf: expected DBDF format: XXXX:XX:XX.X or BDF format: XX:XX.X");
        return DOCA_ERROR_INVALID_VALUE;
    }
    struct resubmit_app_config *config = config_voidp;
    config->pf_pci_str = strdup(param_voidp);

    return DOCA_SUCCESS;
}

doca_error_t set_arg_vf(void *param_voidp, void *config_voidp)
{
    if (!is_valid_pci_addr_str(param_voidp)) {
        DOCA_LOG_ERR("--vf: expected DBDF format: XXXX:XX:XX.X or BDF format: XX:XX.X");
        return DOCA_ERROR_INVALID_VALUE;
    }
    struct resubmit_app_config *config = config_voidp;
    config->vf_pci_str = strdup(param_voidp);

    return DOCA_SUCCESS;
}

doca_error_t create_program_args(struct resubmit_app_config *config)
{
	/* Parse cmdline/json arguments */
	doca_argp_init("resubmit-demo", config);
	doca_argp_set_dpdk_program(dpdk_init);

    return DOCA_SUCCESS;
}

int
main(int argc, char **argv)
{
	char **dpdk_argv = malloc(argc * sizeof(void*)); // same as argv but without -a arguments	
	char *dummy_devargs = NULL;

	struct resubmit_app_config config = {
		.dpdk_config = {
			.port_config = {
				.nb_ports = 0, // updated after dpdk_init()
				.nb_queues = 1,
				.nb_hairpin_q = 1,
                .isolated_mode = true,
                .enable_mbuf_metadata = true,
			},
		},
		.uplink.port_id = 0,
		.user_vf_repr.port_id = 1,
        .resubmit_meta_flag = 0x55,
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
	
	disable_dpdk_accept_args(argc, argv, dpdk_argv, &config.pf_pci_str, &dummy_devargs);

    create_program_args(&config);
	result = doca_argp_start(argc, dpdk_argv);
    if (result != DOCA_SUCCESS)
        exit(1);

    install_signal_handler();

	rte_flow_dynf_metadata_register();

    open_doca_devs(&config);

	config.dpdk_config.port_config.nb_ports = rte_eth_dev_count_avail();

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

    doca_flow_port_stop(config.user_vf_repr.port);
    doca_flow_port_stop(config.uplink.port);
	
	doca_flow_destroy();
	doca_argp_destroy();

	return 0;
}

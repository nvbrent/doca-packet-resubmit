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
// +------+                                +--------+ (5)
// | user | --> [VF0] --> [pf0vf0repr] --> | egress | -----------------> [p0 uplink]
// | app  | (1)                            | pipe   | [match: pkt mod]
// +------+                                +--------+
//                                      (2) |    ^
// +---------+ <-------- [miss: RSS] -------+    |
// |         |                                   |
// | daemon  | (3) [new pipe entry]              |
// | process |                                   |
// |         | ---> [VF1] --> [pf0vf1repr] ------+
// +---------+  (4)
//


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

typedef uint8_t ipv6_addr_t[16];

struct resubmit_app_config
{
	struct application_dpdk_config dpdk_config;

    struct doca_dev *uplink_doca_dev;
    struct doca_dev *daemon_vf_doca_dev;

	struct doca_flow_port *uplink_port;
	struct doca_flow_port *switch_port;
	struct doca_flow_port *daemon_vf_port;
    
    uint16_t uplink_port_id; // always 0
    uint16_t user_vf_repr_id;
    uint16_t daemon_vf_repr_id;
    uint16_t daemon_vf_id;

    rte_be32_t rewrite_src_ip;

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

    result = open_doca_device_with_pci("0000:ca:00.0", NULL, &config->uplink_doca_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to open dpdk port (%s): %s", "uplink", doca_error_get_descr(result));
        return result;
    }

    result = doca_dpdk_port_probe(config->uplink_doca_dev, "dv_flow_en=2,dv_xmeta_en=4,representor=vf[0-1]");
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to probe dpdk port (%s): %s", "uplink", doca_error_get_descr(result));
        return result;
    }

    result = open_doca_device_with_pci("0000:ca:00.3", NULL, &config->daemon_vf_doca_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to open dpdk port (%s): %s", "vf", doca_error_get_descr(result));
        return result;
    }

    result = doca_dpdk_port_probe(config->daemon_vf_doca_dev, "dv_flow_en=2");
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to probe dpdk port (%s): %s", "vf", doca_error_get_descr(result));
        return result;
    }
    return result;
}

void create_ipv4_flow(
    struct resubmit_app_config *config, 
    struct rte_mbuf *packet, 
    struct rte_ipv4_hdr *ipv4)
{
    struct doca_flow_match match = {
        .parser_meta = {
            .outer_l3_type = DOCA_FLOW_L3_META_IPV4,
        },
        .outer = {
            .l3_type = DOCA_FLOW_L3_TYPE_IP4,
            .ip4 = {
                .dst_ip = ipv4->dst_addr, // match the dst IP from the received packet
            },
        },
    };
    struct doca_flow_actions actions = {
        .outer = {
            .ip4 = {
                .dst_ip = ipv4->dst_addr + 0x01010101, // ignore endian and wrapping for now
            },
        },
    };
    struct doca_flow_pipe_entry *entry = NULL;
    doca_flow_pipe_add_entry(
        0, config->ipv4_egress_pipe, &match, &actions, NULL, NULL, DOCA_FLOW_NO_WAIT, NULL, 
        &entry);

    doca_flow_entries_process(
        config->switch_port, 0, 0, 0);
    
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipv4->dst_addr, dst_ip_str, INET_ADDRSTRLEN);
    DOCA_LOG_INFO("Created flow for IP dst %s", dst_ip_str);
}

bool create_flow(struct resubmit_app_config *config, struct rte_mbuf *packet)
{
    uint32_t *pkt_meta = RTE_FLOW_DYNF_METADATA(packet);
    if (*pkt_meta) {
        DOCA_LOG_WARN("Note: detected packet with meta=0x%x", *pkt_meta);
        return false;
    }

    *pkt_meta = 1; // mark the packet so we don't send it again

	struct rte_ether_hdr *l2_header = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
	if (RTE_ETH_IS_IPV4_HDR((packet)->packet_type)) {
    	struct rte_ipv4_hdr *ipv4 = (void *)(l2_header + 1);
        create_ipv4_flow(config, packet, ipv4);
        return true;
    } else {
		//struct rte_ipv6_hdr *ipv6 = (void *)(l2_header + 1);
        //create_ipv6_flow(config, packet, ipv6);
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
    log_port_start("l-core polling on port", config->uplink_port_id);

    while (!force_quit) {
        uint16_t num_rx = rte_eth_rx_burst(config->uplink_port_id, queue_id, mbufs_rx, MAX_BURST_SIZE);
        if (num_rx)
            DOCA_LOG_INFO("Received %d packets", num_rx);
        
        // To be truly resiliant, we should keep a table of already-handled flows,
        // and only create a new Pipe Entry if we have not yet handled this flow.

        uint16_t num_tx = 0;
        for (uint16_t i=0; i<num_rx; i++) {
            if (create_flow(config, mbufs_rx[i])) {
                mbufs_tx[num_tx++] = mbufs_rx[i];
            }
        }

        if (num_tx)
            rte_eth_tx_burst(config->daemon_vf_id, queue_id, mbufs_tx, num_tx);
    }

    return 0;
}

static struct doca_flow_port *
port_init(uint16_t port_id, struct doca_dev *doca_dev)
{
	char port_id_str[128];
	snprintf(port_id_str, sizeof(port_id_str), "%d", port_id);

	struct doca_flow_port_cfg port_cfg = {
		.port_id = port_id,
		.type = DOCA_FLOW_PORT_DPDK_BY_ID,
		.devargs = port_id_str,
        .dev = doca_dev,
	};
	struct doca_flow_port * port = NULL;
	doca_error_t res = doca_flow_port_start(&port_cfg, &port);
	if (res != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "failed to initialize doca flow port: %d (%s)\n", res, doca_error_get_descr(res));
	}

    log_port_start("Started doca_flow_port:", port_id);

	return port;
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

    config->uplink_port = port_init(config->uplink_port_id, config->uplink_doca_dev); // cannot return null
    config->switch_port = doca_flow_port_switch_get(config->uplink_port);
    
    config->uplink_port = port_init(config->user_vf_repr_id, NULL);
    config->uplink_port = port_init(config->daemon_vf_repr_id, NULL);
    
    config->daemon_vf_port = port_init(config->daemon_vf_id, config->daemon_vf_doca_dev);

	return 0;
}

void
create_pipes(struct resubmit_app_config *config)
{
    // root_pipe --> [ipv4, port_meta==0] --> ingress_ipv4 --> pf0vf0repr // traffic from uplink
    // root_pipe --> [ipv4, port_meta!=0] --> egress_ipv4 // traffic from VF0, VF1
    // egress_ipv4 --> [match dst_ip] --> [pkt mod] --> to_uplink_pipe --> p0 uplink
    // egress_ipv4 -->    [ miss ]    --> rss_pipe --> pf0/RxQ[0] --> vf1/TxQ[0]

    doca_error_t result;

    struct doca_flow_match empty_match = {};

    struct doca_flow_monitor count = {
        .counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
    };

    {
        struct doca_flow_pipe_cfg pipe_cfg = {
            .attr = {
                .name = "ingress_ipv4",
            },
            .port = config->switch_port,
            .match = &empty_match,
            .monitor = &count,
        };

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PORT,
            .port_id = config->user_vf_repr_id,
        };

        result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &config->ingress_pipe);
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
        struct doca_flow_fwd fwd_miss = { .type = DOCA_FLOW_FWD_DROP };

        result = doca_flow_pipe_create(&pipe_cfg, &fwd_to_rss, &fwd_miss, &config->rss_pipe);
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
            .port_id = config->uplink_port_id,
        };

        result = doca_flow_pipe_create(&pipe_cfg, &fwd, NULL, &config->to_uplink_pipe);
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
    {
        struct doca_flow_match match = {
            .parser_meta = {
                .outer_l3_type = DOCA_FLOW_L3_META_IPV4,
            },
            .outer = {
                .l3_type = DOCA_FLOW_L3_TYPE_IP4,
                .ip4 = {
                    .dst_ip = UINT32_MAX,
                },
            },
        };
        struct doca_flow_actions actions = {
            .outer = {
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
        };

        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = config->to_uplink_pipe,
        };
        struct doca_flow_fwd fwd_miss = {
            .type = DOCA_FLOW_FWD_PIPE,
            .next_pipe = config->rss_pipe,
        };

        result = doca_flow_pipe_create(&pipe_cfg, &fwd, &fwd_miss, &config->ipv4_egress_pipe);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to create pipe %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
            exit(1);
        }
    }
    {
        struct doca_flow_match match_port_meta = { .parser_meta.port_meta = UINT32_MAX };
        struct doca_flow_match match_mask_port_meta = { .parser_meta.port_meta = UINT32_MAX };

        struct doca_flow_pipe_cfg pipe_cfg = {
            .attr = {
                .name = "ROOT",
                //.type = DOCA_FLOW_PIPE_CONTROL,
                .miss_counter = true,
                .is_root = true,
            },
            .port = config->switch_port,
            .monitor = &count,
            .match = &match_port_meta,
            .match_mask = &match_mask_port_meta,
        };
        struct doca_flow_fwd fwd = {
            .type = DOCA_FLOW_FWD_CHANGEABLE,
        };
        struct doca_flow_fwd fwd_miss = {
            .type = DOCA_FLOW_FWD_DROP,
        };
        result = doca_flow_pipe_create(&pipe_cfg, &fwd, &fwd_miss, &config->root_pipe);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to create pipe %s: %s", pipe_cfg.attr.name, doca_error_get_descr(result));
            exit(1);
        }

        match_port_meta.parser_meta.port_meta = 0;
        fwd.type = DOCA_FLOW_FWD_PIPE;
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
    doca_flow_entries_process(config->switch_port, 0, 10000, 5);
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
                .isolated_mode = true,
                .enable_mbuf_metadata = true,
			},
		},
		.uplink_port_id = 0,
		.user_vf_repr_id = 1,
		.daemon_vf_repr_id = 2,
        .daemon_vf_id = 3,
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
	
    struct doca_flow_pipe_entry *entries_to_query[] = {
        config.root_pipe_ingress_entry,
        config.root_pipe_egress_entry,
        config.root_pipe_egress_entry2,
        config.ingress_pipe_entry,
        config.to_uplink_pipe_entry,
        config.rss_pipe_entry,
    };
    int n_entries_to_query = sizeof(entries_to_query) / sizeof(entries_to_query[0]);

    struct doca_flow_pipe *pipe_miss_to_query[] = {
        config.ipv4_egress_pipe,
        config.root_pipe,
        config.rss_pipe,
    };
    int n_pipes_to_query = sizeof(pipe_miss_to_query) / sizeof(pipe_miss_to_query[0]);

    while (!force_quit) {
		sleep(3);
        printf("Entries: ");
        for (int i=0; i<n_entries_to_query; i++) {
            if (entries_to_query[i]) {
                struct doca_flow_query stats = {};
                if (doca_flow_query_entry(entries_to_query[i], &stats) == DOCA_SUCCESS)
                    printf("%ld, ", stats.total_pkts);
            }
        }
        printf("; Pipe miss: ");
        for (int i=0; i<n_pipes_to_query; i++) {
            if (pipe_miss_to_query[i]) {
                struct doca_flow_query stats = {};
                if (doca_flow_query_pipe_miss(pipe_miss_to_query[i], &stats) == DOCA_SUCCESS)
                    printf("%ld, ", stats.total_pkts);
            }
        }
        printf("\n");
	}

    DOCA_LOG_INFO("Shutting down...");

	uint32_t lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
	}
	
	doca_flow_destroy();
	doca_argp_destroy();

	return 0;
}

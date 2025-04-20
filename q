[1mdiff --git a/examples/qos_sched/65kpipe_25gb.cfg b/examples/qos_sched/65kpipe_25gb.cfg[m
[1mindex e1925c8dbf..45ed70ff0f 100644[m
[1m--- a/examples/qos_sched/65kpipe_25gb.cfg[m
[1m+++ b/examples/qos_sched/65kpipe_25gb.cfg[m
[36m@@ -28,7 +28,7 @@[m [mtc 10 rate = 3125000000        ; Bytes per second[m
 tc 11 rate = 3125000000        ; Bytes per second[m
 tc 12 rate = 3125000000        ; Bytes per second[m
 [m
[31m-tc period = 10                 ; Milliseconds[m
[32m+[m[32mtc period = 2                 ; Milliseconds[m
 [m
 ; Pipe configuration[m
 [pipe profile 0][m
[36m@@ -49,7 +49,7 @@[m [mtc 10 rate = 12500000000        ; Bytes per second[m
 tc 11 rate = 12500000000        ; Bytes per second[m
 tc 12 rate = 12500000000        ; Bytes per second[m
 [m
[31m-tc period = 10                ; Milliseconds[m
[32m+[m[32mtc period = 2                ; Milliseconds[m
 [m
 tc 12 oversubscription weight = 1[m
 [m
[1mdiff --git a/examples/qos_sched/app_thread.c b/examples/qos_sched/app_thread.c[m
[1mindex ac3b1900c6..81d564895e 100644[m
[1m--- a/examples/qos_sched/app_thread.c[m
[1m+++ b/examples/qos_sched/app_thread.c[m
[36m@@ -129,10 +129,14 @@[m [mapp_tx_thread(struct thread_conf **confs)[m
 	while ((conf = confs[conf_idx])) {[m
 		nb_pkts = rte_ring_sc_dequeue_burst(conf->tx_ring, (void **)mbufs,[m
 					burst_conf.qos_dequeue, NULL);[m
[32m+[m		[32muint16_t nb_tx = 0;[m
 		if (likely(nb_pkts != 0)) {[m
[31m-			uint16_t nb_tx = rte_eth_tx_burst(conf->tx_port, 0, mbufs, nb_pkts);[m
[31m-			if (nb_pkts != nb_tx)[m
[31m-				rte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_pkts - nb_tx);[m
[32m+[m			[32mfor(int i = 0; i < nb_pkts; i++) {[m
[32m+[m				[32mint rx_queue = mbufs[i]->hash.sched.traffic_class;[m
[32m+[m			[32m}[m
[32m+[m			[32mnb_tx = rte_eth_tx_burst(conf->tx_port, 0, mbufs, nb_pkts);[m
[32m+[m			[32m if (nb_pkts != nb_tx)[m
[32m+[m			[41m [m	[32mrte_pktmbuf_free_bulk(&mbufs[nb_tx], nb_pkts - nb_tx);[m
 		}[m
 [m
 		conf_idx++;[m
[36m@@ -165,6 +169,7 @@[m [mapp_worker_thread(struct thread_conf **confs)[m
 [m
 		nb_pkt = rte_sched_port_dequeue(conf->sched_port, mbufs,[m
 					burst_conf.qos_dequeue);[m
[32m+[m
 		if (likely(nb_pkt > 0))[m
 			while (rte_ring_sp_enqueue_bulk(conf->tx_ring,[m
 					(void **)mbufs, nb_pkt, NULL) == 0)[m
[1mdiff --git a/examples/qos_sched/init.c b/examples/qos_sched/init.c[m
[1mindex ab59f50327..3aafb0969f 100644[m
[1m--- a/examples/qos_sched/init.c[m
[1m+++ b/examples/qos_sched/init.c[m
[36m@@ -110,7 +110,7 @@[m [mapp_init_port(uint16_t portid, struct rte_mempool *mp)[m
 	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)[m
 		local_port_conf.txmode.offloads |=[m
 			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;[m
[31m-	ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);[m
[32m+[m	[32mret = rte_eth_dev_configure(portid, 1, 8, &local_port_conf);[m
 	if (ret < 0)[m
 		rte_exit(EXIT_FAILURE,[m
 			 "Cannot configure device: err=%d, port=%u\n",[m
[36m@@ -138,13 +138,25 @@[m [mapp_init_port(uint16_t portid, struct rte_mempool *mp)[m
 [m
 	/* init one TX queue */[m
 	fflush(stdout);[m
[31m-	tx_conf.offloads = local_port_conf.txmode.offloads;[m
[31m-	ret = rte_eth_tx_queue_setup(portid, 0,[m
[31m-		(uint16_t)ring_conf.tx_size, rte_eth_dev_socket_id(portid), &tx_conf);[m
[31m-	if (ret < 0)[m
[31m-		rte_exit(EXIT_FAILURE,[m
[31m-			 "rte_eth_tx_queue_setup: err=%d, port=%u queue=%d\n",[m
[31m-			 ret, portid, 0);[m
[32m+[m	[32mfor (int i = 0; i < 8; i++) {[m
[32m+[m		[32mtx_conf.offloads = local_port_conf.txmode.offloads;[m
[32m+[m		[32mret = rte_eth_tx_queue_setup(portid, i,[m
[32m+[m			[32m(uint16_t)ring_conf.tx_size, rte_eth_dev_socket_id(portid), &tx_conf);[m
[32m+[m
[32m+[m		[32mtx_buffer[i] = rte_zmalloc_socket("tx_buffer",[m
[32m+[m				[32mRTE_ETH_TX_BUFFER_SIZE(MAX_PKT_RX_BURST), 0,[m
[32m+[m				[32mrte_eth_dev_socket_id(portid));[m
[32m+[m		[32mif (tx_buffer[portid] == NULL)[m
[32m+[m			[32mrte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",[m
[32m+[m					[32mportid);[m
[32m+[m
[32m+[m		[32mrte_eth_tx_buffer_init(tx_buffer[i], MAX_PKT_RX_BURST);[m
[32m+[m
[32m+[m		[32mif (ret < 0)[m
[32m+[m			[32mrte_exit(EXIT_FAILURE,[m
[32m+[m				[32m "rte_eth_tx_queue_setup: err=%d, port=%u queue=%d\n",[m
[32m+[m				[32m ret, portid, i);[m
[32m+[m	[32m}[m
 [m
 	/* Start device */[m
 	ret = rte_eth_dev_start(portid);[m
[1mdiff --git a/examples/qos_sched/main.h b/examples/qos_sched/main.h[m
[1mindex 3913c804df..1d68e985e6 100644[m
[1m--- a/examples/qos_sched/main.h[m
[1m+++ b/examples/qos_sched/main.h[m
[36m@@ -142,6 +142,8 @@[m [mextern struct rte_sched_port_params port_params;[m
 extern struct rte_sched_cman_params cman_params;[m
 extern struct rte_sched_subport_params subport_params[MAX_SCHED_SUBPORTS];[m
 [m
[32m+[m[32mextern struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];[m
[32m+[m
 int app_parse_args(int argc, char **argv);[m
 int app_init(void);[m
 [m

#include <assert.h>

#include "zeek-config.h"
// #include "device.h"

#include "Dpdk.h"
#include <iosource/Packet.h>
// #include <rte_per_lcore.h>
// #include <rte_lcore.h>
#include<iostream>
using namespace std;

using namespace iosource::pktsrc;



DpdkSource::~DpdkSource(){
	Close();
}

DpdkSource::DpdkSource(const std::string& path, bool is_live, const std::string& arg_kind){

	if ( ! is_live )
		Error("pf_ring source does not support offline input");

	current_filter = -1;
	props.path = path;
	props.is_live = is_live;

}

static int
lcore_hello(__rte_unused void *arg)
{
    unsigned lcore_id;
    lcore_id = rte_lcore_id();
    printf("hello from core %u\n", lcore_id);
    return 0;
}

static int lcore_main(){
    /* call lcore_hello() on the main lcore */
    lcore_hello(NULL);
    return 0;
}


iosource::PktSrc* DpdkSource::Instantiate(const std::string& path, bool is_live){
	char *my_argv[] = {
     "myprogram", // most programs will ignore this
     "-l 1",
     "-n 2",
     "-w 0000:00:19.0",
     NULL
	};

    int ret;
    unsigned lcore_id;

    /* Initialize the Environment Abstraction Layer (EAL). */
    ret = rte_eal_init(3, my_argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    
    std::cout << "path : " << path;     // test is device id

    /* Creates a new mempool in memory to hold the mbufs. */
    struct rte_mempool *mbuf_pool;
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize the single port available */
    uint16_t portid = 0;
    if (port_init(portid, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);


    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
    

    /* call lcore_hello() on the main lcore */

    lcore_main();
}


void DpdkSource::Open(){

}


void DpdkSource::Close(){
	//last_burst = 0;
	Closed();
}


/* Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{

    struct rte_eth_conf port_conf;
    port_conf.rxmode.max_rx_pkt_len = RTE_ETHER_MAX_LEN;

    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    if (!rte_eth_dev_is_valid_port(port))
        return -1;
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
                port, strerror(-retval));
        return retval;
    }
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;
    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }
    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;
    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);
    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;
    return 0;
}
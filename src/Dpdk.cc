#include <assert.h>
#include "zeek-config.h"
#include "Dpdk.h"
#include <iostream>


using namespace std;
using namespace iosource::pktsrc;


DpdkSource::~DpdkSource(){
	Close();
}

DpdkSource::DpdkSource(const std::string& path, bool is_live){

    if ( ! is_live )
    	Error("Dpdk source does not support offline input");

    current_filter = -1;
    props.path = path;
    props.is_live = is_live;
    goOverBurst = 0;

}


iosource::PktSrc* DpdkSource::Instantiate(const std::string& path, bool is_live){
    return new DpdkSource(path, is_live);
}


bool DpdkSource::ExtractNextPacket(Packet* pkt){
	/* You should never call this function, call burst instead */
	/* It is possible to change the implementation to return one packet */
	/* after calling this function, but dpdk should use bursts */
	return false;
}

void DpdkSource::DoneWithPacket(){
    // after finishing the last bit of the burst
    goOverBurst = 0;
}

bool DpdkSource::PrecompileFilter(int index, const std::string& filter){
	return PktSrc::PrecompileBPFFilter(index, filter);
}

bool DpdkSource::SetFilter(int index){
	/* Uh, DPDK has this option? */
	return true;
}

void DpdkSource::Statistics(Stats* s){
}


static int
lcore_hello(__rte_unused void *arg){
    unsigned lcore_id;
    lcore_id = rte_lcore_id();
    printf("hello from core %u\n", lcore_id);
    return 0;
}
static int lcore_main(){
    // call lcore_hello() on the main lcore
    lcore_hello(NULL);
    return 0;
}


void DpdkSource::Open(){
    char *my_argv[] = {
    "myprogram", // most programs will ignore this
    "-d", "/usr/local/lib/dpdk/pmds-21.0",
    "-l", "1",
    "-n","4",
    "-a", "0000:02:00.0",
	};

    int ret;
    unsigned lcore_id;

    /* Initialize the Environment Abstraction Layer (EAL). */
    ret = rte_eal_init(RTE_DIM(my_argv), my_argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    
    // std::cout << "path : " << path;     // test is device id

    /* Creates a new mempool in memory to hold the mbufs. */
    struct rte_mempool *mbuf_pool;
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");


    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
    
    
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE, port = 0;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(port))
        printf("Error: port not valid");

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
    }

    printf("tx offload capa = 0x%" PRIx64 "\n", dev_info.tx_offload_capa);

    struct rte_eth_conf port_conf = {0};
    port_conf.rxmode.max_rx_pkt_len = RTE_ETHER_MAX_LEN;


    printf("default port_conf.txmode.offloads = 0x%" PRIx64 "\n", port_conf.txmode.offloads);

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE){
        printf("\nOk: tx offload supported \n");
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        printf("\nError: rte_eth_dev_configure failed code = %d\n", retval);
    
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);

    if (retval != 0)
        printf("Error: rte_eth_dev_adjust_nb_rx_tx_desc failed code = %d\n", retval);

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            printf("Error: rte_eth_rx_queue_setup failed code = %d\n", retval);
    }

    struct rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            printf("Error: rte_eth_tx_queue_setup failed\n\n");
    }



    /* call lcore_hello() on the main lcore */
    lcore_main();
}

void DpdkSource::Close(){
	//last_burst = 0;
	Closed();
}


int  DpdkSource::ExtractNextBurst(Packet pbufs[MAX_PKT_BURST]){

    /* Get burst of RX packets, from first port of pair. */    /// t1
    const uint16_t n_pkts = rte_eth_rx_burst(0, 0, bufs, MAX_PKT_BURST);  // hard coded the port
    goOverBurst = n_pkts;					// d1 = now - t1 , s peed = n_pkts*64B/d >> plot this over time

	for(int i=0;i<n_pkts;i++){
		BuffertToPacket(bufs[i], &pbufs[i]);      // compare d2 to d1,  at what point the plugin crashes? 
    }
    
	return n_pkts;
}


void  DpdkSource::BuffertToPacket(struct rte_mbuf* buf, Packet* pkt){
	if(buf == NULL || pkt == NULL)
		return;

	pkt_timeval ts = {0, 0};
	u_char* data = rte_pktmbuf_mtod(buf, u_char*);
	std::string tag = "";
    

	pkt->Init(1, &ts, rte_pktmbuf_data_len(buf), rte_pktmbuf_pkt_len(buf), data, false, tag); //  copy = true: the constructor will make an internal copy of data, so that the caller can release its version.
}
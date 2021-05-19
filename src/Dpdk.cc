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
    NumQ = std::stoi(path);
}


iosource::PktSrc* DpdkSource::Instantiate(const std::string& path, bool is_live){
    return new DpdkSource(path, is_live);
}


bool DpdkSource::ExtractNextPacket(Packet* pkt){

    // /* Get burst of RX packets, from first port of pair. */    /// t1
    // printf("ExtractNextPacket(   )\n");
    while (true){
        for (int j = 0; j < NumQ; j++){
            const uint16_t n_pkts = rte_eth_rx_burst(0, j, bufs, BURST_SIZE);  // hard coded the port
            if (n_pkts == 0){ 			
                return false;
            }else{
                printf("New burst %d\n", n_pkts);
                stats.received+=n_pkts;
                for (int i = 0; i < n_pkts; i++){
                    pkt_timeval ts = {0, 0};
                    u_char* data = rte_pktmbuf_mtod(bufs[i], u_char*);

                    std::string tag = "";
                    pkt->Init(props.link_type, &ts, rte_pktmbuf_data_len(bufs[i]), rte_pktmbuf_pkt_len(bufs[i]), data, false, tag); //  copy = true: the constructor will make an internal copy of data, so that the caller can release its version.
                    rte_pktmbuf_free(bufs[i]);
                }
                return true;
            }
        }
    }
	return false;
}

void DpdkSource::DoneWithPacket(){
    printf("Done Burst\n");   
}

bool DpdkSource::PrecompileFilter(int index, const std::string& filter){
	return PktSrc::PrecompileBPFFilter(index, filter);
}

bool DpdkSource::SetFilter(int index){
    current_filter = index;
	return true;
}

void DpdkSource::Statistics(Stats* s){

    if(!props.is_live){
	
    	s->received = s->dropped = s->link = s->bytes_received = 0;
    
    }else{
	    rte_eth_stats_get(0, &dpdk_stats);
        s->received = dpdk_stats.ipackets;   // or stats.received;
        s->bytes_received = dpdk_stats.ibytes;
        s->dropped = dpdk_stats.imissed;
	}

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

    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(0))
        printf("Error: port not valid");

    int retval = rte_eth_dev_info_get(0, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", 0, strerror(-retval));
    }

    struct rte_eth_conf port_conf = {0};
    port_conf.rxmode.max_rx_pkt_len = RTE_ETHER_MAX_LEN;

    /* Configure the Ethernet device. */
    const uint16_t tx_rings = 0;
    
    retval = rte_eth_dev_configure(0, NumQ, tx_rings, &port_conf);
    if (retval != 0)
        printf("\nError: rte_eth_dev_configure failed code = %d\n", retval);
    
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(0, &nb_rxd, &nb_txd);
    if (retval != 0)
        printf("\nError: rte_eth_dev_adjust_nb_rx_tx_desc failed code = %d\n", retval);
    
    struct rte_eth_rxconf rxconf = {0};
    rxconf = dev_info.default_rxconf;


    for (int q = 0; q < NumQ; q++) {         // single rx queue per worker for now
        retval = rte_eth_rx_queue_setup(0, q, nb_rxd, rte_eth_dev_socket_id(0), &rxconf, mbuf_pool);  // option to pin cpu to queue? now same core
        if (retval < 0)
            printf("\nError: rte_eth_rx_queue_setup failed code = %d\n", retval);
    }
 

    // struct rte_eth_txconf txconf = {0};
    // txconf = dev_info.default_txconf;
    // txconf.offloads = port_conf.txmode.offloads;
    // for (int q = 0; q < tx_rings; q++) {
    //     retval = rte_eth_tx_queue_setup(0, q, nb_txd, rte_eth_dev_socket_id(0), &txconf);
    //     if (retval < 0)
    //         printf("\nError: rte_eth_tx_queue_setup failed code = %d\n", retval);
    // }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(0);
    if (retval < 0)
        printf("Error: rte_eth_dev_start failed code = %d\n", retval);

    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(0, &addr);
    if (retval != 0)
        printf("Error: rte_eth_macaddr_get failed code = %d\n", retval);

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            0,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);
    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(0);
    if (retval != 0)
        printf("Error: rte_eth_promiscuous_enable failed code = %d\n", retval);


    props.is_live = true;
	props.link_type = DLT_EN10MB;
    
    Opened(props);
}

void DpdkSource::Close(){
	Closed();
}

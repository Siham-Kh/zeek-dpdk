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
}


iosource::PktSrc* DpdkSource::Instantiate(const std::string& path, bool is_live){
    return new DpdkSource(path, is_live);
}


bool DpdkSource::ExtractNextPacket(Packet* pkt){

    // /* Get burst of RX packets, from first port of pair. */    /// t1
    // printf("ExtractNextPacket(   )\n");
    while (true){
        const uint16_t n_pkts = rte_eth_rx_burst(0, 0, bufs, 10);  // hard coded the port
        if (n_pkts == 0){ 			
            return false;
        }else{
            printf("new packet %d\n", n_pkts);
            stats.received+=n_pkts;
            for (int i =0; i < n_pkts; i++){
                pkt_timeval ts = {0, 0};
	            u_char* data = rte_pktmbuf_mtod(bufs[i], u_char*);

               	// struct rte_ether_hdr *eth_hdr = {0};
                // eth_hdr = rte_pktmbuf_mtod(bufs[i], struct ether_hdr *);
	            // struct rte_ether_addr src = eth_hdr->s_addr;
	            // struct rte_ether_addr dst = eth_hdr->d_addr;

	            // printf("**** from MAC : %02X:%02X:%02X:%02X:%02X:%02X \n", src.addr_bytes[0],src.addr_bytes[1],src.addr_bytes[2],src.addr_bytes[3],src.addr_bytes[4],src.addr_bytes[5]);
	            // printf("**** to MAC: %02X:%02X:%02X:%02X:%02X:%02X \n", dst.addr_bytes[0],dst.addr_bytes[1],dst.addr_bytes[2],dst.addr_bytes[3],dst.addr_bytes[4],dst.addr_bytes[5]);


	            std::string tag = "";
	            pkt->Init(props.link_type, &ts, rte_pktmbuf_data_len(bufs[i]), rte_pktmbuf_pkt_len(bufs[i]), data, false, tag); //  copy = true: the constructor will make an internal copy of data, so that the caller can release its version.
                rte_pktmbuf_free(bufs[i]);
                printf("freed\n");
            }
            return true;
        }
    }
	return false;
}

void DpdkSource::DoneWithPacket(){
    printf("DoneWithPacket()\n");   
}

bool DpdkSource::PrecompileFilter(int index, const std::string& filter){
	return PktSrc::PrecompileBPFFilter(index, filter);
}

bool DpdkSource::SetFilter(int index){
	/* Uh, DPDK has this option? */
    current_filter = index;
	return true;
}

void DpdkSource::Statistics(Stats* s){

    if(!props.is_live)
		s->received = s->dropped = s->link = s->bytes_received = 0;

    
    else{
		// TODO check stats/rte_eth_stats. Not available for every NIC
		rte_eth_stats_get(port, &dpdk_stats);
		if(dpdk_stats.ipackets == 0 && stats.received > 0){
			fprintf(stderr, "[+] Cannot get stats directly from DPDK\n");

			s->received = stats.received;
			s->bytes_received = stats.bytes_received;
			s->dropped = stats.dropped;
		}

		else{
			s->received = dpdk_stats.ipackets;
			s->bytes_received = dpdk_stats.ibytes;
			s->dropped = dpdk_stats.imissed;
		}
	}

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
    const uint16_t rx_rings = 1, tx_rings = 1;
    retval = rte_eth_dev_configure(0, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        printf("\nError: rte_eth_dev_configure failed code = %d\n", retval);
    
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(0, &nb_rxd, &nb_txd);
    if (retval != 0)
        printf("\nError: rte_eth_dev_adjust_nb_rx_tx_desc failed code = %d\n", retval);
    
    struct rte_eth_rxconf rxconf = {0};
    rxconf = dev_info.default_rxconf;


    for (int q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(0, q, nb_rxd, rte_eth_dev_socket_id(0), &rxconf, mbuf_pool);
        if (retval < 0)
            printf("\nError: rte_eth_rx_queue_setup failed code = %d\n", retval);
    }
 

    struct rte_eth_txconf txconf = {0};
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (int q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(0, q, nb_txd, rte_eth_dev_socket_id(0), &txconf);
        if (retval < 0)
            printf("\nError: rte_eth_tx_queue_setup failed code = %d\n", retval);
    }

    lcore_main();

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


    /* call lcore_hello() on the main lcore */
    lcore_main();

    props.is_live = true;
	props.link_type = DLT_EN10MB;
    
    Opened(props);
}

void DpdkSource::Close(){
	Closed();
}

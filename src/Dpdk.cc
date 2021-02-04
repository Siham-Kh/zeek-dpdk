#include <assert.h>

#include "zeek-config.h"
// #include "device.h"

#include "Dpdk.h"
#include <iosource/Packet.h>
// #include <rte_per_lcore.h>
// #include <rte_lcore.h>


using namespace iosource::pktsrc;



DpdkSource::~DpdkSource(){
	Close();
}

DpdkSource::DpdkSource(const std::string& path, bool is_live){

	if ( ! is_live )
		Error("pf_ring source does not support offline input");

	// // kind = arg_kind;
	// // current_filter = -1;
	// props.path = path;
	// props.is_live = is_live;

}

static int
lcore_hello(__rte_unused void *arg)
{
    unsigned lcore_id;

    lcore_id = rte_lcore_id();
    printf("hello from core %u\n", lcore_id);
    return 0;
}

iosource::PktSrc* DpdkSource::Instantiate(const std::string& path, bool is_live){
	char *my_argv[] = {
     "myprogram", // most programs will ignore this
     "-l 3",
     "-n 4",
     NULL
	};

    int ret;
    unsigned lcore_id;
    ret = rte_eal_init(3, my_argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    /* call lcore_hello() on every worker lcore */
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
    }
    /* call it on main lcore too */
    lcore_hello(NULL);
    rte_eal_mp_wait_lcore();
}
void DpdkSource::Open(){
	// /* We need to configure it and start it */
	// // struct rte_eth_link link;
	
    // int ret = rte_eal_init(0, NULL);
    // if (ret < 0)
    //     rte_panic("Cannot init EAL\n");

    // printf("hello from core %u\n", ret);

}

// bool DpdkSource::Configure(){
// 	return !config_device(port,RX_QUEUES,TX_QUEUES,RX_DESC,TX_DESC, DROP_EN, RSS_EN, OFFLOAD_DIS, STRIPVLAN_EN, RSS_MASK, MBUF_ELEMENTS-1, MBUF_SIZE*1024);
// }

void DpdkSource::Close(){
	//last_burst = 0;
	Closed();
}

// void DpdkSource::DoneWithPacket(){
// 	/* Just free the packets in the mbuf */
// 	//for(int i=0;i<last_burst_size;i++)
// 	// 	rte_pktmbuf_free_export(last_burst[0]);
// 	// last_burst_size = 0;
// }

// bool DpdkSource::PrecompileFilter(int index, const std::string& filter){
// 	return PktSrc::PrecompileBPFFilter(index, filter);
// }

// bool DpdkSource::SetFilter(int index){
// 	/* Uh, DPDK has this option? */
// 	return true;
// }

// void DpdkSource::Statistics(Stats* s){
// 	if(!props.is_live)
// 		s->received = s->dropped = s->link = s->bytes_received = 0;

// 	else{
// 		// TODO check stats/rte_eth_stats. Not available for every NIC
// 		rte_eth_stats_get(port, &dpdk_stats);
// 		if(dpdk_stats.ipackets == 0 && stats.received > 0){
// 			fprintf(stderr, "[+] Cannot get stats directly from DPDK\n");

// 			s->received = stats.received;
// 			s->bytes_received = stats.bytes_received;
// 			s->dropped = stats.dropped;
// 		}

// 		else{
// 			s->received = dpdk_stats.ipackets;
// 			s->bytes_received = dpdk_stats.ibytes;
// 			s->dropped = dpdk_stats.imissed;
// 		}
// 	}
// }




// bool DpdkSource::ExtractNextPacket(Packet* pkt){
// 	/* You should never call this function, call burst instead */
// 	/* It is possible to change the implementation to return one packet */
// 	/* after calling this function, but dpdk should use bursts */
// 	return false;
// }

// int  DpdkSource::ExtractNextBurst(Packet bufs[MAX_PKT_BURST]){
// 	// int n_pkts = rte_eth_rx_burst_export(port, 0, last_burst, MAX_PKT_BURST);
// 	// stats.received+=n_pkts;
// 	// last_burst_size = n_pkts;

// 	// for(int i=0;i<n_pkts;i++)
// 	// 	ConvertToPacket(last_burst[i], &bufs[i]);
	
// 	// return n_pkts;
// }


// void  DpdkSource::ConvertToPacket(struct rte_mbuf* buf, Packet* pkt){
// 	if(buf == NULL || pkt == NULL)
// 		return;

// 	pkt_timeval ts = {current_time(true), 0};
// 	u_char* data = rte_pktmbuf_mtod(buf, u_char*);
		
// 	pkt->Init(props.link_type, &ts, rte_pktmbuf_data_len(buf), rte_pktmbuf_pkt_len(buf), data);
// }

// int DpdkSource::GetLastBurstSize(){
// 	// return last_burst_size;
// }
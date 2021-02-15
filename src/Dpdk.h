#ifndef IOSOURCE_PKTSRC_DPDK_SOURCE_H
#define IOSOURCE_PKTSRC_DPDK_SOURCE_H

#include <iosource/PktSrc.h>
#include <rte_ethdev.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32



#define RX_QUEUES 1
#define TX_QUEUES 0
#define RX_DESC 0
#define TX_DESC 0
#define DROP_EN 0 // drop packets if no descriptor available
#define RSS_EN 0 // enable RSS
#define OFFLOAD_DIS 0 // disable offloads
#define STRIPVLAN_EN 0 // strip vlan enable
#define RSS_MASK 0 
#define MBUF_ELEMENTS 8192 // optimal -> MBUF_ELEMENTS mod MBUF_SIZE = 0
#define MBUF_SIZE 2 // on KB
#define MAX_PKT_BURST 10

namespace iosource {
namespace pktsrc {

class DpdkSource : public iosource::PktSrc{

public:
	DpdkSource(const std::string& path, bool is_live, const std::string& arg_kind);
	~DpdkSource() override;

	static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
	// PktSrc interface.
	void Open() override;
	void Close() override;
	// bool ExtractNextPacket(Packet* pkt) override;
	// int ExtractNextBurst(Packet bufs[MAX_PKT_BURST]) ;
	// int GetLastBurstSize() ;
	// void DoneWithPacket() override;
	// bool PrecompileFilter(int index, const std::string& filter) override;
	// bool SetFilter(int index) override;
	// void Statistics(Stats* stats) override;


private:

	static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool);
	static int lcore_hello(__rte_unused void *arg);
	static int lcore_hello();

	Properties props;
	std::string kind;
	int current_filter;

};

}
}

#endif
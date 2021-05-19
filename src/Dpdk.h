#ifndef IOSOURCE_PKTSRC_DPDK_SOURCE_H
#define IOSOURCE_PKTSRC_DPDK_SOURCE_H


extern "C" {
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <errno.h>          // errorno
#include <unistd.h>         // close()
#include <linux/version.h>  // kernel version

#include <net/ethernet.h>      // ETH_P_ALL
#include <linux/if.h>          // ifreq
#include <linux/if_packet.h>   // AF_PACKET, etc.
#include <linux/sockios.h>     // SIOCSHWTSTAMP
#include <linux/net_tstamp.h>  // hwtstamp_config
#include <pcap.h>
}

#include <iosource/PktSrc.h>
#include <rte_ethdev.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <iosource/Packet.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64
#define RX_QUEUES 2  // number of queues
#define TX_QUEUES 1
#define RX_DESC 1024
#define TX_DESC 0
#define DROP_EN 0 // drop packets if no descriptor available
#define RSS_EN 0 // enable RSS
#define OFFLOAD_DIS 0 // disable offloads
#define STRIPVLAN_EN 0 // strip vlan enable
#define RSS_MASK 0 
#define MBUF_ELEMENTS 8192 // optimal -> MBUF_ELEMENTS mod MBUF_SIZE = 0
#define MBUF_SIZE 2 // on KB
#define MAX_PKT_BURST 10   // normally it's 64

namespace iosource {
namespace pktsrc {

class DpdkSource : public iosource::PktSrc{

public:
	DpdkSource(const std::string& path, bool is_live);
	~DpdkSource() override;

	static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
	// PktSrc interface.
	void Open();
	void Close();
	bool ExtractNextPacket(Packet* pkt);
	// int ExtractNextBurst(Packet bufs[MAX_PKT_BURST]);
	// int GetLastBurstSize() override;

	
	void DoneWithPacket();
	bool PrecompileFilter(int index, const std::string& filter) override;
	bool SetFilter(int index) override;
	void Statistics(Stats* stats) override;
	
private:

	static int lcore_hello(__rte_unused void *arg);
	static int lcore_hello();
	void BuffertToPacket(struct rte_mbuf* buf, Packet* pkt);

	Properties props;
	int current_filter;

	struct rte_mbuf *bufs[MAX_PKT_BURST];
	rte_eth_stats dpdk_stats;
	Stats stats;

	int goOverBurst;

	int NumQ;

};

}
}

#endif
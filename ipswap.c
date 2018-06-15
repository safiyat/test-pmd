#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_string_fns.h>
#include <rte_icmp.h>
#include <rte_flow.h>

#include "testpmd.h"
#define SRC_IP_1       81 
#define SRC_IP_2       0
#define SRC_IP_3       33
#define SRC_IP_4       7

/*static const char *
arp_op_name(uint16_t arp_op)
{
        switch (arp_op ) {
        case ARP_OP_REQUEST:
                return "ARP Request";
        case ARP_OP_REPLY:
                return "ARP Reply";
        case ARP_OP_REVREQUEST:
                return "Reverse ARP Request";
        case ARP_OP_REVREPLY:
                return "Reverse ARP Reply";
        case ARP_OP_INVREQUEST:
                return "Peer Identify Request";
        case ARP_OP_INVREPLY:
                return "Peer Identify Reply";
        default:
                break;
        }
        return "Unkwown ARP op";
}*/

static void
ipv4_addr_to_dot(uint32_t be_ipv4_addr, char *buf)
{
    uint32_t ipv4_addr;

    ipv4_addr = rte_be_to_cpu_32(be_ipv4_addr);
    sprintf(buf, "%d.%d.%d.%d", (ipv4_addr >> 24) & 0xFF,
        (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
        ipv4_addr & 0xFF);
}

/*static void
ether_addr_dump(const char *what, const struct ether_addr *ea)
{
    char buf[ETHER_ADDR_FMT_SIZE];

    ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, ea);
    if (what)
        printf("%s", what);
    printf("%s", buf);
}
*/
static void
ipv4_addr_dump(const char *what, uint32_t be_ipv4_addr)
{
    char buf[16];

    ipv4_addr_to_dot(be_ipv4_addr, buf);
    if (what)
        printf("%s", what);
    printf("%s", buf);
}

static uint16_t
ipv4_hdr_cksum(struct ipv4_hdr *ip_h)
{
        uint16_t *v16_h;
        uint32_t ip_cksum;

        /*
         * Compute the sum of successive 16-bit words of the IPv4 header,
         * skipping the checksum field of the header.
         */
        v16_h = (unaligned_uint16_t *) ip_h;
        ip_cksum = v16_h[0] + v16_h[1] + v16_h[2] + v16_h[3] +
                v16_h[4] + v16_h[6] + v16_h[7] + v16_h[8] + v16_h[9];

        /* reduce 32 bit checksum to 16 bits and complement it */
        ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
        ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
        ip_cksum = (~ip_cksum) & 0x0000FFFF;
        return (ip_cksum == 0) ? 0xFFFF : (uint16_t) ip_cksum;
}

#define is_multicast_ipv4_addr(ipv4_addr) \
        (((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)


/*
 * MAC swap forwarding mode: Swap the source and the destination Ethernet
 * addresses of packets before forwarding them.
 */
static void
pkt_burst_mac_swap(struct fwd_stream *fs)
{
        /* Start of testing variables */
        struct ipv4_hdr *ip_hdr;

        uint32_t ip_addr;
        uint32_t cksum;

        struct rte_mbuf  *ping_burst[MAX_PKT_BURST];
        uint16_t nb_pings = 0;
        // Arp Stuff
        uint16_t arp_op;
        uint16_t arp_pro;
        struct arp_hdr  *arp_h;
        // struct vlan_hdr *vlan_h;
        int l2_len;

        /* End of testing variables */
        
        struct rte_mbuf  *pkts_burst[MAX_PKT_BURST];
        struct rte_port  *txp;
        struct rte_mbuf  *mb;
        struct ether_hdr *eth_hdr;
        // struct ether_addr addr;
        struct ether_addr eth_addr;
        struct icmp_hdr *icmp_h;

        // uint16_t nb_replies;
        uint16_t nb_rx;
        uint16_t nb_tx;
        uint16_t i;
        uint32_t retry;
        uint64_t ol_flags = 0;
        uint32_t src_ip = SRC_IP_1 | (SRC_IP_2 << 8) | (SRC_IP_3 << 16) | (SRC_IP_4 << 24);
        uint16_t eth_type;
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
        uint64_t start_tsc;
        uint64_t end_tsc;
        uint64_t core_cycles;
#endif
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
        start_tsc = rte_rdtsc();
#endif
        /*
         * Receive a burst of packets and forward them.
         */
        nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, pkts_burst,
                                 nb_pkt_per_burst);
        if (unlikely(nb_rx == 0))
                return;

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
        fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif
        fs->rx_packets += nb_rx;
        txp = &ports[fs->tx_port];
        if (txp->tx_ol_flags & TESTPMD_TX_OFFLOAD_INSERT_VLAN)
                ol_flags = PKT_TX_VLAN_PKT;
        if (txp->tx_ol_flags & TESTPMD_TX_OFFLOAD_INSERT_QINQ)
                ol_flags |= PKT_TX_QINQ_PKT;
        //nb_replies = 0;
        for (i = 0; i < nb_rx; i++) {
                if (likely(i < nb_rx - 1))
                        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + 1],
                                                       void *));
                mb = pkts_burst[i];
                eth_hdr = rte_pktmbuf_mtod(mb, struct ether_hdr *);
                ip_hdr = rte_pktmbuf_mtod_offset(mb, struct ipv4_hdr *, sizeof(struct ether_hdr));
                eth_type = RTE_BE_TO_CPU_16(eth_hdr->ether_type);
                l2_len = sizeof(struct ether_hdr);
                //ether_addr_copy(&peer_eth_addrs[fs->peer_addr], &eth_hdr->d_addr);
                //ether_addr_copy(&ports[fs->tx_port].eth_addr, &eth_hdr->s_addr);
                /*
                 * Check if packet is a ICMP echo request.
                 */
                icmp_h = (struct icmp_hdr *) ((char *)ip_hdr + sizeof(struct ipv4_hdr));
                if ((ip_hdr->next_proto_id == IPPROTO_ICMP) &&
                        (icmp_h->icmp_type == IP_ICMP_ECHO_REQUEST) &&
                        (icmp_h->icmp_code == 0)) {
                        nb_pings = 0;
                        printf("\nGot Ping request from ");
                        ipv4_addr_dump(":", ip_hdr->src_addr);
                        ether_addr_copy(&eth_hdr->s_addr, &eth_addr);
                        ether_addr_copy(&eth_hdr->d_addr, &eth_hdr->s_addr);
                        ether_addr_copy(&eth_addr, &eth_hdr->d_addr);
                        ip_addr = ip_hdr->src_addr;
                        if (is_multicast_ipv4_addr(ip_hdr->dst_addr)) {
                                uint32_t ip_src;
                                ip_src = rte_be_to_cpu_32(ip_addr);
                                if ((ip_src & 0x00000003) == 1)
                                        ip_src = (ip_src & 0xFFFFFFFC) | 0x00000002;
                                else
                                        ip_src = (ip_src & 0xFFFFFFFC) | 0x00000001;
                                ip_hdr->src_addr = rte_cpu_to_be_32(ip_src);
                                ip_hdr->dst_addr = ip_addr;
                                ip_hdr->hdr_checksum = ipv4_hdr_cksum(ip_hdr);
                        } else {
                                ip_hdr->src_addr = ip_hdr->dst_addr;
                                ip_hdr->dst_addr = ip_addr;
                        }
                        // ip_hdr->src_addr = ip_hdr->dst_addr;
                        // ip_hdr->dst_addr = ip_addr;
                        icmp_h->icmp_type = IP_ICMP_ECHO_REPLY;
                        cksum = ~icmp_h->icmp_cksum & 0xffff;
                        cksum += ~htons(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
                        cksum += htons(IP_ICMP_ECHO_REPLY << 8);
                        cksum = (cksum & 0xffff) + (cksum >> 16);
                        cksum = (cksum & 0xffff) + (cksum >> 16);
                        icmp_h->icmp_cksum = ~cksum;

                        ping_burst[nb_pings++] = mb; //used to be "= pkt"
                        // pkts_burst[nb_replies++] = pkt;
                        //nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, ping_burst, nb_pings);
                        nb_tx = rte_eth_tx_burst(fs->rx_port, fs->tx_queue, ping_burst, nb_pings);
                        fs->tx_packets += nb_tx;
                }
                else if (eth_type == ETHER_TYPE_ARP) {
                        nb_pings = 0;
                        ipv4_addr_dump("\nARP sip=", ip_hdr->src_addr);
                        arp_h = (struct arp_hdr *) ((char *)eth_hdr + l2_len);
                        arp_op = RTE_BE_TO_CPU_16(arp_h->arp_op);
                        arp_pro = RTE_BE_TO_CPU_16(arp_h->arp_pro);
                        
                        if ((RTE_BE_TO_CPU_16(arp_h->arp_hrd) !=
                             ARP_HRD_ETHER) ||
                            (arp_pro != ETHER_TYPE_IPv4) ||
                            (arp_h->arp_hln != 6) ||
                            (arp_h->arp_pln != 4)
                            ) {
                                rte_pktmbuf_free(mb);
                                continue;
                        }
                        if (arp_op != ARP_OP_REQUEST) {
                                rte_pktmbuf_free(mb);
                                continue;
                        }

                        /* Use source MAC address as destination MAC address. */
                        ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
                        /* Set source MAC address with MAC address of TX port */
                        ether_addr_copy(&ports[fs->tx_port].eth_addr,
                                        &eth_hdr->s_addr);
                        arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
                        ether_addr_copy(&arp_h->arp_data.arp_tha, &eth_addr);
                        ether_addr_copy(&arp_h->arp_data.arp_sha, &arp_h->arp_data.arp_tha);
                        ether_addr_copy(&eth_hdr->s_addr, &arp_h->arp_data.arp_sha);
                        /* Swap IP addresses in ARP payload */
                        ip_addr = arp_h->arp_data.arp_sip;
                        arp_h->arp_data.arp_sip = arp_h->arp_data.arp_tip;
                        arp_h->arp_data.arp_tip = ip_addr;
                        // pkts_burst[nb_replies++] = mb;
                        ping_burst[nb_pings++] = mb;
                        nb_tx = rte_eth_tx_burst(fs->rx_port, fs->tx_queue, ping_burst, nb_pings);
                        fs->tx_packets += nb_tx;
                        continue;
                }
                else {
                        
                    ether_addr_copy(&peer_eth_addrs[fs->peer_addr], &eth_hdr->d_addr);
                    ether_addr_copy(&ports[fs->tx_port].eth_addr, &eth_hdr->s_addr);

                    /* Seems to be the correct way of getting the ipv4_hdr struct, compared to the (commented) function above.
                    * Found similar method at http://dpdk.org/browse/dpdk/tree/examples/l3fwd-vf/main.c lines 458-460. */
                    ip_hdr->dst_addr = ip_hdr->src_addr;
                    ip_hdr->src_addr = src_ip;
                    rte_eth_macaddr_get(fs->tx_port, &eth_hdr->s_addr);
                    /* End of testing */

                    mb->ol_flags = ol_flags;
                    mb->l2_len = sizeof(struct ether_hdr);
                    mb->l3_len = sizeof(struct ipv4_hdr);
                    mb->vlan_tci = txp->tx_vlan_id;
                    mb->vlan_tci_outer = txp->tx_vlan_id_outer;
                }
        }
        nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_rx);
        /*
         * Retry if necessary
         */
        if (unlikely(nb_tx < nb_rx) && fs->retry_enabled) {
                retry = 0;
                while (nb_tx < nb_rx && retry++ < burst_tx_retry_num) {
                        rte_delay_us(burst_tx_delay_time);
                        nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
                                        &pkts_burst[nb_tx], nb_rx - nb_tx);
                }
        }
        fs->tx_packets += nb_tx;
#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
        fs->tx_burst_stats.pkt_burst_spread[nb_tx]++;
#endif
        if (unlikely(nb_tx < nb_rx)) {
                fs->fwd_dropped += (nb_rx - nb_tx);
                do {
                        rte_pktmbuf_free(pkts_burst[nb_tx]);
                } while (++nb_tx < nb_rx);
        }
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
        end_tsc = rte_rdtsc();
        core_cycles = (end_tsc - start_tsc);
        fs->core_cycles = (uint64_t) (fs->core_cycles + core_cycles);
#endif
}
struct fwd_engine ip_swap_engine = {
        .fwd_mode_name  = "ipswap",
        .port_fwd_begin = NULL,
        .port_fwd_end   = NULL,
        .packet_fwd     = pkt_burst_mac_swap,
};

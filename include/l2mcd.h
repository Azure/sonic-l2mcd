/*
 * Copyright 2019 Broadcom.  The term “Broadcom” refers to Broadcom Inc. and/or
 * its subsidiaries.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __L2MCD_H__
#define __L2MCD_H__

#include <sys/socket.h>
#include <sys/un.h>
#include <event2/event.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include "applog.h"
#include "avl.h"
#include "l2mcd_data_struct.h"
#include "l2mcd_ipc.h"

#define L2MCD_MSG_SOCK_NAME "/var/run/l2mcd_msg.sock"
#define L2MCD_PORTDB_PHYIF_START_IDX 4096
#define L2MCD_PORTDB_PHYIF_MAX_IDX 512
#define L2MCD_PORTDB_PHYIF_LAST_IDX (L2MCD_PORTDB_PHYIF_START_IDX+L2MCD_PORTDB_PHYIF_MAX_IDX-1)
#define L2MCD_PORTDB_LAGIF_START_IDX (L2MCD_PORTDB_PHYIF_LAST_IDX+1)
#define L2MCD_PORTDB_LAGIF_MAX_IDX 10000
#define L2MCD_PORTDB_LAGIF_LAST_INDEX (L2MCD_PORTDB_LAGIF_START_IDX+L2MCD_PORTDB_LAGIF_MAX_IDX-1)
#define L2MCD_100MS_TIMEOUT      100000

#define L2MCD_IFINDEX_IS_PHY(x) ((x>=L2MCD_PORTDB_PHYIF_START_IDX) && x<=L2MCD_PORTDB_PHYIF_LAST_IDX)
#define L2MCD_IFINDEX_IS_LAG(x) ((x>=L2MCD_PORTDB_LAGIF_START_IDX) && x<=L2MCD_PORTDB_LAGIF_LAST_INDEX)
#define L2MCD_PORTDB_HASH_SIZE     8192
#define L2MCD_MAX_INTERFACES       8192
#define L2MCD_DEFAULT_VRF_IDX      0
#define L2MCD_IPV4_AFI             1
#define L2MCD_IPV6_AFI             2
#define L2MCD_AFI_MAX              1
#define MCAST_IPV4_AFI L2MCD_IPV4_AFI
#define MCAST_IPV6_AFI L2MCD_IPV6_AFI
#define L2MCD_LIBEV_PRIO_QUEUES 2
#define L2MCD_LIBEV_HIGH_PRI_Q  0
#define L2MCD_LIBEV_LOW_PRI_Q   1

#define L2MCD_DEFAULT_KEY_SEPARATOR ":"
#define L2MCD_STATE_KEY_SEPARATOR "|"
#define L2MCD_100MS_TIMEOUT 100000 
#define L2MCD_VLAN_MAX 4095
#define L2MCD_RX_BUFFER_SIZE  2048


#define L2MCD_BF_RD(reg, off, mask)   (((reg) & (mask)) >> (off))
#define BITFLD(offset,width)    (((1<<(width))-1) << (offset))
#define L2MCD_IFIDX_TYPE_OFFSET       26
#define L2MCD_IFIDX_TYPE_MASK         BITFLD(26, 6)   /* max 64 if types */
#define L2MCD_IFIDX_IFID_OFFSET       0
#define L2MCD_IFIDX_IFID_MASK         BITFLD(0, 16)

#define L2MCD_IFIDX_TYPE(ifidx)   L2MCD_BF_RD(ifidx, L2MCD_IFIDX_TYPE_OFFSET, L2MCD_IFIDX_TYPE_MASK)
#define V2BF(value, off, mask)  (((value) << (off)) & (mask))
#define L2MCD_IFIDX_TYPE_BF(type) V2BF((type), L2MCD_IFIDX_TYPE_OFFSET, L2MCD_IFIDX_TYPE_MASK)
#define L2MCD_IFIDX_IFID_BF(ifid) V2BF((ifid), L2MCD_IFIDX_IFID_OFFSET, L2MCD_IFIDX_IFID_MASK)

#define L2MCD_VLAN_BM_POS(x) (x&31)
#define L2MCD_VLAN_BM_IDX(x) (x>>5)
#define L2MCD_IS_BIT_SET(val, pos) ((val) & (1<<(pos)))
#define L2MCD_BIT_SET(val, pos)  ((val) |= (1<<(pos)))
#define L2MCD_BIT_CLEAR(val, pos)  ((val) &= ~(1<<(pos)))
#define L2MCD_VLAN_BM_SET(bm,x) L2MCD_BIT_SET(bm[L2MCD_VLAN_BM_IDX(x)],L2MCD_VLAN_BM_POS(x)) 
#define L2MCD_VLAN_BM_CLR(bm,x) L2MCD_BIT_CLEAR(bm[L2MCD_VLAN_BM_IDX(x)],L2MCD_VLAN_BM_POS(x)) 
#define L2MCD_VLAN_IS_BM_SET(bm,x) L2MCD_IS_BIT_SET(bm[L2MCD_VLAN_BM_IDX(x)],L2MCD_VLAN_BM_POS(x)) 


typedef void* L2MCD_AVL_TREE;
typedef uint32_t L2MCD_AVL_NODE;

typedef struct l2mcd_if_tree_s
{
    L2MCD_AVL_NODE node;
    uint32_t kif;
    uint32_t ifid;
    int sock_fd;
    char iname[L2MCD_IFNAME_SIZE];
    int oper;
    int po_id;
    int rx_pkts;
    uint32_t sock_pkts;
    uint32_t sock_drops;
    uint32_t bm[128];
    struct event *igmp_rx_event;
} l2mcd_if_tree_t;

typedef struct
{
    uint16_t no_of_sockets;
    uint64_t timer_100ms;
    uint64_t pkt_rx;
    uint64_t ipc;
    uint64_t netlink;
} L2MCD_LIBEV_STATS;

typedef struct 
{
    uint32_t tot_pkts;
    uint32_t igmp_pkts;
    uint32_t pim_pkts;
    uint32_t non_igmp_pkts;
    uint32_t no_aux;
    uint32_t no_tag;
    uint32_t inv_tags;
} L2MCD_RX_SOCK_STATS;

typedef struct L2MCD_CONTEXT {
    /* Libevent base to monitor all socket Fd's*/
    struct event_base   *evbase;
    /*Fd's used by socket*/
    int                 ipc_fd;         //communication with l2mcdmgr, etc.
    int                 igmp_rx_fd;     //Recieve socket for snooped packets
    int                 igmp_tx_fd;     //Tx Socket 
    uint32_t            l2mcd_msg_fd;
    uint32_t            nl_fd;
    L2MCD_LIBEV_STATS   libev_stats;
    L2MCD_RX_SOCK_STATS rx_stats;
    FILE                *cmd_fp;
    FILE                *pkt_fp;
    FILE                *init_fp;
    uint8_t             vlan_log_mask;
    uint8_t             fwk_dbg_mode;
    uint8_t             dbg_to_sys_log;
    uint8_t             dbg_vlan_log_all;
    char                l2mcd_global_mac[ETHER_ADDR_LEN];
    uint8_t             pktlog[L2MCD_VLAN_MAX+1];
    uint32_t            ifindex_to_kifindex[L2MCD_PORTDB_PHYIF_MAX_IDX];
    uint32_t            curr_dbg_level;
    char                rx_buf[L2MCD_RX_BUFFER_SIZE];
    L2MCD_AVL_TREE      kif_to_if_tree;
    L2MCD_AVL_TREE      if_to_kif_tree;
    int                 rx_is_l2_sock;
    int                 portdb_pending_count;
    uint8_t             port_init_done;
} L2MCD_CONTEXT;


extern L2MCD_CONTEXT l2mcd_context;
#define g_l2mcd_evbase                    l2mcd_context.evbase
#define g_l2mcd_ipc_handle                l2mcd_context.ipc_fd
#define g_l2mcd_igmp_rx_handle            l2mcd_context.igmp_rx_fd
#define g_l2mcd_igmp_tx_handle            l2mcd_context.igmp_tx_fd
#define g_l2mcd_igmp_msg_handle           l2mcd_context.l2mcd_msg_fd
#define g_l2mcd_nl_fd                     l2mcd_context.nl_fd
#define g_l2mcd_stats_libev_no_of_sockets l2mcd_context.libev_stats.no_of_sockets
#define g_l2mcd_stats_libev_ipc           l2mcd_context.libev_stats.ipc
#define g_l2mcd_stats_libev_timer         l2mcd_context.libev_stats.timer_100ms
#define g_l2mcd_cmd_fp                    l2mcd_context.cmd_fp
#define g_l2mcd_fwk_dbg_mode              l2mcd_context.fwk_dbg_mode
#define g_l2mcd_pkt_fp                    l2mcd_context.pkt_fp
#define g_l2mcd_init_fp                   l2mcd_context.init_fp
#define g_l2mcd_vlan_log_mask             l2mcd_context.vlan_log_mask
#define g_l2mcd_global_mac                l2mcd_context.l2mcd_global_mac
#define g_l2mcd_pkt_log                   l2mcd_context.pktlog
#define g_if_to_kif                       l2mcd_context.ifindex_to_kifindex
#define g_curr_dbg_level                  l2mcd_context.curr_dbg_level
#define g_l2mcd_vlan_dbg_to_sys_log            l2mcd_context.dbg_to_sys_log     
#define g_l2mcd_dbg_vlan_log_all          l2mcd_context.dbg_vlan_log_all     
#define g_l2mcd_rx_buf                    l2mcd_context.rx_buf
#define g_l2mcd_if_to_kif_tree            l2mcd_context.if_to_kif_tree
#define g_l2mcd_kif_to_if_tree            l2mcd_context.kif_to_if_tree
#define g_l2mcd_rx_is_l2_sock             l2mcd_context.rx_is_l2_sock
#define g_rx_stats_non_igmp_pkts          l2mcd_context.rx_stats.non_igmp_pkts
#define g_rx_stats_igmp_pkts              l2mcd_context.rx_stats.igmp_pkts
#define g_rx_stats_pim_pkts               l2mcd_context.rx_stats.pim_pkts
#define g_rx_stats_tot_pkts               l2mcd_context.rx_stats.tot_pkts
#define g_rx_stats_no_aux                 l2mcd_context.rx_stats.no_aux
#define g_rx_stats_no_tag                 l2mcd_context.rx_stats.no_tag
#define g_rx_stats_inv_tags               l2mcd_context.rx_stats.inv_tags 
#define g_portdb_pending_count            l2mcd_context.portdb_pending_count
#define g_port_init_done                  l2mcd_context.port_init_done

#define L2MCD_INIT_LOG(...)  
#define L2MCD_INIT_LOG_INFO(...)        
#define L2MCD_LOG_DEBUG printf
#define L2MCD_LOG_INFO printf
#define L2MCD_LOG_NOTICE printf
#define L2MCD_LOG_WARN printf
#define L2MCD_LOG_ERR printf
#define L2MCD_LOG_CRIT printf
#define L2MCD_CLI_PRINT printf

#define L2MCD_LOG_MASK_DEBUG 0x4
#define L2MCD_LOG_MASK_PKT   0x2
#define L2MCD_LOG_MASK_INFO  0x1

#define L2MCD_VLAN_LOG_ERR(vlan,...)      
#define L2MCD_VLAN_LOG_INFO(vlan,...)      
#define L2MCD_PKT_PRINT(vlan, ...)       
#define L2MCD_VLAN_LOG_DEBUG(vlan,...)       

int l2mcd_system_init(int flag);
 struct event *l2mcd_igmprx_sock_init(int *fd, char *iname);
int l2mcd_igmprx_sock_close(char *pnames, int fd, struct event *igmp_rx_event);
#endif

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
#define L2MCD_PORTDB_PHYIF_MAX_IDX 256
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
extern int applog_level_map[APP_LOG_LEVEL_MAX + 2];


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


//AVL Tree Defnitions
#define M_AVLL_OFFSETOF(STRUCT, FIELD)  (unsigned long)((char *)(&((STRUCT *)0)->FIELD) - (char *)0)
typedef struct avl_table L2MCD_AVL_TABLE;
typedef L2MCD_AVL_TABLE* L2MCD_AVL_TREE;
typedef uint32_t L2MCD_AVL_NODE;
#define M_AVLL_INIT_TREE(TREE, COMPARE, KEY_OFF, NODE_OFF)
static inline void * M_AVLL_FIRST(L2MCD_AVL_TREE avl_tree)
{
    if (!avl_tree) return NULL;
    avl_t_init((avl_trav_t *)(avl_tree->trav), avl_tree);
    return avl_t_next((avl_trav_t *)(avl_tree->trav));
}
static inline void * M_AVLL_NEXT(L2MCD_AVL_TREE avl_tree, L2MCD_AVL_NODE node)
{
   if (!avl_tree) return NULL;
   return avl_t_next((avl_trav_t *)(avl_tree->trav));
}
static inline L2MCD_AVL_TREE L2MCD_AVL_CREATE(avl_comparison_func *func, void *ptr, void *a)
{
    L2MCD_AVL_TREE tree;
    tree= avl_create(func, ptr, (struct libavl_allocator *) a);
    tree->trav = calloc(1, sizeof(avl_trav_t));
    return tree;
}
#define L2MCD_AVL_ENTRY_COUNT(TREE) TREE->avl_count
#define M_AVLL_FIND    avl_find
#define M_AVLL_DELETE  avl_delete
#define M_AVLL_INSERT  avl_probe
#define M_AVLL_DESTROY avl_destroy
#define M_AVLL_INIT_NODE(NODE) 
#define M_AVLL_SET_REBALANCE(TREE, FLAG)


typedef enum {
    L2MCD_IF_TYPE_UNKNOWN_IF  = 2,    /* reserved */
    L2MCD_IF_TYPE_PHYSICAL    = 6,    /* physical GE interface */
    L2MCD_IF_TYPE_L2_TRUNK    = 10 ,  /* external (user visible) trunk */
    L2MCD_IF_TYPE_SVI         = 18,   /* Switch Virtual Ifc- IP maps on multiple L2 */
    L2MCD_IF_TYPE_LOOPBACK_IF = 22,   /* L3 loopback interface */
} ifm_type_t;

#define  is_virtual_port(port)       			(port<L2MCD_PORTDB_PHYIF_START_IDX)
#define  is_physical_port(port)		            (port >= L2MCD_PORTDB_PHYIF_START_IDX)

/* Generate the logical ifIndex based on type specific if id */
static inline ifindex_t l2mcd_ifindex_create_logical_idx(ifm_type_t type, uint port_id)
{
    return (L2MCD_IFIDX_TYPE_BF(type) | L2MCD_IFIDX_IFID_BF(port_id));
}
static inline bool_t l2mcd_ifindex_is_svi(ifindex_t ifidx)
{
  return (L2MCD_IFIDX_TYPE(ifidx) == L2MCD_IF_TYPE_SVI);
}
static inline int l2mcd_ifindex_get_svi_vid(ifindex_t ifidx)
{
  if (L2MCD_IFIDX_TYPE(ifidx) == L2MCD_IF_TYPE_SVI) {
		return (ifidx & 0x3ffff);	/* vlanid was lsb 12 bit but extended to 18 bits */	
  } else {
    return (-1);
  }	
}
static inline int l2mcd_ifindex_is_physical(ifindex_t ifidx)
{
    if (L2MCD_IFIDX_TYPE(ifidx) == L2MCD_IF_TYPE_PHYSICAL)
    {
        return TRUE;
    }
    return FALSE;
}

static inline int l2mcd_ifindex_is_trunk(ifindex_t ifidx)
{
    if (L2MCD_IFIDX_TYPE(ifidx) == L2MCD_IF_TYPE_L2_TRUNK)
    {
        return TRUE;
    }
    return FALSE;
}
static inline int l2mcd_ifindex_is_tunnel (ifindex_t ifidx)
{
    return FALSE;
}


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
     uint8_t            dbg_vlan_log_all;
    char                l2mcd_global_mac[ETHER_ADDR_LEN];
    uint8_t             pktlog[L2MCD_VLAN_MAX+1];
    uint32_t            ifindex_to_kifindex[L2MCD_PORTDB_PHYIF_MAX_IDX];
    uint32_t            curr_dbg_level;
    char                rx_buf[L2MCD_RX_BUFFER_SIZE];
    L2MCD_AVL_TREE         kif_to_if_tree;
    L2MCD_AVL_TREE         if_to_kif_tree;
    int                 rx_is_l2_sock;
    int                 portdb_pending_count;
} L2MCD_CONTEXT;

#define L2MCD_CTL_CMD_RESET          0x1
#define L2MCD_CTL_CMD_DB_LEVEL       0x2
#define L2MCD_CTL_CMD_SESS_NAME      0x4
#define L2MCD_CTL_CMD_SESS_VID       0x8
#define L2MCD_CTL_CMD_DUMP_ALL       0x10
#define L2MCD_CTL_CMD_PLOG_NAME      0x20
#define L2MCD_CTL_CMD_CUSTOM         0x40
#define L2MCD_CTL_CMD_PKT            0x80
#define L2MCD_CTL_VLAN_TRACE         0x100
typedef struct L2MCD_CTL_MSG {
    uint32_t cmd;
    int  dbgLevel;
    int  vid;
    int  cmd_id;
    char fname[100];
} L2MCD_CTL_MSG;

typedef struct L2MCD_APP_TABLE_ENTRY {
    uint8_t     op_code;
    uint8_t     port_oper;
    uint8_t     is_static;  
    uint8_t     is_remote; 
    int         vlan_id; 
    uint32_t    count; 
    char        saddr[L2MCD_IP_ADDR_STR_SIZE];
    char        gaddr[L2MCD_IP_ADDR_STR_SIZE];
    PORT_ATTR   ports[L2MCD_IPC_MAX_PORTS]; 
} L2MCD_APP_TABLE_ENTRY;


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

#define L2MCD_LOG_DEBUG(...)        applog_write(APP_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define L2MCD_LOG_INFO(...)         applog_write(APP_LOG_LEVEL_INFO, __VA_ARGS__)
#define L2MCD_LOG_NOTICE(...)       applog_write(APP_LOG_LEVEL_NOTICE, __VA_ARGS__)
#define L2MCD_LOG_WARN(...)         applog_write(APP_LOG_LEVEL_WARNING, __VA_ARGS__)
#define L2MCD_LOG_ERR(...)          applog_write(APP_LOG_LEVEL_ERR, __VA_ARGS__)
#define L2MCD_LOG_CRIT(...)         applog_write(APP_LOG_LEVEL_CRIT, __VA_ARGS__)
#define L2MCD_CLI_PRINT(...)        do {\
             if (g_l2mcd_fwk_dbg_mode) {l2mcsync_debug_print(__VA_ARGS__);}\
             else if (g_l2mcd_cmd_fp) {fprintf(g_l2mcd_cmd_fp, ##__VA_ARGS__);fprintf(g_l2mcd_cmd_fp,"\n"); fflush(g_l2mcd_cmd_fp);}\
             }while(0)
#define L2MCD_LOG_MASK_DEBUG 0x4
#define L2MCD_LOG_MASK_PKT   0x2
#define L2MCD_LOG_MASK_INFO  0x1

#define L2MCD_INIT_LOG(...)        do {\
            if (g_l2mcd_init_fp) {\
            fprintf(g_l2mcd_init_fp, ##__VA_ARGS__);fprintf(g_l2mcd_init_fp,"\n");fflush(g_l2mcd_init_fp);}\
            applog_write(APP_LOG_LEVEL_INFO, __VA_ARGS__);\
            }while(0)
#define L2MCD_VLAN_LOG_ERR(vlan,...)        do {\
            if (g_l2mcd_pkt_fp && g_l2mcd_pkt_log[vlan&0xFFF]) {\
            fprintf(g_l2mcd_pkt_fp,"[%d] ", vlan);fprintf(g_l2mcd_pkt_fp, ##__VA_ARGS__);fprintf(g_l2mcd_pkt_fp,"\n"); fflush(g_l2mcd_pkt_fp);}\
            if (g_l2mcd_vlan_dbg_to_sys_log && g_l2mcd_pkt_log[vlan&0xFFF] && (g_l2mcd_vlan_log_mask&L2MCD_LOG_MASK_INFO)) {\
                applog_write(APP_LOG_LEVEL_NOTICE, __VA_ARGS__);}\
            }while(0)
#define L2MCD_VLAN_LOG_INFO(vlan,...)        do {\
            if (g_l2mcd_pkt_fp && g_l2mcd_pkt_log[vlan&0xFFF] && (g_l2mcd_vlan_log_mask&L2MCD_LOG_MASK_INFO)) {\
            fprintf(g_l2mcd_pkt_fp,"[%d] ", vlan);fprintf(g_l2mcd_pkt_fp, ##__VA_ARGS__);fprintf(g_l2mcd_pkt_fp,"\n"); fflush(g_l2mcd_pkt_fp);}\
            if (g_l2mcd_vlan_dbg_to_sys_log && g_l2mcd_pkt_log[vlan&0xFFF] && (g_l2mcd_vlan_log_mask&L2MCD_LOG_MASK_INFO)) {\
                applog_write(APP_LOG_LEVEL_NOTICE, __VA_ARGS__);}\
            }while(0)
#define L2MCD_PKT_PRINT(vlan, ...)        do {\
            if (g_l2mcd_pkt_fp && g_l2mcd_pkt_log[vlan&0xFFF] && (g_l2mcd_vlan_log_mask&L2MCD_LOG_MASK_PKT)) {\
            fprintf(g_l2mcd_pkt_fp,"[%d] ", vlan);fprintf(g_l2mcd_pkt_fp, ##__VA_ARGS__);fprintf(g_l2mcd_pkt_fp,"\n"); fflush(g_l2mcd_pkt_fp);}\
            if (g_l2mcd_vlan_dbg_to_sys_log && g_l2mcd_pkt_log[vlan&0xFFF] && (g_l2mcd_vlan_log_mask&L2MCD_LOG_MASK_PKT)) {\
                applog_write(APP_LOG_LEVEL_NOTICE, __VA_ARGS__);}\
            }while(0)
#define L2MCD_VLAN_LOG_DEBUG(vlan,...)        do {\
            if (g_l2mcd_pkt_fp && g_l2mcd_pkt_log[vlan&0xFFF] && (g_l2mcd_vlan_log_mask&L2MCD_LOG_MASK_DEBUG)) {\
            fprintf(g_l2mcd_pkt_fp,"[%d] ", vlan);fprintf(g_l2mcd_pkt_fp, ##__VA_ARGS__);fprintf(g_l2mcd_pkt_fp,"\n"); fflush(g_l2mcd_pkt_fp);}\
            if (g_l2mcd_vlan_dbg_to_sys_log && g_l2mcd_pkt_log[vlan&0xFFF] && (g_l2mcd_vlan_log_mask&L2MCD_LOG_MASK_DEBUG)) {\
                applog_write(APP_LOG_LEVEL_NOTICE,__VA_ARGS__);}\
            }while(0)

int l2mcd_system_init(int flag);
int l2mcd_mld_vdb_init(void);
int l2mcd_avll_init(void);
void dump_mcgrpl3if(int vid);
uint32_t l2mcd_ifname_to_kifindex(char *if_name);
void dump_mcgrp_class (uint32_t afi);
void l2mcd_print_global_var(void);
int l2mcd_avl_compare_u32(const void *ptr1, const void *ptr2, void *params);
 struct event *l2mcd_igmprx_sock_init(int *fd, char *iname);
int l2mcd_igmprx_sock_close(char *pnames, int fd, struct event *igmp_rx_event);
int l2mcd_add_kif_to_if(char *ifname, uint32_t ifid, int sock_fd, struct event *ev, int po_id, int vid, int op, int oper);
int l2mcd_del_if_tree(uint32_t ifid);
l2mcd_if_tree_t* l2mcd_if_to_kif(uint32_t ifid);
l2mcd_if_tree_t* l2mcd_kif_to_if(uint32_t kif);
l2mcd_if_tree_t* l2mcd_kif_to_rx_if(uint32_t kif);
void l2mcd_set_loglevel(int level);
void l2mcd_dump_cfg(int vid);
void l2mcd_dump_custom(int id);
void portdb_insert_addr_ipv4_list(L2MCD_AVL_TREE *portdb_tree, UINT32 port_index,
                     UINT32 ipaddress, UINT8 prefix_length, VRF_INDEX vrf_index, UINT32 flags);
int l2mcd_portstate_update(int kif, int state, char *iname);
int l3_time_freq_init(void);
int l2mcd_port_list_update(char *pnames, int oper_state, int is_add);
void igmp_process_pimv2_packet(char *sptr_ip6_hdr,  UINT16 vir_port_id, UINT32 phy_port_id);
#endif

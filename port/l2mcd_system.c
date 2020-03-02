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

#define _GNU_SOURCE 
#include <sys/socket.h>
#include <sys/types.h>
#include "l2mcd.h"
#include <linux/filter.h>
#include <linux/rtnetlink.h>
#include "mld_vlan_db.h"
#include "l2mcd_mld_utils.h"
#include "l2mcd_mld_port.h"
#include "l2mcd_mcast_co.h"
#include <sys/ioctl.h>
#include "l2mcd_dbsync.h"
#include "l2mcd_portdb.h"

L2MCD_CONTEXT l2mcd_context;
char g_l2mcd_test_buf1[2000];
uint8_t g_l2mcd_test_buf2[2000];

MCGRP_GLOBAL_CLASS    gMld, *pgMld = &gMld;
MCGRP_GLOBAL_CLASS    gIgmp, *pgIgmp = &gIgmp;
MCAST_GLOBAL_CLASS    gMulticast, *pgMulticast = &gMulticast;
MCGRP_CLASS           Mld0, *pMld0 = &Mld0;
MCGRP_CLASS           Igmp0, *pIgmp0 = &Igmp0;
MCAST_CLASS           Multicast0, *pMulticast0 = &Multicast0;

struct sock_filter g_igmp_filter[] = {
    //1. Load Word @0
    BPF_STMT(BPF_LD |BPF_ABS|BPF_H, 0x0),
    //2. Jump if Equal to 0x00100,
    //true=next,    >> 1st HAlf of IP Mcast mac Matched
    //false=next+3  >> return failure
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x0100, 0, 3),
    //3. Load Half-Word @4
    BPF_STMT(BPF_LD |BPF_ABS|BPF_B, 0x2),
    //4. Jump if Equal to 0x5e,
    //true=next, >> IP Mcast MAC matched return SUCCESS
    //false=next+1 >> no match found, return failure
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x5e, 0, 1),
    //5. Match Found trap packet to Application
    BPF_STMT(BPF_RET|BPF_K, 0xffff),
    //6. NO Match skip packet, return 0
    BPF_STMT(BPF_RET|BPF_K, 0),
};

int l2mcd_system_group_entry_notify(MADDR_ST *group_address, MADDR_ST *src_address, int vir_port, int phy_port_id, int is_static, int insert)
{  
    L2MCD_APP_TABLE_ENTRY msg;
    struct sockaddr_in sa;
    l2mcd_if_tree_t *l2mcd_if_tree;
    int rmt1=0, rmt2=0;
    MCGRP_SOURCE *igmpv3_src;
    MCGRP_CLASS         *mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(L2MCD_IPV4_AFI, L2MCD_DEFAULT_VRF_IDX);
    MCGRP_MBRSHP        *mcgrp_mbrshp=NULL;

    memset(&msg,0, sizeof(L2MCD_APP_TABLE_ENTRY));
    msg.vlan_id=vir_port;
    sa.sin_addr.s_addr = htonl(group_address->ip.v4addr);
    inet_ntop(AF_INET, &(sa.sin_addr), msg.gaddr, INET_ADDRSTRLEN);
    l2mcd_if_tree = l2mcd_if_to_kif(phy_port_id);
    if (l2mcd_if_tree)
    {
        memcpy(msg.ports[0].pnames, l2mcd_if_tree->iname, sizeof(PORT_ATTR));
        msg.port_oper = l2mcd_if_tree->oper;
    }
    if (!src_address ||  !src_address->ip.v4addr)
    {
        snprintf(msg.saddr, L2MCD_IP_ADDR_STR_SIZE, "0.0.0.0");
    }
    else 
    {
        sa.sin_addr.s_addr = htonl(src_address->ip.v4addr);
        inet_ntop(AF_INET, &(sa.sin_addr), msg.saddr, INET_ADDRSTRLEN);
    }


    msg.is_static=is_static;
    mcgrp_mbrshp = mcgrp_find_mbrshp_entry_for_grpaddr(mcgrp, group_address, vir_port, phy_port_id);
    if (mcgrp_mbrshp) 
    {
        msg.is_remote = mcgrp_mbrshp->is_remote;
        msg.is_static=  mcgrp_mbrshp->static_mmbr;
        rmt1=mcgrp_mbrshp->is_remote;
        if (src_address && !mcast_addr_any(src_address)) 
        {
            igmpv3_src = mcgrp_find_source(mcgrp_mbrshp, src_address,  FILT_INCL);
            if (igmpv3_src) 
            {
                msg.is_remote = igmpv3_src->is_remote;
                rmt2=msg.is_remote;
            }
        }
    }

    msg.op_code = insert;
    msg.count=1;
    L2MCD_VLAN_LOG_INFO(vir_port, "%s:%d:[vlan:%d] GA:%s S:%s %s Rmt:%d/%d/%d op:%d", 
       FN,LN,vir_port, msg.gaddr, msg.saddr,  msg.ports[0].pnames, msg.is_remote,rmt1,rmt2, msg.op_code);
    l2mcsync_add_l2mc_entry(&msg); 
    return 0;
}

int l2mcd_system_mrouter_notify(int vir_port, int phy_port_id, int is_static, int insert)
{  
    L2MCD_APP_TABLE_ENTRY msg;
    l2mcd_if_tree_t *l2mcd_if_tree;
    memset(&msg,0, sizeof(L2MCD_APP_TABLE_ENTRY));
    msg.vlan_id=vir_port;
    l2mcd_if_tree = l2mcd_if_to_kif(phy_port_id);

    if (l2mcd_if_tree)
    {
        memcpy(msg.ports[0].pnames, l2mcd_if_tree->iname, sizeof(PORT_ATTR));
        msg.port_oper = l2mcd_if_tree->oper;
    }

    msg.op_code = insert;
    msg.count=1;
    msg.is_static=is_static;
    L2MCD_VLAN_LOG_INFO(vir_port, "%s:%d:[vlan:%d] Mrouter %s op:%s", FN,LN,vir_port, msg.ports[0].pnames, msg.op_code?"ADD":"DEL");
    l2mcsync_process_mrouterentry(&msg); 
    return 0;
}

void l2mcd_igmp_process_sync_report (
        mcast_grp_addr_t      *saddr,
        mcast_grp_addr_t      *gaddr,
        uint16_t      vir_port_id,
        uint16_t      phy_port_id,
        uint8_t       insert,
        uint8_t       cmd_code)
{

    MCGRP_L3IF     *mcgrp_vport = NULL;
    MCGRP_PORT_ENTRY  *mcgrp_pport = NULL;  
    MADDR_ST      src_addr;
    MADDR_ST      grp_addr;
    UINT32 src_list;
    MCGRP_CLASS         *mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(L2MCD_IPV4_AFI, L2MCD_DEFAULT_VRF_IDX);
    uint8_t sync_ver;
    uint8_t sync_action=IS_EXCL;
    uint8_t num_srcs=1;

    if (cmd_code ==1) return;
    mcast_set_ip_addr(&grp_addr, gaddr);
    mcast_set_ip_addr(&src_addr, saddr);
    mcgrp_vport  = gIgmp.port_list[vir_port_id];
    if (mcgrp_vport == NULL)
    { 
        L2MCD_LOG_NOTICE("%s:%d vlan:%d not found", __FUNCTION__, __LINE__, vir_port_id);
        return;
    }
    if (is_virtual_port(vir_port_id)) 
    {
        mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
        if (mcgrp_pport == NULL || !mcgrp_pport->is_up) 
        {
            L2MCD_LOG_NOTICE("%s:%d mcgrp pport:%s not found on vlan:%d", __FUNCTION__, __LINE__, 
                            mld_get_if_name_from_ifindex(phy_port_id), vir_port_id);
            return;
        }
	} 
    else if (mcgrp_vport->vir_port_id == mcgrp_vport->phy_port_id) 
    {
        mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
        if (mcgrp_pport == NULL)
        {
            L2MCD_LOG_NOTICE("%s:%d mcgrp pport:%s not found on vlan:%d", __FUNCTION__, __LINE__, 
                            mld_get_if_name_from_ifindex(phy_port_id), vir_port_id);
            return;
        }
	} else 
    {
        L2MCD_LOG_NOTICE("%s:%d mcgrp pport:%s not found on vlan:%d", __FUNCTION__, __LINE__, 
                mld_get_if_name_from_ifindex(phy_port_id), vir_port_id);
		return;
	}

    src_list=src_addr.ip.v4addr;
    sync_ver=mcgrp_pport->oper_version;
    if (!cmd_code) sync_ver|=IGMP_REMOTE_FLAG;
    sync_action = TO_INCL;

    if (src_list)
    {
        /* V3 */
        sync_action = insert ? ALLOW_NEW:BLOCK_OLD;
        if (mcgrp_pport->oper_version < IGMP_VERSION_3)
        {
            /* NOP. TODO V2 on V3 allow  this. back end expected to take care*/
        }
    }
    if (!src_list) 
    {
         /* V1/V2 */
        sync_action = insert ? IS_EXCL:TO_INCL;
        num_srcs=0;
        if (mcgrp_pport->oper_version == IGMP_VERSION_3)
        {
             /* NOP. TODO V3 on V2 allow  this. back end expected to take care*/
        }
    }
    
    mcgrp_update_group_address_table(mcgrp, vir_port_id, phy_port_id,
                    &grp_addr, &src_addr,
                    sync_action,
                    sync_ver,
                    num_srcs, (void *)&src_list);
    
    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d: Processed version%d mclag remote entry (%s, %s, vlan%d): %s port:%s action:%d, #src:%d, vers:0x%x", 
                        __FUNCTION__, __LINE__, mcgrp_pport->oper_version,
                        (src_addr.ip.v4addr?mcast_print_addr(&src_addr):"*"), mcast_print_addr(&grp_addr), vir_port_id, 
                        (insert?"Added":"Deleted"), mld_get_if_name_from_ifindex(phy_port_id),sync_action,num_srcs,sync_ver);
    return;
}

void l2mcd_igmp_process_remote_mrouter (
        uint16_t      vir_port_id,
        uint16_t      phy_port_id,
        uint8_t       insert)
{
    MCGRP_CLASS *mcgrp = IGMP_GET_INSTANCE_FROM_VRFINDEX(L2MCD_DEFAULT_VRF_IDX);
    MCGRP_L3IF     *mcgrp_vport = NULL;
    MCGRP_PORT_ENTRY  *mcgrp_pport = NULL;  

    mcgrp_vport  = gIgmp.port_list[vir_port_id];
    if (mcgrp_vport == NULL)
    { 
        L2MCD_LOG_NOTICE("%s:%d vlan:%d not found", __FUNCTION__, __LINE__, vir_port_id);
        return;
    }
    if (is_virtual_port(vir_port_id)) 
    {
        mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
        if (mcgrp_pport == NULL || !mcgrp_pport->is_up) 
        {
            L2MCD_LOG_NOTICE("%s:%d mcgrp pport:%s not found on vlan:%d", __FUNCTION__, __LINE__, 
                            mld_get_if_name_from_ifindex(phy_port_id), vir_port_id);
            return;
        }
	} 
    else if (mcgrp_vport->vir_port_id == mcgrp_vport->phy_port_id) 
    {
        mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
        if (mcgrp_pport == NULL)
        {
            L2MCD_LOG_NOTICE("%s:%d mcgrp pport:%s not found on vlan:%d", __FUNCTION__, __LINE__, 
                            mld_get_if_name_from_ifindex(phy_port_id), vir_port_id);
            return;
        }
	} else 
    {
        L2MCD_LOG_NOTICE("%s:%d mcgrp pport:%s not found on vlan:%d", __FUNCTION__, __LINE__, 
                mld_get_if_name_from_ifindex(phy_port_id), vir_port_id);
		return;
	}

    if (is_mld_snooping_enabled(mcgrp_vport, MCAST_IPV4_AFI)) 
    {
        if (insert) {
            mcgrp_add_router_port(mcgrp, mcgrp_vport, phy_port_id, TRUE,
                    MLD_PROTO_MROUTER,
                    DEFAULT_MROUTER_AGING_TIME, TRUE);
        } else {
            mcgrp_delete_router_port(mcgrp, mcgrp_vport, phy_port_id);
        }

    }

    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d: Processed mclag remote mrouter entry on vlan%d: %s mrouter-port:%s ",
                        __FUNCTION__, __LINE__, vir_port_id, 
                        (insert?"Added":"Deleted"), mld_get_if_name_from_ifindex(phy_port_id));
    return;
}

/*
 * l2mcd_process_ipc_msg 
 *
 * Processing of L2MCd socket messages
 */
static void l2mcd_process_ipc_msg(L2MCD_IPC_MSG *msg, int len, struct sockaddr_un client_addr)
{
    L2MCD_CONFIG_MSG *data=NULL;
    L2MCD_CTL_MSG    *ctl_data=NULL;
    int vlan_id=0;
    int afi = MLD_IP_IPV4_AFI;
    uint8_t vlan_type = MLD_VLAN;
    mld_vlan_node_t *vlan_node = NULL;
    int rc=0;
    mld_cfg_param_t *cfg;
    int val=0;
    mcast_grp_addr_t grpaddr,srcaddr;
    struct in_addr ipaddr;
    int iftype=0;
    int ifidx, ifidx2, kif;
    int i=0;
    int enableFlag=0;
    char ifname[L2MCD_IFNAME_SIZE];
    IP_PARAMETERS  *ip_param, test_ip_param;
    l2mcd_if_tree_t *l2mcd_if_tree;
    IGMP_PACKET  *igmp_pkt;
    FILE *l2mcd_pkt_fp;
    char str[20];
    int j=0;
    MCGRP_CLASS         *mcgrp = NULL; 


    L2MCD_LOG_DEBUG("igmps recieved IPC message type:%u ", msg->msg_type);

    switch(msg->msg_type)
    {
        case L2MCD_IGMP_PKT_MSG:
        {
            ip_param = (IP_PARAMETERS*) msg->data;
            igmp_pkt   = (IGMP_PACKET *) ip_param->data;
            vlan_id = mld_l3_get_port_from_ifindex(ip_param->rx_port_number,MLD_VLAN);
            kif = ip_param->rx_phy_port_number;
            l2mcd_if_tree = l2mcd_kif_to_rx_if(kif);
            if (!l2mcd_if_tree)
            {
                L2MCD_LOG_NOTICE("%s unknown RX interface :kif:%d",__FUNCTION__, kif);
                return;
            }
            ifidx = l2mcd_if_tree->ifid;
            l2mcd_if_tree->rx_pkts++;
            ip_param->rx_phy_port_number = ifidx;
            L2MCD_PKT_PRINT(vlan_id,
                "IGMP RX IF:%s lif:%d in kif:%d   Vid:%d IP: v:0x%x,ihl:0x%x,len:0x%x,ttl:0x%x,prot:%d,csum:0x%x sip:0x%x dip:0x%x  option:code 0x%x length:%d,val:%d   IGMP:type:0x%x mrt:0x%x csum:0x%x ga:0x%x", 
                l2mcd_if_tree->iname,ip_param->rx_phy_port_number, kif, vlan_id,
                igmp_pkt->ip_header.version_header_length.version, igmp_pkt->ip_header.version_header_length.header_length,
                igmp_pkt->ip_header.total_length,igmp_pkt->ip_header.time_to_live,
                igmp_pkt->ip_header.protocol, igmp_pkt->ip_header.header_checksum,
                igmp_pkt->ip_header.source_ip_address,igmp_pkt->ip_header.destination_ip_address,
                igmp_pkt->ip_options.code.option_number, igmp_pkt->ip_options.length,igmp_pkt->ip_options.value,
                igmp_pkt->igmp_message.type, igmp_pkt->igmp_message.maximum_response_time, igmp_pkt->igmp_message.checksum, igmp_pkt->igmp_message.group_address);
            receive_igmp_packet(ip_param);
            free(ip_param->data);
            break;
        }
        case L2MCD_SNOOP_PORT_LIST_MSG:
        {
            data = (L2MCD_CONFIG_MSG *) msg->data;
            if (!data)
            {
                L2MCD_LOG_NOTICE(" No Data for recievd IPC message type:%u ", msg->msg_type);
                break;
            }
            L2MCD_LOG_NOTICE("L2MCD_SNOOP_PORT_LIST_MSG count:%d",data->count);
            for (i=0;i<data->count;i++)
            {
                l2mcd_port_list_update(data->ports[i].pnames, data->ports[i].oper_state, data->op_code);
            }
            break;
        }
        case L2MCD_LAG_MEM_TABLE_UPDATE:
        {
            data = (L2MCD_CONFIG_MSG *) msg->data;
            if (!data)
            {
                L2MCD_LOG_NOTICE("No Data for recievd IPC message L2MCD_VLAN_MEM_TABLE_UPDATE type:%u ", msg->msg_type);
                break;
            }
            for (i=0;i<data->count;i+=2)
            {
                ifidx = data->op_code ? portdb_get_portindex_from_ifname(data->ports[i].pnames):0;
                ifidx2 =  portdb_get_portindex_from_ifname(data->ports[i+1].pnames);
                l2mcd_add_kif_to_if(data->ports[i+1].pnames, ifidx2, -1, NULL, ifidx, -1, -1, -1);
                L2MCD_LOG_INFO("LAG Memeber LAG:%s(%d) Member:%s(%d) opcode:%d", 
                     data->ports[i].pnames, ifidx, data->ports[i+1].pnames, ifidx2,data->op_code);
            }
            break;
        }
        case L2MCD_CONFIG_PARAMS_MSG:
        {
            data = (L2MCD_CONFIG_MSG *) msg->data;
            if (!data)
            {
                L2MCD_LOG_NOTICE("No Data for recievd IPC message L2MCD_VLAN_MEM_TABLE_UPDATE type:%u ", msg->msg_type);
                break;
            }
            g_curr_dbg_level = data->count;
            memcpy(&g_l2mcd_global_mac, &data->mac_addr, ETHER_ADDR_LEN);
            memcpy((char *) gIgmp.mac, (const char *) g_l2mcd_global_mac, ETHER_ADDR_LEN);
	        L2MCD_INIT_LOG("Global MAC set for IPV4  0x%x:0x%x:0x%x:0x%x:0x%x:0x%x: dbglevel:%d",
                   gIgmp.mac[0],gIgmp.mac[1],gIgmp.mac[2],gIgmp.mac[3],gIgmp.mac[4],gIgmp.mac[5],
                   g_curr_dbg_level);
            APP_LOG_SET_LEVEL(g_curr_dbg_level);
            /* Debug FM call back register is done delayed, to ensure fm is up by the time. */ 
            l2mcsync_init_debug_framework();
            break;
        }
        case L2MCD_VLAN_MEM_TABLE_UPDATE:
        {
            data = (L2MCD_CONFIG_MSG *) msg->data;
            if (!data)
            {
                L2MCD_LOG_NOTICE("No Data for recievd IPC message L2MCD_VLAN_MEM_TABLE_UPDATE type:%u ", msg->msg_type);
                break;
            }
            vlan_id = data->vlan_id;
            vlan_node = mld_vdb_vlan_get(vlan_id, MLD_VLAN);
            if (!vlan_node)
            {
                return;
            }
            for(i=0;i<data->count;i++)
            {
                ifidx = portdb_get_portindex_from_ifname(data->ports[i].pnames);
                val = mld_is_port_member_of_vlan(vlan_node,ifidx);
                if ((!val && data->op_code) || (val && !data->op_code))
                {
                    mld_map_port_vlan_state(vlan_id, ifidx, data->op_code, L2MCD_IPV4_AFI, MLD_VLAN , TRUE, TRUE);
                    L2MCD_VLAN_LOG_INFO(vlan_id, "%s:%d:[vlan:%d] l2mcd-cfg:VLAN_MEMBER port:%s ifindx:%d, op:%d", FN,LN, vlan_id, data->ports[i].pnames, ifidx,data->op_code);
                    l2mcd_add_kif_to_if(data->ports[i].pnames, ifidx, -1, NULL, -1, vlan_id, data->op_code? 1:0, -1);
                    if (!data->op_code) 
                    {
                        mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(L2MCD_IPV4_AFI, L2MCD_DEFAULT_VRF_IDX);
                       mld_protocol_port_state_notify(vlan_node, L2MCD_DEFAULT_VRF_IDX, mcgrp, ifidx, 0);
                    }
                    break;
                }
                L2MCD_VLAN_LOG_INFO(vlan_id,"%s:%d:[vlan:%d] val:%d vlan-member:%s ifindx:%d op:%d ignored",FN, LN, vlan_id, val,data->ports[i].pnames, ifidx,data->op_code);
            }
            break;
        }
        case L2MCD_SNOOP_CONFIG_MSG:
        {
            data = (L2MCD_CONFIG_MSG *) msg->data;
            if (!data)
            {
                L2MCD_LOG_NOTICE("No Data for recievd IPC message type:%u ", msg->msg_type);
                break;
            }
            vlan_id = data->vlan_id;
            vlan_node = mld_vdb_vlan_get(vlan_id, MLD_VLAN);
            L2MCD_VLAN_LOG_INFO(vlan_id, "%s:%d:[vlan:%d] l2mcd-cfg:SNOOP ipc_rx type:%s, ver:%d,  querier:%s, fleave:%s , qtime:%d, lmq_time:%d, qmx_resp_time:%d, dyn_count:%d", 
               FN, LN,vlan_id, data->op_code?"Add":"Del", data->version, data->querier?"Y":"N", data->fast_leave?"Y":"N", 
               data->query_interval, data->last_member_query_interval, data->query_max_response_time,data->count);

            if (!vlan_node || (vlan_node && !mld_is_flag_set(vlan_node, afi, MLD_SNOOPING_ENABLED)))
            {
                snprintf(ifname, L2MCD_IFNAME_SIZE,"Vlan%d",vlan_id);
                l2mcd_add_kif_to_if(ifname, vlan_id, -1, NULL, -1, -1, -1, 1);
                rc = mld_if_snoop_set(afi, vlan_id, TRUE, MLD_VLAN);
                L2MCD_VLAN_LOG_DEBUG(vlan_id, "igmps is enabled for vlan %d ifcnt:%d rc:%d", vlan_id, data->count, rc);
                l2mcsync_add_vlan_entry(vlan_id);
                vlan_node = mld_vdb_vlan_get(vlan_id, MLD_VLAN);
                portdb_entry_t *port_entry=portdb_find_port_entry(&gMld.ve_portdb_tree, vlan_id);
                if (port_entry && port_entry->opaque_data) 
                {
                    /* IP adress is already configured for the vlan */
                    vlan_node->ve_ifindex = vlan_node->ifindex;
                    L2MCD_VLAN_LOG_INFO(vlan_id, "%s:%d:[vlan:%d] VE enabled vlan", FN,LN, vlan_id);
                }

            }

            if (vlan_node && mld_is_flag_set(vlan_node, afi, MLD_SNOOPING_ENABLED)) 
            {
                if (!data->op_code)
                {
                    L2MCD_VLAN_LOG_DEBUG(vlan_id,"igmps disable for vlan:%d", vlan_id);
                    mld_if_snoop_unset(afi, vlan_id, TRUE, MLD_VLAN);
                    l2mcsync_del_vlan_entry(vlan_id);
                    break;
                }

                cfg = mld_vdb_vlan_get_cfg_param(vlan_node, TRUE, afi);
                if (!cfg)
                {
                    L2MCD_LOG_NOTICE("igmps Unable to retrive cfg_param for vlan  %d", vlan_id);
                    return;
                }
                L2MCD_VLAN_LOG_DEBUG(vlan_id,"igmps curr_cfg vlan:%d qi:%d,  qmr:%d lmqi:%d  ver:%d flags:0x%x",
                                vlan_id, cfg->cfg_query_interval_time, cfg->max_response_time, cfg->LMQ_interval, 
                                cfg->cfg_version, vlan_node->flags[afi-1]);
                if (data->fast_leave && !mld_is_flag_set(vlan_node, afi,MLD_FAST_LEAVE_CONFIGURED))
                {
                    rc = mld_fastleave_set(afi, vlan_id, vlan_type);
                    L2MCD_VLAN_LOG_DEBUG(vlan_id,"igmps enabling fastleave for vlan :%d rc:%d", vlan_id, rc);
                }
                if (!data->fast_leave && mld_is_flag_set(vlan_node, afi,MLD_FAST_LEAVE_CONFIGURED))
                {
                    rc = mld_fastleave_unset(afi, vlan_id, vlan_type);
                    L2MCD_VLAN_LOG_DEBUG(vlan_id,"igmps disabling fastleave for vlan :%d rc:%d", vlan_id, rc);
                }

                if (data->querier && !mld_is_flag_set(vlan_node, afi,MLD_SNOOPING_QUERIER_ENABLED))
                {
                     rc = mld_snoop_querier_set(afi, vlan_id, vlan_type);
                     L2MCD_VLAN_LOG_DEBUG(vlan_id,"igmps enabling querier for vlan :%d rc:%d", vlan_id, rc);
                }
                if (!data->querier && mld_is_flag_set(vlan_node, afi,MLD_SNOOPING_QUERIER_ENABLED))
                {
                     rc = mld_snoop_querier_unset(afi, vlan_id, vlan_type);
                     L2MCD_VLAN_LOG_DEBUG(vlan_id,"igmps disabling querier for vlan :%d rc:%d", vlan_id, rc);
                }
                if (cfg->cfg_query_interval_time != data->query_interval)
                {
                    val = cfg->cfg_query_interval_time;
                    rc =  mld_query_interval_set(afi, vlan_id, data->query_interval, vlan_type);
                    L2MCD_VLAN_LOG_DEBUG(vlan_id,"igmps rc:%d changed QI for vlan %d from %d to %d", 
                               rc, vlan_id, val, data->query_interval);
                }
                if (cfg->max_response_time != data->query_max_response_time)
                {
                    val = cfg->max_response_time;
                    rc = mld_query_max_response_time_set(afi, vlan_id, data->query_max_response_time, vlan_type);
                    L2MCD_VLAN_LOG_DEBUG(vlan_id,"igmps rc:%d changed qmr of vlan %d from %d to %d", rc, vlan_id, val, data->query_max_response_time);
                }
                if (cfg->LMQ_interval != data->last_member_query_interval)
                {
                    val = cfg->LMQ_interval;
                    rc = mld_lmqi_set(afi, vlan_id,data->last_member_query_interval, vlan_type);
                    L2MCD_VLAN_LOG_DEBUG(vlan_id,"igmps rc:%d changed LMQI of vlan %d from %d to %d", rc, vlan_id, cfg->LMQ_interval, data->last_member_query_interval);
                }
                if (cfg->cfg_version != data->version)
                {
                   rc = mld_if_set_version_api(MLD_DEFAULT_VRF_ID, vlan_id, data->version, afi, vlan_type);
                   L2MCD_VLAN_LOG_DEBUG(vlan_id,"igmps rc:%d changed IGMP version of vlan=%d from %d to %d", rc, vlan_id, cfg->cfg_version, data->version);
                }
                for(i=0;i<data->count;i++)
                {
                    ifidx = portdb_get_portindex_from_ifname(data->ports[i].pnames);
                    L2MCD_VLAN_LOG_DEBUG(vlan_id,"%s:%d:[vlan:%d] vlan-member:%s ifindx:%d", __FUNCTION__, __LINE__, vlan_id, data->ports[i].pnames, ifidx);
                    mld_map_port_vlan_state(vlan_id, ifidx, TRUE, L2MCD_IPV4_AFI, MLD_VLAN , TRUE, TRUE);
                    l2mcd_add_kif_to_if(data->ports[i].pnames, ifidx, -1, NULL, -1, vlan_id, 1, -1);
                }
            }
            break;
        }
        case L2MCD_SNOOP_MROUTER_CONFIG_MSG:
        {
            data = (L2MCD_CONFIG_MSG *) msg->data;
            vlan_id = data->vlan_id;
            if (!data)
            {
                L2MCD_LOG_ERR("%s:%d No Data for recievd IPC message type:%u ", msg->msg_type, __FUNCTION__, __LINE__);
                break;
            } 
            iftype = L2MCD_IF_TYPE_PHYSICAL;
            enableFlag=data->op_code;
            rc = mld_snooping_mrouter_if_set_api(data->vlan_id, iftype, data->ports[0].pnames, enableFlag, MCAST_IPV4_AFI,MLD_VLAN);
            L2MCD_VLAN_LOG_INFO(vlan_id, "%s:%d:[vlan:%d] l2mcd-cfg:MROUTER op:%d cnt:%d port[0]:%s", FN,LN,vlan_id,data->op_code,data->count,data->ports[0].pnames);
            break;
        }
        
        case L2MCD_SNOOP_REMOTE_CONFIG_MSG:
            data = (L2MCD_CONFIG_MSG *) msg->data;
            vlan_id = data->vlan_id;
            if (!data)
            {
                L2MCD_LOG_NOTICE("%s:%d No Data for recievd IPC message type:%u ", msg->msg_type, __FUNCTION__, __LINE__);
                break;
            }
            grpaddr.afi = MCAST_IPV4_AFI;
            inet_aton(data->gaddr, &ipaddr);
            grpaddr.ip.ipv4_addr = htonl(ipaddr.s_addr);
            srcaddr.afi = MCAST_IPV4_AFI;
            inet_aton(data->saddr, &ipaddr);
            srcaddr.ip.ipv4_addr = htonl(ipaddr.s_addr);
            ifidx = portdb_get_portindex_from_ifname(data->ports[0].pnames);
            L2MCD_VLAN_LOG_INFO(data->vlan_id, "%s:%d:[vlan:%d] l2mcd-cfg:REMOTE op:%d cnt:%d port[0]:%s (%d) GA:%s SA:%s[0x%x] type:%d",
                    FN,LN,data->vlan_id, data->op_code,data->count,data->ports[0].pnames,ifidx, data->gaddr,data->saddr,srcaddr.ip.ipv4_addr, data->cmd_code);
            l2mcd_igmp_process_sync_report(&srcaddr, &grpaddr, vlan_id, ifidx, data->op_code, data->cmd_code);
            break;
        
        case L2MCD_SNOOP_MROUTER_REMOTE_CONFIG_MSG:
            data = (L2MCD_CONFIG_MSG *) msg->data;
            vlan_id = data->vlan_id;
            if (!data)
            {
                L2MCD_LOG_NOTICE("%s:%d No Data for recievd IPC message type:%u ", msg->msg_type, __FUNCTION__, __LINE__);
                break;
            }
            grpaddr.afi = MCAST_IPV4_AFI;
            ifidx = portdb_get_portindex_from_ifname(data->ports[0].pnames);
            L2MCD_VLAN_LOG_INFO(data->vlan_id, "%s:%d:[vlan:%d] l2mcd-cfg:Mrouter REMOTE op:%d cnt:%d port[0]:%s (%d)",
                    FN,LN,data->vlan_id, data->op_code,data->count,data->ports[0].pnames,ifidx);
            l2mcd_igmp_process_remote_mrouter(vlan_id, ifidx, data->op_code);

        case L2MCD_SNOOP_STATIC_CONFIG_MSG:
        {
            data = (L2MCD_CONFIG_MSG *) msg->data;
            vlan_id = data->vlan_id;
            if (!data)
            {
                L2MCD_LOG_NOTICE("%s:%d No Data for recievd IPC message type:%u ", msg->msg_type, __FUNCTION__, __LINE__);
                break;
            }
            grpaddr.afi = MCAST_IPV4_AFI;
            inet_aton(data->gaddr, &ipaddr);
            grpaddr.ip.ipv4_addr = htonl(ipaddr.s_addr);
            srcaddr.afi = MCAST_IPV4_AFI;
            inet_aton(data->saddr, &ipaddr);
            srcaddr.ip.ipv4_addr = htonl(ipaddr.s_addr);
            if (!data->op_code)
            {
                rc = mld_static_group_source_unset(data->vlan_id, data->ports[0].pnames, iftype, &grpaddr, 0, FALSE, vlan_type);
            }
            else
            {
                rc = mld_static_group_source_set(data->vlan_id, data->ports[0].pnames, iftype, &grpaddr, 1, FALSE, vlan_type);
            }
            L2MCD_VLAN_LOG_INFO(data->vlan_id, "%s:%d:[vlan:%d] l2mcd-cfg:%s op:%d cnt:%d port[0]:%s GA:%s SA:%s[0x%x]",
                 FN,LN,data->vlan_id, (msg->msg_type==L2MCD_SNOOP_STATIC_CONFIG_MSG)?"STATIC":"REMOTE",
                 data->op_code,data->count,data->ports[0].pnames,data->gaddr,data->saddr,srcaddr.ip.ipv4_addr);
            break;
        }
        case L2MCD_INTERFACE_TABLE_UPDATE:
        {
            data = (L2MCD_CONFIG_MSG *) msg->data;
            if (!data)
            {
                L2MCD_LOG_NOTICE(" No Data for recievd IPC message type:%u ", msg->msg_type);
                break;
            }
            inet_aton(data->gaddr, &ipaddr);
            vlan_id = data->vlan_id;
            val = data->prefix_length;
            if (data->op_code)
            {
                rc = portdb_add_port_entry_to_tree(&gMld.ve_portdb_tree, vlan_id, L2MCD_DEFAULT_VRF_IDX,vlan_id);
                portdb_insert_addr_ipv4_list(&gMld.ve_portdb_tree, vlan_id, htonl(ipaddr.s_addr),val, L2MCD_DEFAULT_VRF_IDX, 0);
            }
            else
            {
                rc = portdb_remove_addr_ipv4_list(&gMld.ve_portdb_tree, vlan_id, htonl(ipaddr.s_addr));
                portdb_remove_port_entry_from_tree(&gMld.ve_portdb_tree, vlan_id);
            }
            vlan_node =  mld_vdb_vlan_get(vlan_id, MLD_VLAN);
            if (!vlan_node)
            {
               vlan_node = mld_vlan_create_fwd_ref(vlan_id, MLD_ROUTE_PORT);
               if (!vlan_node) 
               {
                   L2MCD_LOG_NOTICE("vlan:%d Interface Table Update IP:%s VDB create error",vlan_id, data->gaddr,val,data->op_code);
                   return;
               }
            }
            vlan_node->ve_ifindex = (!data->op_code & !rc)? vlan_id: vlan_node->ifindex;
            L2MCD_VLAN_LOG_INFO(vlan_id, "%s:%d:[vlan:%d] Interface Table Update IP:%s  %d %d ",FN,LN,data->vlan_id, data->gaddr,val,data->op_code);
            break;
        }

        case L2MCD_SNOOP_CTL_MSG: /* Internal Debugging & Test */
        {
            ctl_data = (L2MCD_CTL_MSG *) msg->data;
            if (ctl_data->cmd & L2MCD_CTL_CMD_PKT)
            {
                l2mcd_pkt_fp =  fopen(ctl_data->fname,"r");
                vlan_id = ctl_data->vid;
                vlan_node = mld_vdb_vlan_get(vlan_id, MLD_VLAN);
                if (!vlan_node) 
                {
                    L2MCD_LOG_INFO("%d vlan invalid \n",vlan_id);
                    break;
                }
                test_ip_param.rx_phy_port_number=ctl_data->cmd_id;//KIF
                test_ip_param.rx_vlan_id = vlan_id;
                test_ip_param.vrf_index = L2MCD_DEFAULT_VRF_IDX;
                test_ip_param.rx_port_number = vlan_node->ifindex;
                if (!l2mcd_pkt_fp)
                {
                    L2MCD_LOG_INFO("%s fopen failed \n",ctl_data->fname);
                    break;
                }
                while(!feof(l2mcd_pkt_fp))
                {
                   g_l2mcd_test_buf1[i++] = fgetc(l2mcd_pkt_fp);
                   if (i>2000) break;
                }
                for (j=0;j<i;j+=2)
                {
                    sprintf(str,"0x%c%c", g_l2mcd_test_buf1[j],g_l2mcd_test_buf1[j+1]);   
                    g_l2mcd_test_buf2[j/2]= strtol(str, NULL, 0);
                }
                g_l2mcd_test_buf2[i]='\0';
                fclose(l2mcd_pkt_fp);
                
                igmp_pkt   = (IGMP_PACKET *) g_l2mcd_test_buf2;
                kif = test_ip_param.rx_phy_port_number;
                l2mcd_if_tree = l2mcd_kif_to_if(kif);
                if (!l2mcd_if_tree)
                {
                    L2MCD_CLI_PRINT("%s unknown RX interface :kif:%d",__FUNCTION__, kif);
                    return;
                }
                else 
                {
                    ifidx = l2mcd_if_tree->ifid;
                    l2mcd_if_tree->rx_pkts++;
                }
                test_ip_param.rx_phy_port_number = l2mcd_if_tree->ifid;
                test_ip_param.data = igmp_pkt;
                struct iphdr *iph = (struct iphdr *) igmp_pkt;

                test_ip_param.source_address = iph->saddr;
                test_ip_param.destination_address  = iph->daddr;
                test_ip_param.header_length  = iph->ihl * 4;
                test_ip_param.total_length = ntohs(iph->tot_len);
                test_ip_param.time_to_live = iph->ttl;
                test_ip_param.destination_address = iph->daddr;
                test_ip_param.vrf_index= L2MCD_DEFAULT_VRF_IDX;

                L2MCD_PKT_PRINT(vlan_id,
                "IGMP Test RX IF:%s lif:%d test-kif:%d   Vid:%d  len:%d IP:v:0x%x,ihl:0x%x,len:0x%x,ttl:0x%x,prot:%d,csum:0x%x sip:0x%x dip:0x%x  option:code 0x%x length:%d,val:%d   IGMP:type:0x%x mrt:0x%x csum:0x%x ga:0x%x", 
                l2mcd_if_tree->iname,test_ip_param.rx_phy_port_number, kif, vlan_id, i,
                igmp_pkt->ip_header.version_header_length.version, igmp_pkt->ip_header.version_header_length.header_length,
                igmp_pkt->ip_header.total_length,igmp_pkt->ip_header.time_to_live,
                igmp_pkt->ip_header.protocol, igmp_pkt->ip_header.header_checksum,
                igmp_pkt->ip_header.source_ip_address,igmp_pkt->ip_header.destination_ip_address,
                igmp_pkt->ip_options.code.option_number, igmp_pkt->ip_options.length,igmp_pkt->ip_options.value,
                igmp_pkt->igmp_message.type, igmp_pkt->igmp_message.maximum_response_time, igmp_pkt->igmp_message.checksum, igmp_pkt->igmp_message.group_address);
                receive_igmp_packet(&test_ip_param);
                break;
            }
            else if (ctl_data->cmd & L2MCD_CTL_CMD_PLOG_NAME)
            {
                if (0 !=strncmp(ctl_data->fname, "none", 4))
                {
                    if (g_l2mcd_pkt_fp) 
                    {
                       fclose(g_l2mcd_pkt_fp); g_l2mcd_pkt_fp = NULL;
                       L2MCD_INIT_LOG("Closed vlan debug log File ");
                    }
                    g_l2mcd_pkt_fp =  fopen(ctl_data->fname,"a+");
                    if (!g_l2mcd_pkt_fp)
                    {
                        L2MCD_INIT_LOG("Global Vlan Debug Log File:%s cannot be be opened, vid:%d", ctl_data->fname,ctl_data->vid);
                        g_l2mcd_pkt_fp=NULL;
                    }
                    L2MCD_INIT_LOG("Global Vlan Debug Log File:%s set",ctl_data->fname);
                }
                if (!ctl_data->vid) 
                { 
                    memset(&g_l2mcd_pkt_log[0], 0, L2MCD_VLAN_MAX);
                    L2MCD_INIT_LOG("Global Vlan Debug Log Diabled for all tags");
                    g_l2mcd_dbg_vlan_log_all=FALSE;
                    break;
                }
                if (ctl_data->vid == L2MCD_VLAN_MAX)
                {
                    L2MCD_INIT_LOG("Global Vlan Debug Log Enabled for all tags ");
                    memset(&g_l2mcd_pkt_log[0],1, L2MCD_VLAN_MAX);
                    g_l2mcd_dbg_vlan_log_all=TRUE;
                }
                else 
                {
                    g_l2mcd_pkt_log[ctl_data->vid] = 1;
                }
                if (ctl_data->cmd & L2MCD_CTL_CMD_DB_LEVEL)
                {
                    if (!ctl_data->dbgLevel)
                    {
                        g_l2mcd_pkt_log[ctl_data->vid] = 0;
                        g_l2mcd_dbg_vlan_log_all=FALSE;
                        L2MCD_INIT_LOG("Vlan Debug Log disabled for vid:%d ", g_l2mcd_vlan_log_mask);
                    }
                    else
                    {
                        g_l2mcd_vlan_log_mask = ctl_data->dbgLevel;
                        L2MCD_INIT_LOG("Global Vlan Debug Log bit mask set to %d", g_l2mcd_vlan_log_mask);
                    }
                }
            }
            else if (ctl_data->cmd & L2MCD_CTL_CMD_DB_LEVEL)
            {
                g_l2mcd_cmd_fp =  fopen(ctl_data->fname,"a+");
                if (!g_l2mcd_cmd_fp)
                {
                    L2MCD_LOG_NOTICE("%s %s fopen failed ",__FUNCTION__, ctl_data->fname);
                    break;
                }
                if (ctl_data->dbgLevel<APP_LOG_LEVEL_MAX) 
                {
                    l2mcd_set_loglevel(ctl_data->dbgLevel);
                }
                else 
                {
                    //Enable to direct internal full logs to syslog
                    g_l2mcd_vlan_dbg_to_sys_log= (ctl_data->dbgLevel==APP_LOG_LEVEL_MAX)? 0:1;
                    L2MCD_CLI_PRINT("g_l2mcd_vlan_dbg_to_sys_log set to %d",g_l2mcd_vlan_dbg_to_sys_log);
                }
                fclose(g_l2mcd_cmd_fp);   
            }
            else
            {
                g_l2mcd_cmd_fp =  fopen(ctl_data->fname,"a+");
                if (!g_l2mcd_cmd_fp)
                {
                    L2MCD_LOG_NOTICE("%s %s fopen failed ",__FUNCTION__, ctl_data->fname);
                    break;
                }
                if (ctl_data->cmd & L2MCD_CTL_CMD_DUMP_ALL)
                {
                    l2mcd_print_global_var();
                    l2mcd_dump_cfg(0);
                    dump_mcgrp_class(L2MCD_IPV4_AFI);
                }
                else if (ctl_data->cmd & L2MCD_CTL_CMD_SESS_VID)
                {
                    l2mcd_dump_cfg(ctl_data->vid);
                }
                else if (ctl_data->cmd & L2MCD_CTL_CMD_CUSTOM)
                {
                    l2mcd_dump_custom(ctl_data->cmd_id);
                }
                fclose(g_l2mcd_cmd_fp);   
            
            }
            break;
        }


        default:
            break;
    }
  
}
 
void l2mcd_100ms_timer(evutil_socket_t fd, short what, void *arg)
{
    g_l2mcd_stats_libev_timer++;
    if (0==(g_l2mcd_stats_libev_timer%10))
    {
        mcgrp_service_wheel_timer(L2MCD_IPV4_AFI);
    }
    //if (g_portdb_pending_count) portdb_pending_list();
    //if ((g_l2mcd_stats_libev_timer%100000)==0) L2MCD_LOG_INFO("Timer %d ", g_l2mcd_stats_libev_timer);
}

void l2mcd_libevent_destroy(struct event *ev)
{
    g_l2mcd_stats_libev_no_of_sockets--;
    event_del(ev);
}

/*
 * l2mcd_libevent_create
 *
 * Create a libevent to register a callback for a socket
 */
struct event *l2mcd_libevent_create(struct event_base *base, 
        evutil_socket_t sock,
        short flags,
        void *cb_fn,
        void *arg, 
        const struct timeval *tv,
        int ev_prio)
{
    struct event *ev = 0;
    int prio;

    if (-1 == sock) //100ms timer
    {
        prio = L2MCD_LIBEV_HIGH_PRI_Q;
    }
    else
    {
        prio = L2MCD_LIBEV_LOW_PRI_Q;
        evutil_make_socket_nonblocking(sock);
    }
    if (ev_prio != -1) prio= ev_prio;

    ev = event_new(base, sock, flags, cb_fn, arg);
    if (ev)
    {
        if(-1 == event_priority_set(ev, prio))
        {
            L2MCD_LOG_ERR("event_priority_set failed");
            return NULL;
        }

        if (-1 != event_add(ev, tv))
        {
            g_l2mcd_stats_libev_no_of_sockets++;
            L2MCD_LOG_INFO("Event Added : ev:%p, arg : %s", ev, (char *)arg);
            L2MCD_LOG_INFO("base : %p, sock : %d, flags : %x, cb_fn : %p", base, sock, flags, cb_fn);
            if (tv)
                L2MCD_LOG_INFO("tv.sec : %u, tv.usec : %u", tv->tv_sec, tv->tv_usec);

            return ev;
        }
    }
    return NULL;
}

/* 
 * l2mcd_recv_client_msg
 *
 * Process messages from client sockets
 */
void l2mcd_recv_client_msg(evutil_socket_t fd, short what, void *arg)
{
    char buffer[4096];
    socklen_t len;
    struct sockaddr_un client_sock;

    g_l2mcd_stats_libev_ipc++;

    len = sizeof(struct sockaddr_un);
    len = recvfrom(fd, (void *) buffer, 4096, 0, (struct sockaddr *) &client_sock, &len);
    if (len == -1)
    {
        L2MCD_LOG_INFO("recv  message error %s", strerror(errno));
    }
    else
    {
        L2MCD_LOG_DEBUG("%s Rcvd message len %d", __FUNCTION__, len);
        l2mcd_process_ipc_msg((L2MCD_IPC_MSG *)buffer, len, client_sock);
    }
}

/*
 * l2mcd igmp_tx socket 
 *
 * Create RAW socket for sending IGMP packets
 */
int l2mcd_igmptx_sock_init()
{
    //g_l2mcd_igmp_tx_handle = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
    //g_l2mcd_igmp_tx_handle = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    g_l2mcd_igmp_tx_handle = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);


    if (g_l2mcd_igmp_tx_handle<0)
    {
      L2MCD_LOG_ERR("Failed to create TX socket for IGMP Snooping");  
      g_l2mcd_igmp_tx_handle=0;
      return -1;
    }
    L2MCD_LOG_INFO("Created IGMP TX socket fd:%d", g_l2mcd_igmp_tx_handle);
    L2MCD_INIT_LOG("Created IGMP TX socket fd:%d", g_l2mcd_igmp_tx_handle);
    return 0;
}

void l2mcd_parseRtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {  
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta; 
        }
        rta = RTA_NEXT(rta,len);  
    }
}

/*
 * l2mcd_nl_msg - Netlink Message handler 
 */
void l2mcd_nl_msg(evutil_socket_t fd, short what, void *arg)
{
    struct sockaddr_nl  nl_sa; 
    struct iovec iov; 
    uint8_t buf[8192];
    struct msghdr msg;  
            
    struct nlmsghdr *h;
    struct ifinfomsg *ifi; 
    struct rtattr *tb[IFLA_MAX + 1];
    int if_up=0;
    int if_run=0;
    char *ifName=NULL;
    ssize_t status=0;

    memset(&nl_sa, 0, sizeof(nl_sa));
    iov.iov_base = buf; 
    iov.iov_len = sizeof(buf);
    msg.msg_name = &nl_sa;               
    msg.msg_namelen = sizeof(nl_sa);       
    msg.msg_iov = &iov;                    
    msg.msg_iovlen = 1;    

    status = recvmsg(fd, &msg, 0);
    if (status <0) 
    {
        L2MCD_VLAN_LOG_DEBUG(4095, "%s:%d  event Received status %li", __FUNCTION__, __LINE__, status);
        return;
    }
    
    for (h = (struct nlmsghdr*)buf; status >= (ssize_t)sizeof(*h); ) 
    {
        L2MCD_VLAN_LOG_DEBUG(4095, "NL event Received %d", h->nlmsg_type);
        if (h->nlmsg_type == RTM_NEWLINK)
        {
            if (h->nlmsg_len<0) 
            {
                L2MCD_LOG_NOTICE("NL sock msg_len:%d  len:%d",h->nlmsg_len, status);
                continue;
            } 
            ifi = (struct ifinfomsg*) NLMSG_DATA(h);
            l2mcd_parseRtattr(tb, IFLA_MAX, IFLA_RTA(ifi), h->nlmsg_len);

            if (tb[IFLA_IFNAME]) ifName = (char*)RTA_DATA(tb[IFLA_IFNAME]); 
            if_up = (ifi->ifi_flags & IFF_UP)? 1:0;
            if_run= (ifi->ifi_flags & IFF_RUNNING)? 1:0;
            L2MCD_LOG_NOTICE("IF Event: %s up:%d if_run:%d index:%d", ifName, if_up, if_run, ifi->ifi_index);  
            l2mcd_portstate_update(ifi->ifi_index, if_run, ifName);
        }
        status -= NLMSG_ALIGN(h->nlmsg_len);
        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(h->nlmsg_len));
    }
    return; 
}

static int l2mcd_pkt_rx_batch_proc=1;
#define  L2MCD_MM_SOCKET_BATCH_SIZE  500
#define L2MCD_NSEC_PER_MSEC   1000000UL
static struct iovec iov[L2MCD_MM_SOCKET_BATCH_SIZE][1];
struct mmsghdr mmsg[L2MCD_MM_SOCKET_BATCH_SIZE];
static uint8_t buf[L2MCD_MM_SOCKET_BATCH_SIZE][L2MCD_RX_BUFFER_SIZE];
static struct sockaddr_ll rx_sa[L2MCD_MM_SOCKET_BATCH_SIZE];
typedef union ucmsgbuf_{
    struct cmsghdr cmsg;
    uint8_t buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
} ucmsgbuf;
ucmsgbuf cmsgbuf[L2MCD_MM_SOCKET_BATCH_SIZE];
struct timespec timeout = { .tv_nsec = 10 * L2MCD_NSEC_PER_MSEC, };   
/*
 * l2mcd_recv_igmp_msg
 * 
 * IGMP Packet RX handler
 */
void l2mcd_recv_igmp_msg(evutil_socket_t fd, short what, void *arg)
{
    struct cmsghdr *cmsg;
    struct tpacket_auxdata *auxdata;
    struct msghdr msg, *msg_ptr;
    uint32_t vid=0;
    IGMP_PACKET  *igmp_pkt = NULL;
    size_t len=0;
    L2MCD_IPC_MSG *tx_msg;
    int tx_len=0;
    IP_PARAMETERS  ip_param_data, *ip_param=NULL;
    struct sockaddr_un sockaddr_msg;
    mld_vlan_node_t *vlan_node = NULL;
    char iname1[L2MCD_IFNAME_SIZE];
    int if_index=0;
    l2mcd_if_tree_t *l2mcd_if_tree = NULL;
    int  msg_proc_thread=0;
    int num_pkts=0, i=0;
    struct iphdr *iph;

    if (!l2mcd_pkt_rx_batch_proc)
    {
        iov[0][0].iov_base = buf[0];
        iov[0][0].iov_len = L2MCD_RX_BUFFER_SIZE;
        memset(&msg, 0, sizeof(struct msghdr));
        msg.msg_name = &rx_sa[0];
        msg.msg_namelen = sizeof(struct sockaddr_ll);
        msg.msg_iov = iov[0];
        msg.msg_iovlen = 1;
        msg.msg_control = &cmsgbuf[0];
        msg.msg_controllen = sizeof(ucmsgbuf);
        len = recvmsg(fd, &msg, 0);
        L2MCD_LOG_INFO("%s sock_rx Received %d byte packets", __FUNCTION__, len);
        if (len == -1) return;
        num_pkts=1;
        iph  = (struct iphdr *) (buf[0] + sizeof(struct ether_header));
        msg_ptr = &msg;
    } else {
        for (i = 0; i < L2MCD_MM_SOCKET_BATCH_SIZE; i++) 
        {
            iov[i][0].iov_base = buf[i];
            iov[i][0].iov_len = sizeof(buf[i]);
            mmsg[i].msg_hdr.msg_name = &rx_sa[i];    
            mmsg[i].msg_hdr.msg_namelen = sizeof(rx_sa);
            mmsg[i].msg_hdr.msg_iov = iov[i];
            mmsg[i].msg_hdr.msg_iovlen = 1;
            mmsg[i].msg_hdr.msg_control = cmsgbuf[i].buf;
            mmsg[i].msg_hdr.msg_controllen = sizeof(cmsgbuf[i]);
        }
        num_pkts = recvmmsg(fd, &mmsg[0], L2MCD_MM_SOCKET_BATCH_SIZE, 0, &timeout);
        L2MCD_LOG_NOTICE("%s sock_rx Received %d packets", __FUNCTION__, num_pkts);
        if (num_pkts == -1) return;
    }


    for (i=0;i<num_pkts;i++)
    {
        if (l2mcd_pkt_rx_batch_proc)
        {
            iph  = (struct iphdr *) (buf[i] + sizeof(struct ether_header));
            msg_ptr = &(mmsg[i].msg_hdr);
        }

        if (msg_ptr->msg_flags & MSG_TRUNC) 
        {
            L2MCD_LOG_NOTICE("%s message too large for buffer", __FUNCTION__); 
            continue;
        }
        g_rx_stats_tot_pkts++;


        if (g_l2mcd_rx_is_l2_sock)
        {
            if ((iph->protocol != IPPROTO_IGMP) &&  (iph->protocol != IPPROTO_PIM))
            {
                g_rx_stats_non_igmp_pkts++;
                continue;
            }
        }
        for (cmsg = CMSG_FIRSTHDR(msg_ptr); cmsg != NULL; cmsg = CMSG_NXTHDR(msg_ptr,cmsg))
        {
            auxdata = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
            if (cmsg->cmsg_type != PACKET_AUXDATA) 
            {
                g_rx_stats_no_aux++;
                continue;
            }
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
            {
                struct in_pktinfo *i = (struct in_pktinfo *)CMSG_DATA(cmsg);
                if_index = i->ipi_ifindex;
                if (!if_index) L2MCD_LOG_DEBUG("IP_PKTINFO fd:%d Inv-Ifindex:%d, proto:%d", fd,if_index,iph->protocol);
            }
            if ((cmsg->cmsg_type == PACKET_AUXDATA) && (auxdata->tp_status & TP_STATUS_VLAN_VALID))
            {
                vid = auxdata->tp_vlan_tci &0xFFF;
            }
        }
        if_indextoname(rx_sa[i].sll_ifindex, iname1);
        if (g_l2mcd_rx_is_l2_sock)
        {
            if (!vid)
            {
                g_rx_stats_no_tag++;
                L2MCD_LOG_INFO("RX-IGMP(L2)Vid:%d, IF: %s(%d) proto:%d skip", vid, iname1, rx_sa[i].sll_ifindex,iph->protocol);
                continue;
            }
            vid=(auxdata->tp_vlan_tci &0xFFF);
        }
        else
        {
            if (!if_index)
            {
                g_rx_stats_no_tag++;
            }
            igmp_pkt=(IGMP_PACKET*) buf[i]; 
            l2mcd_if_tree= l2mcd_kif_to_if(if_index);
            if (l2mcd_if_tree) vid = l2mcd_if_tree->ifid;
        }
    
        if (vid<L2MCD_VLAN_MAX)
        {
            vlan_node = mld_vdb_vlan_get(vid, MLD_VLAN);
        }
        if (vlan_node)
        {
            if (!mld_is_flag_set(vlan_node,  L2MCD_IPV4_AFI,  MLD_SNOOPING_ENABLED)) 
            {
                continue;
            }
            if (msg_proc_thread)
            {
                /* Optimization hook -  RX packet needs processed in a seperate thread context */
                tx_len = sizeof(IP_PARAMETERS) + (offsetof(struct L2MCD_IPC_MSG, data));
                tx_msg = (L2MCD_IPC_MSG *)calloc(1, tx_len);
                tx_msg->msg_type = L2MCD_IGMP_PKT_MSG;
                tx_msg->msg_len =  tx_len;
                ip_param = (IP_PARAMETERS *)tx_msg->data;

                igmp_pkt = malloc(sizeof(IGMP_PACKET));
                memcpy(igmp_pkt, (buf[i] + sizeof(struct ether_header)), sizeof(IGMP_PACKET));
            }
            else 
            {
                igmp_pkt   = (IGMP_PACKET *) (buf[i] + sizeof(struct ether_header));
                ip_param = &ip_param_data;
            }
            ip_param->rx_port_number = vlan_node->ifindex;
            ip_param->rx_phy_port_number = rx_sa[i].sll_ifindex;
            ip_param->rx_vlan_id = vid;
            ip_param->source_address = iph->saddr;
            ip_param->destination_address  = iph->daddr;
            ip_param->header_length  = iph->ihl * 4;
            ip_param->total_length = ntohs(iph->tot_len);
            ip_param->time_to_live = iph->ttl;
            ip_param->destination_address = iph->daddr;
            ip_param->vrf_index = L2MCD_DEFAULT_VRF_IDX;
            ip_param->data = igmp_pkt;
            if (msg_proc_thread)
            {
                bzero(&sockaddr_msg, sizeof(sockaddr_msg));
                sockaddr_msg.sun_family = AF_UNIX;
                strncpy(sockaddr_msg.sun_path, L2MCD_IPC_SOCK_NAME, sizeof(sockaddr_msg.sun_path)-1);
                if (sendto(g_l2mcd_igmp_msg_handle, (void*) tx_msg, tx_len, 0, (struct sockaddr *)&sockaddr_msg, sizeof(struct sockaddr_un))<0)
                {
                    L2MCD_PKT_PRINT(vid, "sock send error g_l2mcd_igmp_msg_handle %d,  %s", g_l2mcd_igmp_msg_handle, strerror(errno));
                }
                free(tx_msg);
            }
            else
            {
                l2mcd_if_tree = l2mcd_kif_to_rx_if(rx_sa[i].sll_ifindex);
                if (!l2mcd_if_tree)
                {
                    L2MCD_LOG_NOTICE("%s unknown RX interface :kif:%d iname:%d",__FUNCTION__, rx_sa[i].sll_ifindex,iname1);
                    continue;
                }
                ip_param->rx_phy_port_number = l2mcd_if_tree->ifid;// l2mcd_if_tree1->po_id ? l2mcd_if_tree1->po_id:l2mcd_if_tree->ifid;
                l2mcd_if_tree->rx_pkts++;
                if (iph->protocol == IPPROTO_IGMP)
                {
                    g_rx_stats_igmp_pkts++;
                    L2MCD_PKT_PRINT(vid,
                        "IGMP_RX IF:%s lif:%d kif:%d  iname1:%s Vid:%d IP: v:0x%x,ihl:0x%x,len:0x%x,ttl:0x%x,prot:%d,csum:0x%x sip:0x%x dip:0x%x  option:code 0x%x length:%d,val:%d   IGMP:type:0x%x mrt:0x%x csum:0x%x ga:0x%x", 
                        l2mcd_if_tree->iname,ip_param->rx_phy_port_number, l2mcd_if_tree->kif, iname1, vid,
                        igmp_pkt->ip_header.version_header_length.version, igmp_pkt->ip_header.version_header_length.header_length,
                        igmp_pkt->ip_header.total_length,igmp_pkt->ip_header.time_to_live,
                        igmp_pkt->ip_header.protocol, igmp_pkt->ip_header.header_checksum,
                        igmp_pkt->ip_header.source_ip_address,igmp_pkt->ip_header.destination_ip_address,
                        igmp_pkt->ip_options.code.option_number, igmp_pkt->ip_options.length,igmp_pkt->ip_options.value,
                        igmp_pkt->igmp_message.type, igmp_pkt->igmp_message.maximum_response_time, igmp_pkt->igmp_message.checksum, igmp_pkt->igmp_message.group_address);
                    receive_igmp_packet(ip_param);
                }
                else /*PIM*/
                {
                    g_rx_stats_pim_pkts++;
                    igmp_process_pimv2_packet((char*)iph,ip_param->rx_port_number,ip_param->rx_phy_port_number);
                }
            }
        }
        else
        {

            g_rx_stats_inv_tags++;
        }
    }
    return;
}

int l2mcd_igmprx_sock_close(char *pname, int fd, struct event *igmp_rx_event)
{
    if (!fd) 
    {
        return -1;
    }
    close(fd);
    if (igmp_rx_event)
    {
        l2mcd_libevent_destroy(igmp_rx_event);
        L2MCD_LOG_INFO("RX_Socket_Delete %s fd:%d ev:%p ev_cnt:%d", pname, fd, igmp_rx_event,g_l2mcd_stats_libev_no_of_sockets);
    }
    else
    {
        L2MCD_LOG_INFO("Closed Socket:%d , Event not found",fd);
    }
    return 0;
}

/*
 * l2mcd igmp_rx socket 
 *
 * Create RAW socket for recieving IGMP packets
 */
struct event *l2mcd_igmprx_sock_init(int *fd, char *iname)
{
    int on=1, skmem=1;
    int sock_level,sock_protocol,sock_domain;
    struct sockaddr_ll sa;
    int ifindex=0;
    struct sock_fprog prog;
    struct event *igmp_rx_event = NULL; 
    if (g_l2mcd_rx_is_l2_sock)
    {
        sock_level = SOL_PACKET;
        sock_protocol = htons(ETH_P_ALL);
        sock_domain = PF_PACKET;
    }
    else
    {
        sock_level = IPPROTO_IP;
        sock_protocol = IPPROTO_IGMP;
        sock_domain = AF_INET;
    }

    *fd = socket(sock_domain, SOCK_RAW, sock_protocol);
    if (*fd < 0)
    {
        L2MCD_LOG_ERR("Failed to create RX socket for IGMP Snooping");
        return NULL;
    }
    on=1;
    if (setsockopt(*fd, sock_level, PACKET_AUXDATA, &on, sizeof(on)) <0) 
    {
        L2MCD_INIT_LOG("%s sock_opt PACKET_AUXDATA set failed %s", __FUNCTION__,strerror(errno));
        L2MCD_LOG_ERR("%s sock_opt PACKET_AUXDATA set failed", __FUNCTION__);
        return NULL;
    }

    on=1;
    if (setsockopt(*fd, sock_level, IP_PKTINFO, &on, sizeof(on)) <0) 
    {
        L2MCD_LOG_ERR("%s sock_opt IP_PKTINFO set failed", __FUNCTION__);
        L2MCD_INIT_LOG("%s sock_opt IP_PKTINFO set failed %s",__FUNCTION__,strerror(errno));
        return NULL;
    }
    skmem=8*1024*1024;
    if (setsockopt(*fd, SOL_SOCKET, SO_RCVBUF, &skmem, sizeof(int)) < 0) 
    {
        L2MCD_INIT_LOG("%s sock_opt BUF set failed %s",__FUNCTION__,strerror(errno));
    }
    int tlen=0; socklen_t tlen_size;
    if (getsockopt(*fd, SOL_SOCKET, SO_RCVBUF, &tlen, &tlen_size) < 0) 
    {
    }
    L2MCD_INIT_LOG("RXBUF size %d %d ",tlen,tlen_size);
    if (g_l2mcd_rx_is_l2_sock)
    {
        ifindex = if_nametoindex(iname);
        memset(&sa, 0, sizeof(sa));
        sa.sll_family = AF_PACKET;
        sa.sll_ifindex =ifindex;;
        if (bind(*fd, (struct sockaddr *)&sa, sizeof(sa))<0)
        {
            L2MCD_LOG_ERR("sock_bind_err fd:%d iname:%s err:%s", *fd, iname,strerror(errno));
            L2MCD_INIT_LOG("sock_bind_err fd:%d iname:%s err:%s", *fd, iname,strerror(errno));
        }
        prog.filter = g_igmp_filter;
        prog.len = (sizeof(g_igmp_filter) / sizeof(struct sock_filter));
        if (-1 == setsockopt(*fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog))) {
        L2MCD_INIT_LOG("setsockopt SO_ATTACH_FILTER for (%s) Failed, errno : %s"
                    , iname, strerror(errno));
        }
    }

    /* Add igmp socket to libevent list */
    igmp_rx_event = l2mcd_libevent_create(g_l2mcd_evbase, *fd,
            EV_READ|EV_PERSIST, l2mcd_recv_igmp_msg, (char *)"RX_SOCK", NULL, -1);
    if (!igmp_rx_event)
    {
        L2MCD_LOG_INFO("igmp_rx_event Create failed");
        close(*fd);
        fd = NULL;
        return NULL;
    }
    L2MCD_INIT_LOG("RX_Socket_Create %s fd:%d Ev:%p ev_cnt:%d",  iname, *fd, igmp_rx_event, g_l2mcd_stats_libev_no_of_sockets);
    return igmp_rx_event;
}




/*
 * l2mcd_ipc_init
 *
 * Socket communication to l2mcd config manager
 */
int l2mcd_ipc_init()
{
    struct sockaddr_un sa;
    int ret;
    struct event *ipc_event = NULL; 


    unlink(L2MCD_IPC_SOCK_NAME);
    g_l2mcd_ipc_handle = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (!g_l2mcd_ipc_handle)
    {
        L2MCD_INIT_LOG("sock create fail %s %s", L2MCD_IPC_SOCK_NAME, strerror(errno));
        return -1;
    }
    L2MCD_INIT_LOG("Created socket %s fd:%d", L2MCD_IPC_SOCK_NAME, g_l2mcd_ipc_handle);
    // setup socket address structure
    memset(&sa, 0, sizeof(struct sockaddr_un));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, L2MCD_IPC_SOCK_NAME, sizeof(sa.sun_path) - 1);

    ret = bind(g_l2mcd_ipc_handle, (struct sockaddr *)&sa, sizeof(struct sockaddr_un));
    if (ret == -1)
    {
        L2MCD_LOG_ERR("ipc bind error %s", strerror(errno));
        L2MCD_INIT_LOG("ipc bind error %s", strerror(errno));
        close(g_l2mcd_ipc_handle);
        return -1;
    }

    //Add ipc socket to libevent list
    ipc_event = l2mcd_libevent_create(g_l2mcd_evbase, g_l2mcd_ipc_handle,
            EV_READ|EV_PERSIST, l2mcd_recv_client_msg, (char *)"L2MCD_IPC", NULL, -1);
    if (!ipc_event)
    {
        L2MCD_LOG_ERR("ipc_event Create failed");
        L2MCD_INIT_LOG("ipc_event Create failed");
        return -1;
    }
    L2MCD_INIT_LOG("LibEvent Register for sock fd:%d name:%s",g_l2mcd_ipc_handle,L2MCD_IPC_SOCK_NAME);
    return 0;
}

int l2mcd_unix_sock_create(uint32_t *sock, char *sock_name, int levent)
{
	struct sockaddr_un addr;
    struct event *ipc_event = NULL; 
    int fd;

    // create socket
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd<0) {
        L2MCD_LOG_ERR("%s  Sock %s create error", __FUNCTION__,sock_name);
        L2MCD_INIT_LOG("%s Sock %s create error %s", __FUNCTION__,sock_name,strerror(errno));
		return -1;
    }
    unlink(sock_name);
    bzero(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_name, sizeof(addr.sun_path)-1);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un))<0)
    {
        L2MCD_LOG_ERR("%s  Sock %s bind error", __FUNCTION__,sock_name);
        L2MCD_INIT_LOG("%s Sock %s bind error %s", __FUNCTION__,sock_name,strerror(errno));
        close(fd);
        return -1;
    }
    *sock = fd;
    L2MCD_INIT_LOG("Created socket %s  fd:%d",sock_name,*sock);
    if (!levent)
    {
        return 0;
    }
    ipc_event = l2mcd_libevent_create(g_l2mcd_evbase, fd,
            EV_READ|EV_PERSIST, l2mcd_recv_client_msg, (char *)"IPC", NULL, -1);
    if (!ipc_event)
    {
        L2MCD_LOG_ERR("ipc_event Create failed");
        L2MCD_INIT_LOG("ipc_event Create failed");
        return -1;
    }
    L2MCD_INIT_LOG("LibEvent Register for sock fd:%d name:%s",*sock,sock_name);
    return 0;
}


int port_ifname_db_init()
{
    int i=0, rc=0;
    char ifname[20];
    for (i=0;i<L2MCD_PORTDB_PHYIF_MAX_IDX;i++)
    {
        snprintf(ifname, 20, "Ethernet%d",i);
        rc= portdb_add_ifname(ifname, strlen(ifname) + 1, i+L2MCD_PORTDB_PHYIF_START_IDX);
    }
    for (i=0;i<L2MCD_PORTDB_LAGIF_MAX_IDX;i++)
    {
        snprintf(ifname, 20, "PortChannel%d",i);
        rc= portdb_add_ifname(ifname, strlen(ifname) + 1, i+L2MCD_PORTDB_LAGIF_START_IDX);
    }
    L2MCD_INIT_LOG("%s Done", __FUNCTION__);
    return rc;
}

int l2mcd_nl_init()
{
      struct sockaddr_nl nl_sa = {
        .nl_family = AF_NETLINK,
        .nl_pad    = 0,
        .nl_pid    = 0,
        .nl_groups = RTMGRP_LINK
    };
    struct event *ipc_event = NULL; 
    g_l2mcd_nl_fd =  socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE); 
    if (g_l2mcd_nl_fd<0) 
    {
        L2MCD_INIT_LOG("NetLink socket Init Failed");
        L2MCD_LOG_ERR("NetLink socket Init Failed");
        return -1;
    }
    if (bind(g_l2mcd_nl_fd, (struct sockaddr*)&nl_sa, sizeof(nl_sa)) < 0) 
    {    // bind socket
        L2MCD_INIT_LOG("Failed to bind netlink socket: %s\n", (char*)strerror(errno));
        close(g_l2mcd_nl_fd);
        return -1;
    }   
    //Add ipc socket to libevent list
    ipc_event = l2mcd_libevent_create(g_l2mcd_evbase, g_l2mcd_nl_fd,
                EV_READ|EV_PERSIST, l2mcd_nl_msg, (char *)"L2MCD NL", NULL,-1);
    if (!ipc_event)
    {
        L2MCD_LOG_ERR("ipc_event Create failed");
        L2MCD_INIT_LOG("ipc_event Create failed");
        return -1;
    }
    L2MCD_INIT_LOG("LibEvent Register for NL sock fd:%d ",g_l2mcd_nl_fd);
    return 0;
}


void mcast_global_init(UINT32 afi)
{
    L2MCD_INIT_LOG("Entering %s afi:%d", __FUNCTION__, afi);
    if (afi == IP_IPV4_AFI)
	{
		gMulticast.instances[IPVRF_DEFAULT_VRF_IDX] = pMulticast0;
		gMulticast.instances_list = pMulticast0;
		gMulticast.instances_list_end = pMulticast0;
        pMulticast0->vrf_index = IPVRF_DEFAULT_VRF_IDX;
	}
    return;
}

int mcast_igmp_init()
{
	memset(&gIgmp, 0, sizeof(MCGRP_GLOBAL_CLASS));
    igmp_enable(IPVRF_DEFAULT_VRF_IDX, 0);
	gIgmp.cfg_version=IGMP_VERSION_2;
	mcast_global_init(IP_IPV4_AFI);
	mcgrp_global_pools_init(IP_IPV4_AFI);
	mcgrp_initialize_port_db_array(IP_IPV4_AFI);
	return (0);
}

/*
 * l2mcd_system_init
 *
 * L2MC Daemon Starting Point
 */
int l2mcd_system_init(int flag)
{
    struct event_config *cfg  = NULL;
    struct timeval l2mcd_ipc_msec_50 = { 0, 1*1000 };
    struct timeval l2mcd_100ms_tv = {0, L2MCD_100MS_TIMEOUT};
    struct event   *l2mcd_evtimer_100ms = 0;
    int rc=0;
    char *l2mcd_msg_sock= L2MCD_MSG_SOCK_NAME;

    memset(&l2mcd_context, 0, sizeof(L2MCD_CONTEXT));
    g_l2mcd_vlan_dbg_to_sys_log = FALSE;
    /* Initialize logger */
    APP_LOG_INIT();
    g_curr_dbg_level = APP_LOG_LEVEL_NOTICE;
    g_l2mcd_rx_is_l2_sock = TRUE;

    /* Debug Log Files */
   
    g_l2mcd_init_fp = fopen("/var/log/l2mcd_init.log","w+");
    APP_LOG_SET_LEVEL(g_curr_dbg_level);
    L2MCD_LOG_NOTICE("l2mcd init started user log_level:0x%x flag:0x%x ",g_curr_dbg_level,flag);
    L2MCD_INIT_LOG("Initializing L2MCD with Loglevel::%d flag:0x%x logall_to_syslog:%d",g_curr_dbg_level, flag,g_l2mcd_vlan_dbg_to_sys_log);

    if (flag & 0x1) 
    {
        g_l2mcd_vlan_dbg_to_sys_log= TRUE;
        g_l2mcd_dbg_vlan_log_all=TRUE;
        memset(&g_l2mcd_pkt_log[0],1, L2MCD_VLAN_MAX);
        g_l2mcd_vlan_log_mask =L2MCD_LOG_MASK_INFO|L2MCD_LOG_MASK_DEBUG;
        L2MCD_INIT_LOG("L2MCD vlan debug all on init");
    }
   
    /* IGMP Vlan Database Init */
    rc = mld_vdb_init();
    if (rc <0)
    {
        L2MCD_LOG_ERR(" L2MCD VLAN DB Init failed (error %d)", rc);
        return -1;
    }

    l2mcd_avll_init();
    mcast_igmp_init();
    portdb_init();
    mld_portdb_gvid_hash_init();

    port_ifname_db_init();
    l3_time_freq_init();
    signal(SIGPIPE, SIG_IGN);

    cfg = event_config_new();
    if (!cfg)
    {
        L2MCD_LOG_INFO("%s event_config_new failed", __FUNCTION__);
        L2MCD_INIT_LOG("%s event_config_new failed", __FUNCTION__);
        return -1;
    }
    L2MCD_LOG_INFO("LIBEVENT VER : 0x%x", event_get_version_number());
    L2MCD_INIT_LOG("LIBEVENT VER : 0x%x", event_get_version_number());
    event_config_set_max_dispatch_interval(cfg, &l2mcd_ipc_msec_50/*max_interval*/, -1/*max_callbacks*/, 1/*min-prio*/);

    /* Create event base to attach a event */
    g_l2mcd_evbase = event_base_new_with_config(cfg);
    if (g_l2mcd_evbase == NULL)
    {
        L2MCD_LOG_ERR("event base creation failed");
        L2MCD_INIT_LOG("event base creation failed");
        return -1;
    }
    event_base_priority_init(g_l2mcd_evbase, L2MCD_LIBEV_PRIO_QUEUES);

    /*IGMP Control Packet Transmit Socket*/
    rc = l2mcd_igmptx_sock_init();
    if (rc < 0)
    {
        L2MCD_LOG_ERR("l2mcd IGMNP TX sock init failed %d", rc);
        L2MCD_INIT_LOG("l2mcd IGMNP TX sock init failed %d", rc);
        return -1;
    }
    L2MCD_INIT_LOG("TX Sock Initialized");
    /*Create a Timer Libevent*/
    l2mcd_evtimer_100ms= l2mcd_libevent_create(g_l2mcd_evbase, -1,
            EV_PERSIST, l2mcd_100ms_timer, (char *)"L2MCD 100MS Timer", &l2mcd_100ms_tv, -1);
    if (!l2mcd_evtimer_100ms)
    {
        L2MCD_LOG_ERR("l2mcd_evtimer_100ms create Failed");
        L2MCD_INIT_LOG("l2mcd_evtimer_100ms create Failed");
        return -1;
    }

    if (l2mcd_unix_sock_create(&g_l2mcd_igmp_msg_handle, l2mcd_msg_sock, 0)<0)
    {
        L2MCD_INIT_LOG("igmp_msg_handle sock create failed");
        return -1;
    }
    L2MCD_INIT_LOG("igmp_msg_hanlde:%d sock:%s created ",g_l2mcd_igmp_msg_handle, l2mcd_msg_sock);

    /*IPC Messaging Socket with L2MC Config Manager*/
    rc = l2mcd_ipc_init();
    if (rc <0)
    {
        L2MCD_LOG_ERR("l2mc ipc init failed :%d", rc);
        L2MCD_INIT_LOG("l2mc ipc init failed :%d", rc);
        return -1;
    }
    l2mcd_nl_init();
    L2MCD_LOG_NOTICE("system init done");
    L2MCD_INIT_LOG("system init done");
    event_base_dispatch(g_l2mcd_evbase);
    return 0;
}

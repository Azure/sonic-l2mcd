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

#include <sys/types.h>
#include "l2mcd.h"
#include <linux/filter.h>
#include "mld_vlan_db.h"
#include "l2mcd_mld_utils.h"
#include "l2mcd_mld_port.h"
#include "l2mcd_mcast_co.h"
#include <sys/ioctl.h>
#include "l2mcd_dbsync.h"
#include "l2mcd_portdb.h"

extern  mld_vlan_db_t mld_vlan_db;
extern struct list *snooping_enabled_vlans[MCAST_AFI_MAX];
#define L2MCD_PBUF_SIZE 4000
char pbuf[L2MCD_PBUF_SIZE];

void l2mcd_dump_port_vlan_bm()
{
    l2mcd_if_tree_t *l2mcd_if_tree;
    int i=0;
    int j=0;
    L2MCD_CLI_PRINT("==============================================================================");
    L2MCD_CLI_PRINT("    Iname      if    Member-Vlans");
    L2MCD_CLI_PRINT("===============================================================================");

    for (l2mcd_if_tree = M_AVLL_FIRST(g_l2mcd_kif_to_if_tree); l2mcd_if_tree; l2mcd_if_tree = M_AVLL_NEXT(g_l2mcd_kif_to_if_tree, l2mcd_if_tree->node))
    {
        pbuf[0]='\0';
        for(i=0;i<4096;i++)  if (L2MCD_VLAN_IS_BM_SET(l2mcd_if_tree->bm,i)) { j+= snprintf(pbuf+j, L2MCD_PBUF_SIZE-j,"%d,", i);}
        L2MCD_CLI_PRINT("%14s %6d  %s", l2mcd_if_tree->iname, l2mcd_if_tree->ifid, pbuf);
        j=0;
    }
    L2MCD_CLI_PRINT("=========================================================================");
}

void l2mcd_dump_portdb_tree(int id)
{
    l2mcd_if_tree_t *l2mcd_if_tree;
    struct tpacket_stats lStats = {};
    socklen_t lStatsLength = sizeof( lStats );
    L2MCD_AVL_TREE l2mcd_kif_if_tree =g_l2mcd_kif_to_if_tree;
    l2mcd_kif_if_tree = id? g_l2mcd_if_to_kif_tree:g_l2mcd_kif_to_if_tree;
    if (id) L2MCD_CLI_PRINT("\nIF to KIF Tree:");
    else L2MCD_CLI_PRINT("\nKIF to IF Tree:");
    L2MCD_CLI_PRINT("========================================================================================================================");
    L2MCD_CLI_PRINT("  Interface           Po          ifindex   Kif  Oper  EventPtr   RxPkts  Sk:Id  Sk:Tpkts/Ipkts/Tdrops/Idrops");
    L2MCD_CLI_PRINT("=========================================================================================================================");
    for (l2mcd_if_tree = M_AVLL_FIRST(l2mcd_kif_if_tree); l2mcd_if_tree; l2mcd_if_tree = M_AVLL_NEXT(l2mcd_kif_if_tree, l2mcd_if_tree->node))
    {
        memset(&lStats, 0, sizeof(struct tpacket_stats));
        if (l2mcd_if_tree->sock_fd)
        {
            getsockopt(l2mcd_if_tree->sock_fd, SOL_PACKET, PACKET_STATISTICS, &lStats, &lStatsLength);
            l2mcd_if_tree->sock_pkts +=lStats.tp_packets;
            l2mcd_if_tree->sock_drops+=lStats.tp_drops;
        }
        L2MCD_CLI_PRINT("%14s %14s      %5d %5d %s %10p %5d %5d %d/%d/%d/%d ", 
          l2mcd_if_tree->iname,  l2mcd_if_tree->po_id ? portdb_get_ifname_from_portindex(l2mcd_if_tree->po_id):" ",
          l2mcd_if_tree->ifid, l2mcd_if_tree->kif, l2mcd_if_tree->oper?"UP  ":"DOWN", 
          l2mcd_if_tree->igmp_rx_event, l2mcd_if_tree->rx_pkts, l2mcd_if_tree->sock_fd,l2mcd_if_tree->sock_pkts, lStats.tp_packets,  
          l2mcd_if_tree->sock_drops,lStats.tp_drops);
    }
    L2MCD_CLI_PRINT("=========================================================================");
}
void l2mcd_dump_portdb()
{
    l2mcd_dump_portdb_tree(0);
    l2mcd_dump_portdb_tree(1);
}


void l2mcd_mcgrp_dump_source_list (MCGRP_CLASS   *mcgrp,
                             MCGRP_MBRSHP  *mcgrp_mbrshp)
{
	int            m = 0;
	char          *incl_str[2] = { "X-INC", "Y-EXC" };
	MCGRP_SOURCE  *p_src;
    struct in_addr ipadr;

	if (!mcgrp || !mcgrp_mbrshp)
    {
    	return;
    }
	for (m = FILT_INCL; m <= FILT_EXCL; m++)
	{
		p_src = mcgrp_mbrshp->src_list[m];
		if (p_src == NULL) continue;
		for(; p_src; p_src = p_src->next)
		{
           ipadr.s_addr = htonl(p_src->src_addr.ip.v4addr);
           L2MCD_CLI_PRINT("  %s Source:%s, #re-xmt:%d, Qry-Incl:%s, SrcTmr:%llu, is_remote:%x", 
                           incl_str[m], inet_ntoa(ipadr), 
                           p_src->retx_cnt,((p_src->include_in_query) ? "TRUE" : "FALSE"),
                           (p_src->src_timer -  read_tb_sec()), p_src->is_remote);

		}
	}
}

void l2mcd_dump_groups(int vid, int flag)
{
    mld_vlan_node_t *vlan_node=NULL;
    int vlan_id;
    MCGRP_L3IF   *mcgrp_vport =NULL;
    MCGRP_ENTRY *mcgrp_entry;
    MCGRP_MBRSHP *grp_mbrshp;
    MCGRP_CLASS  *mcgrp=NULL;
    mcgrp = IGMP_GET_INSTANCE_FROM_VRFINDEX(IPVRF_DEFAULT_VRF_IDX);
    struct in_addr ipadr;
    int j=0;
    UINT64  curr_time = read_tb_sec();
   
    L2MCD_CLI_PRINT("\nIGMP GROUPS DETAIL");
    L2MCD_CLI_PRINT("====================================================================");
    for (vlan_node = M_AVLL_FIRST(mld_vlan_db.vdb_tree); vlan_node; vlan_node = M_AVLL_NEXT(mld_vlan_db.vdb_tree, vlan_node->node))
    {
        if (vid && vid!= vlan_node->gvid) continue;
        vlan_id = vlan_node->gvid;
        mcgrp_vport = gIgmp.port_list[vlan_id];
        if (!mcgrp_vport) {L2MCD_CLI_PRINT("mcgroup_vport not available for vlan:%d\n", vlan_id); continue;}
        L2MCD_CLI_PRINT("Vlan:%d mcgrp avl_entry_count:%zu ", vlan_id, L2MCD_AVL_ENTRY_COUNT(mcgrp_vport->sptr_grp_tree));
        for (mcgrp_entry = M_AVLL_FIRST(mcgrp_vport->sptr_grp_tree);
            mcgrp_entry;
            mcgrp_entry = M_AVLL_NEXT(mcgrp_vport->sptr_grp_tree, mcgrp_entry->node))
        {
            ipadr.s_addr = htonl(mcgrp_entry->group_address.ip.v4addr);
            
            if (!flag) 
            {
                j+= snprintf(pbuf+j, L2MCD_PBUF_SIZE-j, "Vlan:%d, GA:%s, Ports: count:%d List:",vlan_id, inet_ntoa(ipadr), mcgrp_entry->num_mbr_ports);
            }
            else
            {
                L2MCD_CLI_PRINT("\nVlan:%d  GA:%s  #Ports:%d  avl_cnt:mbr_ports_tree:%zu",
                    vlan_id, inet_ntoa(ipadr), mcgrp_entry->num_mbr_ports, L2MCD_AVL_ENTRY_COUNT(mcgrp_entry->mbr_ports_tree));
            }
            if (mcgrp_entry->num_mbr_ports)  
            {
                grp_mbrshp = mcgrp_find_first_mbrshp(mcgrp_entry);
                while(grp_mbrshp)
                {
                    if (mcgrp_entry->group_address.afi == IP_IPV4_AFI)
                    {
                        if (!flag)
                        {
                            j+=snprintf(pbuf+j, L2MCD_PBUF_SIZE-j,"%s[%d] ",portdb_get_ifname_from_portindex(grp_mbrshp->phy_port_id),grp_mbrshp->phy_port_id);
                            if (j>=L2MCD_PBUF_SIZE) break;
                        }
                        else 
                        {
                            L2MCD_CLI_PRINT("%s (%d), Filter:%s, Aging:%s HostTmr:%llu/%llu, Tmr:%llu, Retcnt:%d, Static:%s, is_remote:%s, CmpVer:%d",
                            mld_get_if_name_from_ifindex(grp_mbrshp->phy_port_id), grp_mbrshp->phy_port_id, 
                            ((grp_mbrshp->filter_mode == FILT_INCL) ? "INCL" : "EXCL"), 
                            ((grp_mbrshp->aging_enabled) ? "Y" : "N"),
                            (grp_mbrshp->host_present[IGMP_VERSION_1] - curr_time), (grp_mbrshp->host_present[IGMP_VERSION_2] - curr_time),
                            (grp_mbrshp->group_timer - curr_time), (int)grp_mbrshp->retx_cnt,
                            ((grp_mbrshp->static_mmbr) ? "Y" : "N"), (grp_mbrshp->is_remote ? "Y" : "N"), grp_mbrshp->grp_compver); 
                            l2mcd_mcgrp_dump_source_list(mcgrp, grp_mbrshp);
                        }
                    }
                    grp_mbrshp = mcgrp_find_next_mbrshp(mcgrp_entry,grp_mbrshp);
                }
            }
            if (!flag) L2MCD_CLI_PRINT("%s", pbuf);
            j=0;
        }

    }
    L2MCD_CLI_PRINT("=================================================================\n");
}

void l2mcd_dump_vdb_port_list(int vid, int tree_id)
{
    mld_vlan_node_t *vlan_node=NULL;
    int vlan_id;
    MCGRP_PORT_ENTRY* mcgrp_pport = NULL;
    MCGRP_L3IF   *mcgrp_vport =NULL;
    mld_vlan_port_t *vlan_port;
    int j=0;

    L2MCD_CLI_PRINT("\n%s", tree_id?"Vlan Port Tree":"VDB port list");
    L2MCD_CLI_PRINT("===========================================================================");
    L2MCD_CLI_PRINT("VLAN  #Grps  PORT_LIST");
    L2MCD_CLI_PRINT("==========================================================================");
    for (vlan_node = M_AVLL_FIRST(mld_vlan_db.vdb_tree); vlan_node; vlan_node = M_AVLL_NEXT(mld_vlan_db.vdb_tree, vlan_node->node))
    {
        vlan_id = vlan_node->gvid;
        if (vid && vid!= vlan_node->gvid) continue;
        mcgrp_vport = gIgmp.port_list[vlan_id];
        if (!mcgrp_vport) {L2MCD_CLI_PRINT("mcgroup_vport not available for vlan:%d\n", vlan_id); continue;}
        mcgrp_pport = mcgrp_vport->phy_port_list;
        j+= snprintf(pbuf+j, L2MCD_PBUF_SIZE-j,"%4d %4d   ", vlan_node->gvid, mcgrp_vport->ngroups);
        if (!tree_id)
        {
            while(mcgrp_pport)
            {
                j+= snprintf(pbuf+j, L2MCD_PBUF_SIZE-j, "%10s  ", portdb_get_ifname_from_portindex(mcgrp_pport->phy_port_id));
                mcgrp_pport=mcgrp_pport->next; 
            }
        }
        else
        {
            for(vlan_port = M_AVLL_FIRST(vlan_node->port_tree); vlan_port;vlan_port = M_AVLL_NEXT(vlan_node->port_tree, vlan_port->node)) 
            {
                j+= snprintf(pbuf+j, L2MCD_PBUF_SIZE-j, "%10s(%d)  ", portdb_get_ifname_from_portindex(vlan_port->ifindex), vlan_port->ifindex);
            }
        }
        
        L2MCD_CLI_PRINT("%s", pbuf);
        j=0;
    }
    L2MCD_CLI_PRINT("=================================================================\n");
}
void l2mcd_dump_vdb_ports(int vid)
{
    l2mcd_dump_vdb_port_list(vid, 0);
    l2mcd_dump_vdb_port_list(vid, 1);
}
void l2mcd_dump_ve_portdb_tree(void)
{
    portdb_entry_t *port_entry;
    port_link_list_t *head;
    struct in_addr in;
    int j=0;

    L2MCD_CLI_PRINT( "=====================VE PortDB Tree ======================================");
    L2MCD_CLI_PRINT("port-index   Address");
    for (port_entry = M_AVLL_FIRST(gMld.ve_portdb_tree); port_entry; port_entry = M_AVLL_NEXT(gMld.ve_portdb_tree, port_entry->node))
    {
        j+= snprintf(pbuf+j, L2MCD_PBUF_SIZE-j,"%4d  ", port_entry->port_index);
        head = (port_link_list_t *)port_entry->opaque_data;
        while(head)
        {
            in.s_addr=htonl(head->value.ipaddress);
            j+= snprintf(pbuf+j, L2MCD_PBUF_SIZE-j," %s/%d ", inet_ntoa(in),head->value.prefix_length);
            head = head->next;
        }
        L2MCD_CLI_PRINT("%s", pbuf);
        j=0;
    }
    L2MCD_CLI_PRINT( "=====================PortDB Tree ======================================");
    L2MCD_CLI_PRINT("port-index   ifindex");
    L2MCD_CLI_PRINT("==========================================================================");
    for (port_entry = M_AVLL_FIRST(gMld.portdb_tree); port_entry; port_entry = M_AVLL_NEXT(gMld.portdb_tree, port_entry->node))
    {
        j+= snprintf(pbuf+j, L2MCD_PBUF_SIZE-j,"%4u  %lu", port_entry->port_index, port_entry->ifindex);
        L2MCD_CLI_PRINT("%s", pbuf);
        j=0;
    }
    L2MCD_CLI_PRINT("====================================================================\n");
}

void l2mcd_dump_vdb_brief(int vid)
{
    mld_vlan_node_t *vlan_node=NULL;
    mld_cfg_param_t *cfg;
    MCGRP_CLASS  *igmp=NULL;
    igmp = IGMP_GET_INSTANCE_FROM_VRFINDEX(IPVRF_DEFAULT_VRF_IDX);
    
    L2MCD_CLI_PRINT("\nIGMP VLAN Database:");
    L2MCD_CLI_PRINT("===========================================================================================================");
    L2MCD_CLI_PRINT("VLAN Ifindex  VeIfindex  ivid/vid   Ver   QI    LMQI  MRT   FLG       TX-Pkts       RX-Pkts");
    L2MCD_CLI_PRINT("===============================================================================================================");
    for (vlan_node = M_AVLL_FIRST(mld_vlan_db.vdb_tree); vlan_node; vlan_node = M_AVLL_NEXT(mld_vlan_db.vdb_tree, vlan_node->node))
    {
        cfg = mld_vdb_vlan_get_cfg_param(vlan_node, TRUE, MLD_IP_IPV4_AFI);
        if (!cfg) continue;
        if (vid && vid!= vlan_node->gvid) continue;
        L2MCD_CLI_PRINT("%4d 0x%x 0x%x  %d/%d  %3d %5d %5d %5d 0x%x %8d %8d" ,vlan_node->gvid,vlan_node->ifindex, vlan_node->ve_ifindex, vlan_node->ivid, vlan_node->gvid,
        cfg->cfg_version, cfg->cfg_query_interval_time, cfg->LMQ_interval,cfg->max_response_time,vlan_node->flags[0],
        igmp->igmp_stats[vlan_node->gvid].xmt_packets,igmp->igmp_stats[vlan_node->gvid].recv_packets);
    }
    L2MCD_CLI_PRINT("=============================================================================================================\n");
}

void l2mcd_dump_vdb_stats(int vid)
{
    mld_vlan_node_t *vlan_node=NULL;
    MCGRP_CLASS  *igmp=NULL;
    IGMP_STATS *igstats;
    igmp = IGMP_GET_INSTANCE_FROM_VRFINDEX(IPVRF_DEFAULT_VRF_IDX);
    L2MCD_CLI_PRINT("\nIGMP Packet Statistics:");
    L2MCD_CLI_PRINT("===========================================================================================================");
    L2MCD_CLI_PRINT("VLAN  RX/TX   RxQ(1/2/3/g/S)   TxQ(1/2/3/g/S)      Lv   MAry 1/2/3    Inv:Qry/Csum/ssm/Err TxErr PIM");
    L2MCD_CLI_PRINT("===========================================================================================================");
    for (vlan_node = M_AVLL_FIRST(mld_vlan_db.vdb_tree); vlan_node; vlan_node = M_AVLL_NEXT(mld_vlan_db.vdb_tree, vlan_node->node))
    {
        if (vid && vid!= vlan_node->gvid) continue;
        igstats = (IGMP_STATS *)&igmp->igmp_stats[vlan_node->gvid];
        L2MCD_CLI_PRINT("%4d  %d/%d   %d/%d/%d/%d/%d    %d/%d/%d/%d/%d      %d   %d/%d/%d      %d/%d/%d/%d  %d  %5d",
        vlan_node->gvid, igstats->recv_packets, igstats->xmt_packets,
        igstats->igmp_recv_gen_query_msg[0], igstats->igmp_recv_gen_query_msg[1],  igstats->igmp_recv_gen_query_msg[2], 
        igstats->igmp_recv_grp_query_msg,igstats->igmp_recv_grp_src_query_msg,
        igstats->igmp_xmt_gen_query_msg[0],igstats->igmp_xmt_gen_query_msg[1],igstats->igmp_xmt_gen_query_msg[2],
        igstats->igmp_xmt_grp_query_msg,igstats->igmp_xmt_grp_query_msg,
        igstats->igmp_recv_leave_msg,   
        igstats->igmp_recv_membership_ary[0],igstats->igmp_recv_membership_ary[1], igstats->igmp_recv_membership_ary[2],
        igstats->igmp_wrong_ver_query,igstats->recv_checksum_error,igstats->igmp_ssm_map_error,igstats->recv_size_or_range_error, igstats->xmt_error,
        igstats->pim_hello_pkt_rcvd);
    }
     L2MCD_CLI_PRINT("===========================================================================================================\n");
}

void l2mcd_dump_snooping_vlans()
{
    int afi = L2MCD_IPV4_AFI;
    mld_vlan_node_t *vlan_node = NULL;
    struct listnode *node = NULL;
    PORT_ID vport;
    ifindex_t ifindex;
    MCGRP_L3IF *mcgrp_vport = NULL;

    LIST_LOOP(snooping_enabled_vlans[afi - 1], vlan_node, node)
    {
        ifindex = vlan_node->ifindex;
        vport = mld_l3_get_port_from_ifindex(ifindex,vlan_node->type);
        mcgrp_vport = gIgmp.port_list[vport];

        if (!mcgrp_vport)
            continue;

        if (!mld_is_flag_set(vlan_node, afi, MLD_IF_CFLAG_SNOOPING_ENABLED))
            continue;

        L2MCD_CLI_PRINT("\n Vlan ID: %d", vlan_node->ivid);
        L2MCD_CLI_PRINT("\t Querier - %s", is_mld_snooping_querier_enabled(mcgrp_vport) ? "Enabled":"Disabled");
        L2MCD_CLI_PRINT("\t IGMP Operation mode: %s",  (mcgrp_vport->oper_version == 2)?"IGMPv2":(mcgrp_vport->oper_version == 3)?"IGMPv3":"IGMPv1");
        L2MCD_CLI_PRINT("\t Is Fast-Leave Enabled: %s", (CHECK_FLAG(mcgrp_vport->flags, MLD_FAST_LEAVE_CONFIGURED)) ? "Enabled":"Disabled");
        L2MCD_CLI_PRINT("\t Query interval = %d", mcgrp_vport->query_interval_time);
        L2MCD_CLI_PRINT("\t Last Member Query Interval = %d", mcgrp_vport->LMQ_interval*1000);
        L2MCD_CLI_PRINT("\t Max Response time = %d", mcgrp_vport->max_response_time);
        
        print_mrtr_list(vlan_node, afi);
    }
}

void l2mcd_print_global_var()
{
    int j=0,i=0;
    int cnt=0;
	L2MCD_CLI_PRINT( "\n========================================");
	L2MCD_CLI_PRINT( "\tIGMP Global Variables");
	L2MCD_CLI_PRINT( "========================================");
	L2MCD_CLI_PRINT("g_snooping_enabled=%d",gIgmp.g_snooping_enabled);
	L2MCD_CLI_PRINT("no_flood_enable=%d",gIgmp.no_flood_enabled);
	L2MCD_CLI_PRINT("oper_version=%d",gIgmp.oper_version);
	L2MCD_CLI_PRINT("Global Config Version=%d",gIgmp.cfg_version);
	L2MCD_CLI_PRINT("Snooping Vlan Count=%d",gIgmp.mld_snp_vlan_count);
	L2MCD_CLI_PRINT("Global Mac=0x%x:0x%x:0x%x:0x%x:0x%x:0x%x",gIgmp.mac[0],gIgmp.mac[1],gIgmp.mac[2],gIgmp.mac[3],gIgmp.mac[4],gIgmp.mac[5]);
	L2MCD_CLI_PRINT("Pkt Recv-Stats: Total:%d igmp:%d, pim:%d, non-igmp:%d, no_aux:%d, no_tag:%d, inv-tag:%d",
		 g_rx_stats_tot_pkts, g_rx_stats_igmp_pkts, g_rx_stats_pim_pkts, g_rx_stats_non_igmp_pkts,  g_rx_stats_no_aux, g_rx_stats_no_tag, g_rx_stats_inv_tags);
    L2MCD_CLI_PRINT("Log Level : %d, Flags: vlanlog_to_syslog:%d, vlanlog_mask:0x%x, vlan_dbg_log_all:%d g_l2mcd_pkt_fp:%p",
     g_curr_dbg_level, g_l2mcd_vlan_dbg_to_sys_log,g_l2mcd_vlan_log_mask,g_l2mcd_dbg_vlan_log_all,g_l2mcd_pkt_fp);
    L2MCD_CLI_PRINT("g_portdb_pending_count:%d, libev_no_of_sockets:%d",g_portdb_pending_count,g_l2mcd_stats_libev_no_of_sockets);
    L2MCD_CLI_PRINT("Entry Count:");
    L2MCD_CLI_PRINT("\tkif_to_if:%zu, if_to_kif:%zu", L2MCD_AVL_ENTRY_COUNT(g_l2mcd_kif_to_if_tree),L2MCD_AVL_ENTRY_COUNT(g_l2mcd_if_to_kif_tree));
    L2MCD_CLI_PRINT("\tvdb_tree:%zu, ve_portdb_tree:%zu", L2MCD_AVL_ENTRY_COUNT(mld_vlan_db.vdb_tree),L2MCD_AVL_ENTRY_COUNT(gMld.ve_portdb_tree));
    
    L2MCD_CLI_PRINT("Vlan Log Enabled For:");
    if (g_l2mcd_dbg_vlan_log_all)
    {
        L2MCD_CLI_PRINT("All");
    }
    else
    {
        for (i=0;i<L2MCD_VLAN_MAX;i++)
        {
            if (g_l2mcd_pkt_log[i]) {j+= snprintf(pbuf+j, L2MCD_PBUF_SIZE-j,"%d,", i); cnt++;}
            if (cnt>20) {cnt=0; j=0; L2MCD_CLI_PRINT("%s", pbuf);}
        }
        if (cnt) L2MCD_CLI_PRINT("%s", pbuf);
    }
	L2MCD_CLI_PRINT( "========================================\n");
	return;
}
void l2mcd_print_vars()
{
     l2mcd_print_global_var();
}
void l2mcd_dump_custom(int id)
{
    switch(id)
    {
        case 1:
            l2mcd_dump_snooping_vlans();
            break;
        case 2:
            l2mcd_dump_portdb_tree(0);
            break;
        case 3:
            l2mcd_dump_vdb_brief(0);
            break;
        case 4:
            l2mcd_dump_vdb_stats(0);
            break;
        case 5:
            l2mcd_dump_vdb_port_list(0,0);
            break;
        case 6:
            l2mcd_dump_port_vlan_bm();
            break;
        case 7:
            l2mcd_dump_groups(0,0);
            break;
        case 8:
            l2mcd_dump_groups(0,1);
            break;
        case 9:
            l2mcd_dump_ve_portdb_tree();
            break;
        case 10:
            l2mcd_print_global_var();
            break;
        case 11:
            l2mcd_dump_portdb_tree(1);
            break;
        case 12:
            l2mcd_dump_vdb_port_list(0,1);
            break;
        default:
            break;
    }

}

void l2mcd_dump_cfg(int vid)
{
    mld_vlan_node_t *vlan_node=NULL;
    if (vid)
    {
        dump_mcgrpl3if(vid);
   
    }
    else 
    {
        for (vlan_node = M_AVLL_FIRST(mld_vlan_db.vdb_tree); vlan_node; vlan_node = M_AVLL_NEXT(mld_vlan_db.vdb_tree, vlan_node->node))
        {
             dump_mcgrpl3if(vlan_node->gvid);
        }
    }

}


void l2mcd_set_loglevel(int level)
{
    if ((level <=APP_LOG_LEVEL_MAX) && (level>=APP_LOG_LEVEL_MIN))
    {
        
        APP_LOG_SET_LEVEL(level);
        L2MCD_CLI_PRINT("l2mcd debug log level changed from  %d to %d ", g_curr_dbg_level, level);
        g_curr_dbg_level=level;
    }
    else
    {
        L2MCD_CLI_PRINT("Invalid log level:%d", level);
    }
    return;
}

void l2mcd_set_loglevel_w(int level)
{
    l2mcd_set_loglevel(level);

}

void dump_mcgrpl3if(int vid)
{
    VRF_INDEX vrfid;
    MCGRP_L3IF *mcgrp_vport;
    //char *protocol_name;
    mld_vlan_node_t *vlan_node;
    int vport;
    ifindex_t ifindex;
    MCGRP_CLASS *mcgrp;
    //MCGRP_GLOBAL_CLASS *mcgrp_gl;
    MCGRP_STATIC_ENTRY  *static_group;
    sg_port_t *sg_port;
    struct in_addr ipstr_struct;
    MCGRP_ROUTER_ENTRY* rtr_port_list;
    int j=0;

    uint32_t afi=MLD_IP_IPV4_AFI;
    uint8_t vlan_type=MLD_VLAN;

    vrfid = MLD_DEFAULT_VRF_ID;
    mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrfid);
    //mcgrp_gl = (IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld);
    //protocol_name = (afi == MLD_IP_IPV6_AFI ? "MLD" : "IGMP");
    vlan_node = mld_vdb_vlan_get(vid, vlan_type);

    if(!vlan_node){
        //L2MCD_CLI_PRINT(, "vlan node do not exist\n");
        return;
    }

    ifindex = vlan_node->ifindex;
    vport = mld_l3_get_port_from_ifindex(ifindex,vlan_node->type);
    mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vport] :
        gMld.port_list[vport];

    if( !mcgrp_vport){
        L2MCD_CLI_PRINT("MCGRP_L3IF is null for vlan %d\n", vid);
        return;
    }
    L2MCD_CLI_PRINT( "===================VLAN %d=====================\n", vid);
    L2MCD_CLI_PRINT( "dumping MCGRP_L3IF for vlan %d", vid);
    L2MCD_CLI_PRINT( "MCGRP_PORT_ENTRY : %p", mcgrp_vport->phy_port_list);
    L2MCD_CLI_PRINT( "L2MCD_AVL_TREE  sptr_grp_tree : %p", &mcgrp_vport->sptr_grp_tree);
    L2MCD_CLI_PRINT( "ngroups : %d", mcgrp_vport->ngroups);
    L2MCD_CLI_PRINT( "vir_port_id : %d", mcgrp_vport->vir_port_id);
    L2MCD_CLI_PRINT( "phy_port_id : %d", mcgrp_vport->phy_port_id);
    L2MCD_CLI_PRINT( "is_ve : %d", mcgrp_vport->is_ve);
    L2MCD_CLI_PRINT( "cfg_mcast_disable : %d", mcgrp_vport->cfg_mcast_disable);
    L2MCD_CLI_PRINT( "cfg_version : %d", mcgrp_vport->cfg_version);
    L2MCD_CLI_PRINT( "oper_version : %d", mcgrp_vport->oper_version);
    L2MCD_CLI_PRINT( "tracking_enabled : %d", mcgrp_vport->tracking_enabled);
    L2MCD_CLI_PRINT( "is_up : %d\n", mcgrp_vport->is_up);
    L2MCD_CLI_PRINT( "start_up_query_interval : %d", mcgrp_vport->start_up_query_interval);
    L2MCD_CLI_PRINT( "start_up_query_count : %d", mcgrp_vport->start_up_query_count);
    L2MCD_CLI_PRINT( "query_interval_time : %d", mcgrp_vport->query_interval_time);
    L2MCD_CLI_PRINT( "cfg_query_interval_time : %d", mcgrp_vport->cfg_query_interval_time);
    L2MCD_CLI_PRINT( "max_response_time : %d", mcgrp_vport->max_response_time);
    L2MCD_CLI_PRINT( "group_membership_time : %d", mcgrp_vport->group_membership_time); // to be displayed in hh:mm:ss format : TODo
    L2MCD_CLI_PRINT( "older_host_present_time : %d", mcgrp_vport->older_host_present_time);
    L2MCD_CLI_PRINT( "LMQ_interval : %d" , mcgrp_vport->LMQ_interval);
    L2MCD_CLI_PRINT( "LMQ_count : %d", mcgrp_vport->LMQ_count);
    L2MCD_CLI_PRINT( "cfg_robustness_var : %d", mcgrp_vport->cfg_robustness_var);
    L2MCD_CLI_PRINT( "robustness_var : %d" , mcgrp_vport->robustness_var);
    L2MCD_CLI_PRINT( "querier_router : %s", afi == MLD_IP_IPV6_AFI ? 
            mcast_print_addr(&mcgrp_vport->querier_router) : mcast_print_addr(&mcgrp_vport->querier_router));
    L2MCD_CLI_PRINT( "querier : %d", mcgrp_vport->querier);
    L2MCD_CLI_PRINT( "querier_uptime : %llu", mcgrp_vport->querier_uptime); // to be displayed in hh:mm:ss format : TODo
    L2MCD_CLI_PRINT( "MCGRP_TIMER_ELEM");
    L2MCD_CLI_PRINT( "      WheelTimerElement : 0x%p", &mcgrp_vport->vport_tmr.mcgrp_wte);
    L2MCD_CLI_PRINT( "      MCGRP_TIMER_TYPE : 0x%d", mcgrp_vport->vport_tmr.timer_type);
    L2MCD_CLI_PRINT( "      MCGRP_CLASS : %p", mcgrp_vport->vport_tmr.mcgrp);
    L2MCD_CLI_PRINT( "      Union {\n");
    L2MCD_CLI_PRINT( "             MCGRP_TMR_ELEM_CLNT : 0x%p\n", &mcgrp_vport->vport_tmr.wte.clnt);
    L2MCD_CLI_PRINT( "             MCGRP_TMR_ELEM_MBRSHP : 0x%p\n", &mcgrp_vport->vport_tmr.wte.mbrshp);
    L2MCD_CLI_PRINT( "             MCGRP_TMR_ELEM_QUERIER : 0x%p\n", &mcgrp_vport->vport_tmr.wte.pport);
    L2MCD_CLI_PRINT( "             MCGRP_STATIC_ENTRY : 0x%p\n",  mcgrp_vport->vport_tmr.wte.static_grp);
    L2MCD_CLI_PRINT( "             MCGRP_TMR_ELEM_QUERIER : 0x%p\n", &mcgrp_vport->vport_tmr.wte.vport);
    L2MCD_CLI_PRINT( "             MCGRP_STATIC_ENTRY : 0x%p\n", &mcgrp_vport->vport_tmr.wte.l2_static_grp);
    L2MCD_CLI_PRINT( "             MCGRP_TMR_ELEM_MROUTER : 0x%p\n", &mcgrp_vport->vport_tmr.wte.mrtr_port);
    L2MCD_CLI_PRINT( "            }\n");
    L2MCD_CLI_PRINT( "v1_rtr_present : %d", mcgrp_vport->v1_rtr_present);    
    L2MCD_CLI_PRINT( "v2_rtr_present : %d", mcgrp_vport->v2_rtr_present);
    L2MCD_CLI_PRINT( "ve_port_mask : 0x%p", mcgrp_vport->ve_port_mask);
    L2MCD_CLI_PRINT( "static_mcgrp_list_head : 0x%p", mcgrp_vport->static_mcgrp_list_head);
    L2MCD_CLI_PRINT( "rtr_port_list : 0x%p", mcgrp_vport->rtr_port_list);
    L2MCD_CLI_PRINT( "verwarn_intvl_start : %d", mcgrp_vport->verwarn_intvl_start);
    L2MCD_CLI_PRINT( "verwarn_count : %d", mcgrp_vport->verwarn_count);
    L2MCD_CLI_PRINT( "flags : %d", mcgrp_vport->flags);
    L2MCD_CLI_PRINT( "is_l3_up : %d", mcgrp_vport->is_l3_up);
    L2MCD_CLI_PRINT( "pims_enable : %d", mcgrp_vport->pims_enable);
    L2MCD_CLI_PRINT( "pims_num_wg_entries : %d", mcgrp_vport->pims_num_wg_entries);
    L2MCD_CLI_PRINT( "pims_num_sg_entries : %d", mcgrp_vport->pims_num_sg_entries);
    L2MCD_CLI_PRINT( "rx_bad_if : %d\n", mcgrp_vport->rx_bad_if);

    static_group = mcgrp_vport->static_mcgrp_list_head;
    while (static_group) 
    {
        ipstr_struct.s_addr =htonl(static_group->group_address.ip.v4addr);
        for (sg_port = M_AVLL_FIRST(static_group->port_tree);sg_port;sg_port = M_AVLL_NEXT(static_group->port_tree, sg_port->node))
        {
            j+=snprintf(pbuf+j, 25, "%s(0x%x) ", portdb_get_ifname_from_portindex(sg_port->ifindex),sg_port->ifindex);
            if (j>=L2MCD_PBUF_SIZE-20) break;
        }  
        L2MCD_CLI_PRINT("Static-Group:");
        L2MCD_CLI_PRINT("gAddr:%s vid:%d %s", inet_ntoa(ipstr_struct), static_group->port_num, pbuf);
        j=0;
        static_group = static_group->next;
    }
    rtr_port_list=mcgrp_vport->rtr_port_list;
    while(rtr_port_list)
    {
        L2MCD_CLI_PRINT("mrtportr: %s ifindex:0x%x ver:%d static:%d",
        portdb_get_ifname_from_portindex(rtr_port_list->phy_port_id), rtr_port_list->phy_port_id, rtr_port_list->cfg_version, rtr_port_list->is_static);
        rtr_port_list=rtr_port_list->next;
    }
    L2MCD_CLI_PRINT( "========================================\n\n");
    return;
}

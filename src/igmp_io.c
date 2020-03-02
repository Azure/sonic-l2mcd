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

#include "l2mcd_portdb.h"
#include "l2mcd_mld_port.h"
#include "l2mcd_mld_utils.h"
#include "l2mcd_dbsync.h"


#define PREFIX_LIST_NAME_LEN 32 //256
extern MCAST_GLOBAL_CLASS    gMulticast, *pgMulticast;
extern L2MCD_AVL_TREE *mld_portdb_tree;
extern L2MCD_AVL_TREE *ve_mld_portdb_tree;

const static char mcgrp_action_label[][8] =
{
    "NONE",
    "IS_INCL",
    "IS_EXCL",
    "TO_INCL",
    "TO_EXCL",
    "ALW_NEW",
    "BLK_OLD"
};


MADDR_ST global_source_ip; // Who sends this packet ??

UINT8 igmp_eval_version(IGMP_MESSAGE *sptr_igmp_message, UINT16 igmp_packet_size)
{
    UINT8   igmpver = 0;

    switch(sptr_igmp_message->type)
    {
        case IGMP_MEMBERSHIP_QUERY_TYPE:
            IGMP_EVAL_QUERY_VERSION(igmpver, sptr_igmp_message->maximum_response_time, igmp_packet_size);
            break;

        case IGMP_V1_MEMBERSHIP_REPORT_TYPE:
            igmpver = IGMP_VERSION_1;
            break;

        case IGMP_V2_MEMBERSHIP_REPORT_TYPE:
        case IGMP_V2_LEAVE_GROUP_TYPE:
            igmpver = IGMP_VERSION_2;
            break;

        case IGMP_V3_MEMBERSHIP_REPORT_TYPE:
            igmpver = IGMP_VERSION_3;
            break;

        default:
            igmpver = 0;
            break;
    }

    return igmpver;
}

enum BOOLEAN igmp_check_valid_range(UINT32  group_address)
{
    // Addresses 224.0.0/24 are reserved for various control protocols
    // and hence are not valid multicast group addresses

    if ((group_address >= 0xe0000100) && (group_address <= 0xefffffff))
        return TRUE;
    else
        return FALSE;
}

enum BOOLEAN igmp_check_if_checksum_is_valid (IGMP_MESSAGE  *sptr_igmp_message, 
        USHORT message_size)
{
    UINT16 calculated_checksum;

    /* calculate checksum for the whole IGMP message */

    if (sptr_igmp_message->checksum != 0x0000)
    {
        calculated_checksum = calculate_ip_checksum (NULL, (BYTE *) sptr_igmp_message, message_size);

        if (calculated_checksum != 0x0000)
        {
            return (FALSE);
        }
    }
    return (TRUE);
}

void igmp_warn_version_mismatch(MCGRP_PORT_ENTRY* igmp_pport, 
        UINT32 rxver, UINT32 src_addr)
{

}

void igmp_warn_ssm_lower_ver_querier(MCGRP_PORT_ENTRY* igmp_pport, 
        UINT32 src_addr, UINT8 rxver)
{

}

/*-------------------------------------------------------------------------------**
 ** This function is called when a query request is received from another router. **
 ** It checks whether it is IGMP V1 query, if it is then it does nothing.         **
 ** Otherwise  it checks if we need to becomes querier, or whether the state of   **
 ** the group address entry in table need to be changed.                          **
 **-------------------------------------------------------------------------------*/
void igmp_process_query(MCGRP_CLASS *igmp,
        UINT16         vir_port_id,
        UINT32        phy_port_id,
        UINT32         group_address,
        IGMP_MESSAGE* igmp_msg,
        UINT16        igmp_msg_sz,
        UINT32         clnt_src_ip)
{

    MCGRP_L3IF        *igmp_vport = NULL;
    MCGRP_PORT_ENTRY  *igmp_pport = NULL;
    MCGRP_MBRSHP*  igmp_mbrshp;
    IGMPV3_MESSAGE*   igmpv3_msg = (IGMPV3_MESSAGE*) igmp_msg;
    MADDR_ST addr;
    UINT8             rx_max_resp_time = 0;

    UINT8             igmpver;
    UINT16            myver;
    MADDR_ST group_addr, src_addr;

    mcast_init_addr(&group_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
    mcast_set_ipv4_addr(&group_addr, group_address);

    igmp_vport = gIgmp.port_list[vir_port_id];

    igmp_pport  = mcgrp_find_phy_port_entry(igmp, igmp_vport, phy_port_id);

    if (igmp_pport == NULL)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id, "IGMP:%s()%d IGMP.VRF%d.ERR: process_query received pkt on a NULL Port %s,%s\n",FN,LN,
                igmp->vrf_index, mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id));

        return;
    }

    rx_max_resp_time = igmp_msg->maximum_response_time;

    // Determine the query's version 
    IGMP_EVAL_QUERY_VERSION(igmpver, rx_max_resp_time, igmp_msg_sz);

    if (igmp_vport->cfg_version != IGMP_VERSION_NONE &&
            igmpver > igmp_vport->cfg_version)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id, "IGMP:%s:%d IGMP ERR:  ver:%d %d mismatch ",FN,LN,igmp_vport->cfg_version,igmpver);
        return;
    }

    // Update stats
    if (group_address == 0)
        igmp->igmp_stats[vir_port_id].igmp_recv_gen_query_msg[igmpver-1]++;
    else if (igmpver == IGMP_VERSION_2 || igmpv3_msg->num_srcs == 0)
        igmp->igmp_stats[vir_port_id].igmp_recv_grp_query_msg++;
    else
        igmp->igmp_stats[vir_port_id].igmp_recv_grp_src_query_msg++;

    switch (igmpver)
    {
        case IGMP_VERSION_1:
            /* There is at least one IGMP Version 1 Querier on the network,
               so set the opration mode of this box on this network to v1.
             */
            igmp_vport->v1_rtr_present = TRUE;
            break;
        case IGMP_VERSION_2:
            /* There is at least one IGMP Version 2 Querier on the network,
               so set the opration mode of this box on this network to v2.
             */
            igmp_vport->v2_rtr_present = TRUE;
            break;
        case IGMP_VERSION_3:
            // In V3, the max. response time is a max. response code
            // Convert the code into a time value
            rx_max_resp_time = MCGRP_CODE_2_VAL(rx_max_resp_time);
            break;

        default:
            L2MCD_VLAN_LOG_ERR(vir_port_id,"IGMP:%s()%d IGMP.VRF%d.ERR: Failed to determine IGMP version. MRTime %d. PktSz %d.\n",FN,LN,
                    igmp->vrf_index, rx_max_resp_time, igmp_msg_sz);
            return;
            break;
    }

    // Update our operating version if needed
    myver = igmp_vport->oper_version;

    if (igmpver != igmp_vport->oper_version)
    {
        igmp->igmp_stats[vir_port_id].igmp_wrong_ver_query++;
        igmp_warn_version_mismatch(igmp_pport, igmpver, clnt_src_ip);
        L2MCD_VLAN_LOG_ERR(vir_port_id, "%s:%d IGMP version mismatch %d !=%d",FN,LN,igmp_vport->oper_version,igmpver);
        return;
    }


    /* QUERIER evaluation
     *
     * Check if the ip address of the router from whom we have received
     * the query is lower than any of our ip address on the receive port.
     * If it is then we become a non-Querier.
     */
    L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] clnt_src_ip:0x%x ip_on_port:0x%x  ",FN,LN,vir_port_id,
            clnt_src_ip, ip_get_lowest_ip_address_on_port(vir_port_id,igmp_vport->type));

    if ((is_mld_l3_configured(igmp_vport) || is_mld_snooping_querier_enabled(igmp_vport)) &&
            clnt_src_ip &&
            ((!ip_get_lowest_ip_address_on_port(vir_port_id,igmp_vport->type)) || 
             (clnt_src_ip < ip_get_lowest_ip_address_on_port(vir_port_id, igmp_vport->type)) ))
    {
        if ((igmp_vport->querier == TRUE) &&
                (clnt_src_ip != igmp_vport->querier_router.ip.v4addr))
        {
            /*Since this is new querier note down the absolute time when the querier was started*/
            igmp_vport->querier_uptime = read_tb_sec();
        }
        igmp_vport->querier = FALSE;
        igmp_vport->querier_router.ip.v4addr = clnt_src_ip;
        igmp_vport->querier_router.afi = IP_IPV4_AFI;
        L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] Querier_ip:%s ",
                FN, LN, vir_port_id,mcast_print_addr(&igmp_vport->querier_router));

        if (WheelTimerSuccess == WheelTimer_IsElementEnqueued(&igmp_vport->vport_tmr.mcgrp_wte))
        {
            WheelTimer_ReTimeElement(igmp->mcgrp_wtid,
                    &igmp_vport->vport_tmr.mcgrp_wte,
                    (UINT32)OTHER_QUERIER_PRESENT_INTERVAL(igmp_vport));
        }
        else
        {
            // Add to the wheel timer.
            igmp_vport->vport_tmr.timer_type            = MCGRP_WTE_QUERIER;
            igmp_vport->vport_tmr.mcgrp                 = igmp;
            igmp_vport->vport_tmr.wte.vport.mcgrp_vport = igmp_vport;
            igmp_vport->vport_tmr.mcgrp_wte.data        = &igmp_vport->vport_tmr;
            WheelTimer_AddElement(igmp->mcgrp_wtid,
                    &igmp_vport->vport_tmr.mcgrp_wte,
                    (UINT32)OTHER_QUERIER_PRESENT_INTERVAL(igmp_vport));
        }
        if (myver == IGMP_VERSION_3 && igmpver < myver)
        {
            // Req 3.6 (ID: IGMPv3/MLDv2 for SSM)
            // Mehul TBD: Make this a syslog error message
            igmp_warn_ssm_lower_ver_querier(igmp_pport, clnt_src_ip, igmpver);
        }
    }

    // Nothing more to process if this a V1 query
    if (igmpver == IGMP_VERSION_1)
    {
        return;
    }


    /* If this is a GS-Query and we are in non-querier mode, we should
     * update the age of this group, unless ofcourse this is a V3 query
     * with the Suppress-Router bit set
     */
    if (igmp_vport->querier == FALSE)
    {
        if (group_address != 0)
        {
            if (igmpver == IGMP_VERSION_2 ||
                    (igmpv3_msg->suppress_router_process == 0 &&
                     igmpv3_msg->num_srcs == 0 /* i.e. this is a GS and not SS Qry */) )
            {
                MCGRP_MBRSHP* igmp_mbrshp;

                /* Find and update lifetime and state of the group address */
                mcast_init_addr(&addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
                mcast_set_ipv4_addr(&addr, group_address);              
                igmp_mbrshp = mcgrp_find_mbrshp_entry_for_grpaddr(igmp, &addr,
                        vir_port_id,
                        phy_port_id);
                if (igmp_mbrshp)
                {
                    if (rx_max_resp_time < 
                            MCGRP_TIMER_GET_REMAINING_TIME(igmp->mcgrp_wtid,
                                &igmp_mbrshp->mbrshp_tmr.mcgrp_wte))
                    {
                        L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] .ALERT:Modifying grp timer in query processing to %d",FN,LN, 
                                vir_port_id, rx_max_resp_time);
                        igmp_mbrshp->group_timer = read_tb_sec() + rx_max_resp_time;
                        WheelTimer_ReTimeElement(igmp->mcgrp_wtid, 
                                &igmp_mbrshp->mbrshp_tmr.mcgrp_wte, 
                                rx_max_resp_time);
                    }
                }
            }
            else if (igmpv3_msg->suppress_router_process == 0)
            {
                // This is a V3 source-specific query and the suppress bit is not set,
                // so update the source's age

                UINT16 s, num_srcs = igmpv3_msg->num_srcs;
                UINT32* p_srcaddr = igmpv3_msg->source_ary;

                mcast_init_addr(&addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
                mcast_set_ipv4_addr(&addr, group_address);


                igmp_mbrshp = mcgrp_find_mbrshp_entry_for_grpaddr(igmp, &addr,
                        vir_port_id,
                        phy_port_id);

                if (igmp_mbrshp)
                {
                    for (s=0; s < num_srcs; s++, p_srcaddr++)
                    {
                        MCGRP_SOURCE* igmpv3_src;

                        mcast_init_addr(&addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
                        mcast_set_ipv4_addr(&addr, *p_srcaddr); 

                        igmpv3_src = mcgrp_find_source(igmp_mbrshp, &addr, 
                                FILT_INCL);
                        if (igmpv3_src)
                        {
                            igmpv3_src->src_timer = read_tb_sec() + rx_max_resp_time;

                            if (rx_max_resp_time < 
                                    MCGRP_TIMER_GET_REMAINING_TIME(igmp->mcgrp_wtid,
                                        &igmp_mbrshp->mbrshp_tmr.mcgrp_wte))
                            {
                                WheelTimer_ReTimeElement(igmp->mcgrp_wtid, 
                                        &igmp_mbrshp->mbrshp_tmr.mcgrp_wte, 
                                        rx_max_resp_time);
                            }
                        }
                    }
                }
            }
        }

        // Non-querier V3 routers are required to update their notion of Robustness Variable 
        // and Query Interval from the received Query
        if (igmpver == IGMP_VERSION_3)
        {
            // Update the query interval time
            if (igmpv3_msg->query_interval_code != 0)
            {
                igmp->query_interval_time = MCGRP_CODE_2_VAL(igmpv3_msg->query_interval_code);
            }

            // Update the robustness variable
            if (igmpv3_msg->robustness_var != 0)
            {
                igmp->robustness_var = igmpv3_msg->robustness_var;

                if (igmp->robustness_var < IGMP_DEFAULT_ROBUSTNESS_VARIABLE)
                {
                    L2MCD_VLAN_LOG_ERR(vir_port_id,"IGMP:%s()%d IGMP.VRF%d.ERR: [ Port %s,%s. Grp %s ] Rx invalid non-zero robustness variable %d\n",FN,LN,
                            igmp->vrf_index, mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id), mcast_print_addr(&group_addr), 
                            igmpv3_msg->robustness_var);
                    igmp->robustness_var = igmp->cfg_robustness_var;
                }
            }
            else
            {
                igmp->robustness_var = igmp->cfg_robustness_var;
            }
        }
    }
    else
    {
        /* I am the querier */
        if (group_address != 0)
        {
            mcast_set_ipv4_addr(&src_addr, clnt_src_ip);
            L2MCD_VLAN_LOG_ERR(vir_port_id,"IGMP:%s()%d IGMP.VRF%d.ERR: Strange... saw GS-query from %s for %s on port %s when we are querier\n",FN,LN,
                    igmp->vrf_index, mcast_print_addr(&src_addr), mcast_print_addr(&group_addr), mld_get_if_name_from_ifindex(phy_port_id));
        }
    }


    if (is_mld_snooping_enabled(igmp_vport, MCAST_IPV4_AFI) && igmp_vport->phy_port_id != phy_port_id) 
    {
        mcgrp_add_router_port(igmp, igmp_vport, phy_port_id, 0, MLD_PROTO_MROUTER, DEFAULT_MROUTER_AGING_TIME, FALSE);
    }



    /* Generate Proxy IGMP reports for groups learnt over MCT */
    mcast_set_ipv4_addr(&group_addr, group_address);
    if (igmpver == IGMP_VERSION_3)
    {
        UINT16 s, num_srcs = igmpv3_msg->num_srcs;
        UINT32* p_srcaddr = igmpv3_msg->source_ary;
        if (num_srcs)
        {
            for (s=0; s < num_srcs; s++, p_srcaddr++)
            {
                mcast_set_ipv4_addr(&src_addr, *p_srcaddr); 
            }
        }
    }

    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] IGMP.QRY From %s,%s. Grp %s Ver:%d",FN,LN,vir_port_id,
            portdb_get_ifname_from_portindex(phy_port_id), portdb_get_ifname_from_portindex(vir_port_id), mcast_print_addr(&group_addr), igmpver);
    return;

}

void igmp_process_v3_report (MCGRP_CLASS    *igmp, 
        IGMPV3_REPORT  *igmpv3_rep,
        UINT32 len_report,
        UINT16 vir_port_id,
        UINT32 phy_port_id,
        UINT32 clnt_src_ip)
{
    UINT16 g, num_grps = net_to_host_short(igmpv3_rep->num_grps);
    IGMPV3_GROUP_RECORD* grp_rec = igmpv3_rep->group_record;
    UINT32 group_address;
    IGMP_STATS* igmp_stats = &igmp->igmp_stats[vir_port_id];
    MADDR_ST              clnt_ip;
    MCGRP_L3IF           *igmp_vport;
    MADDR_ST             group_addr; //, src_addr;
    MCGRP_PORT_ENTRY *igmp_pport;
    UINT8          igmpver            = IGMP_VERSION_3;
    
    igmp_vport  = gIgmp.port_list[vir_port_id];
    igmp_pport  = mcgrp_find_phy_port_entry(igmp, igmp_vport, phy_port_id);

    if (igmp_vport == NULL || igmp_pport == NULL)
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] [ Port %s (%d),%s ] Ignoring version %d pkt as %s port is not initialized\n",FN,LN,vir_port_id,
                mld_get_if_name_from_ifindex(phy_port_id), phy_port_id,  mld_get_if_name_from_port(vir_port_id), IGMP_VERSION_3,
                (igmp_vport == NULL ? "Vir" : "Phy"));
        return;
    }

    // Ignore PDUs if they are of a higher version than what we are configured to operate
    if (igmp_pport->oper_version < IGMP_VERSION_3)
    {

         L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] [ Port %s(%d),%s ] Ignoring version %d pkt,version mismatch (portver %d)",FN,LN,vir_port_id,
                mld_get_if_name_from_ifindex(phy_port_id), phy_port_id, mld_get_if_name_from_port(vir_port_id), IGMP_VERSION_3,
                igmp_pport->oper_version);
        return;
    }

    mcast_init_addr(&clnt_ip, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
    mcast_set_ipv4_addr(&clnt_ip, clnt_src_ip);
    if (!num_grps)
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] num_groups:%d port:%d", __FUNCTION__, LN, vir_port_id, igmpv3_rep->num_grps,phy_port_id);
    }
                   
    for (g=0; g < num_grps; g++)
    {
         group_address = (UINT32) net_to_host_long(grp_rec->group_address);
         mcast_init_addr(&group_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));        
         mcast_set_ipv4_addr(&group_addr, group_address);
         L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] Port %s,%s(%d) Grp %s, S:%s, num_grps:%d v3_type:%d", __FUNCTION__, LN,  vir_port_id, mld_get_if_name_from_port(vir_port_id), 
                    mld_get_if_name_from_port(phy_port_id), phy_port_id, ipaddr_print_str(&group_addr),ipaddr_print_str(&clnt_ip),num_grps,igmpv3_rep->type);

        if (igmp_check_valid_range(group_address))
        {
            UINT16 num_srcs = net_to_host_short(grp_rec->num_srcs);
            UINT8 v3_action = grp_rec->type;
            UINT32 *src_list = grp_rec->source_address_ary;  //No sources           
            BOOLEAN is_ssm_grp = FALSE;
            UINT16 eff_num_srcs = num_srcs;
            L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d]: Type V3Rept Port %s,%s Grp: %s action %s. #Srcs %u source_ary:0x%x",FN,LN,
                    vir_port_id, mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id), mcast_print_addr(&group_addr), mcgrp_action_label[grp_rec->type], num_srcs,
                    grp_rec->source_address_ary[0]);
            //Source address comes in Network byte order. Convert to host byte order.
            if(num_srcs != 0)
            {
                UINT32 tmp_src = 0;
                int i = 0;
                for(i=0; i < num_srcs ; i++)
                {
                    tmp_src = net_to_host_long(src_list[i]);
                    if(tmp_src == 0)
                    {
                        if(eff_num_srcs >0) eff_num_srcs--;
                        L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] src_list[%d] contains invalid source , skipping/decremented  eff_num_srcs:%d ", FN, LN,vir_port_id,
                                            i, eff_num_srcs);
                        continue;
                    }
                    src_list[i] = tmp_src;
                }
            }
            num_srcs = eff_num_srcs;
            if (((grp_rec->type == IS_EXCL) || (grp_rec->type == TO_EXCL))
                    && 
                    (num_srcs == 0))
            {
            }   // else process the v3 pkt as v3 pkt

            if (grp_rec->type <= IGMP_MAX_ACTION_TYPE)
                igmp_stats->igmpv3_msg_type[grp_rec->type - 1]++; /*The array starts from 0, whereas the enum value for IS_INCL etc., start from 1*/

            /* Currently we dont support V3 EXCL mode. so we ignore if join comes with this list.
             *  statistics are updated
             */
            if (num_srcs && ((grp_rec->type == IS_EXCL) || (grp_rec->type == TO_EXCL)))
            {
                L2MCD_LOG_DEBUG(" IGMP:%s()%d IGMP.VRF%d: Grp:%s with EXCL list is ignored.action %s\n", 
                        FN, LN, igmp->vrf_index, mcast_print_addr(&group_addr), mcgrp_action_label[grp_rec->type]);
                continue;   //goto the next group and process
            }

            /* TR000631856: Start fix: When we have V3 report mode with 0.0.0.0 as source address, we should treat it as a V2 report. */
            if (((v3_action == ALLOW_NEW) || (v3_action == IS_INCL)) && (num_srcs == 0))
            {
                v3_action = IS_EXCL;
                igmpver = IGMP_VERSION_2;   

            }
            if ((v3_action == BLOCK_OLD) && (num_srcs == 0))
            {
                v3_action = TO_INCL;
                igmpver = IGMP_VERSION_2;   

            }
            /* Fix for TR000631856 ends here */

            L2MCD_LOG_DEBUG("IGMP:%s()%d group_addr:%s num_srcs:%d v3_action:%d is_ssm_grp:%d, igmpver=%d ",FN,LN, 
                    mcast_print_addr(&group_addr), num_srcs, v3_action, is_ssm_grp,igmpver );

            mcgrp_update_group_address_table(igmp, vir_port_id, 
                    phy_port_id,
                    &group_addr,
                    &clnt_ip,
                    v3_action,
                    igmpver,
                    num_srcs, (void *)src_list);
            if(v3_action == BLOCK_OLD){
                MADDR_ST src_addr;
                uint32_t i;
                if (num_srcs)
                {
                    for(i = 0; i < num_srcs; i++)
                    {
                        mcast_set_ipv4_addr(&src_addr, src_list[i]);
                    }
                }
                else{
                }
            }
        }
        else
        {
            L2MCD_LOG_DEBUG("IGMP:%s()%d IGMP.VRF%d.ERR: [ Port %s,%s. Grp %s ] Out-of-range address - Rx V3 report dropped\n",FN,LN,
                    igmp->vrf_index, mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id),
                    mcast_print_addr(&group_addr));
        }
        grp_rec = NEXT_GRP_REC(grp_rec);
    }
}

/*--------------------------------------------------------------------------------**
 ** This function is called from receive_igmp_packet_callback() when we receive an IGMP packet **
 ** Or from mcast_mct_process_message_from_peer() when we receive an IGMP message from **
 ** a remote MCT peer. The function validates the received packet and then calls the correct function **
 ** to process the information extracted from the packet further.                  **
 ** Returns a pointer to the packet if it is to be freed, NULL otherwise.
 **--------------------------------------------------------------------------------*/
int receive_igmp_packet (IP_PARAMETERS  *sptr_ip_parameters)
{
    IGMP_PACKET    *sptr_igmp_packet   = (IGMP_PACKET *) sptr_ip_parameters->data;
    USHORT         rx_port_number      = sptr_ip_parameters->rx_port_number;
    UINT32         rx_phy_port         = sptr_ip_parameters->rx_phy_port_number;
    UINT16         igmp_packet_size    = (sptr_ip_parameters->total_length) -  (sptr_ip_parameters->header_length);
    UINT8          igmpver             = IGMP_VERSION_NONE;
    int            vid=0;

    IGMP_MESSAGE  *sptr_igmp_message;
    IP_HEADER     *ip_hdr;
    UINT32         group_address, clnt_src_ip, dest_ip;
    MCGRP_L3IF    *igmp_vport = NULL;
    MCGRP_MBRSHP *igmp_mbrshp;

    VRF_INDEX vrf_index = sptr_ip_parameters->vrf_index;
    MCGRP_CLASS *igmp = IGMP_GET_INSTANCE_FROM_VRFINDEX(vrf_index);
    MCAST_CLASS *multicast = MCAST_GET_INSTANCE_FROM_VRFINDEX(IP_IPV4_AFI, vrf_index);
    MADDR_ST group_addr;
    MADDR_ST       clnt_ip, dest_addr;
    UINT64         init_time =0;
    static UINT32  v1rep_time, v2rep_time, v2leave_time, nreports, nleave;
    BOOLEAN       dbg_enabled = FALSE;

    //init_time = read_tb_msec();

    // rx_phy_port_number is the physical port number
    // rx_port_number is the translated port#
    //    - if the port is part of a VE, it is the VE id,
    //    - if the port is part of a trunk, it is the trunk's primary port#
    //    - otherwise it is the same as the physical port#
    multicast->source_port = sptr_ip_parameters->rx_phy_port_number;
    multicast->source_virtual_port = sptr_ip_parameters->rx_port_number;
    mcast_set_ipv4_addr(&global_source_ip, ntohl(sptr_ip_parameters->source_address));
    
        

    if (trunk_port_state(multicast->source_port) != TRUNK_NONE)
        rx_phy_port = trunk_primary_port(multicast->source_port);
    else
        rx_phy_port = multicast->source_port;


    // Get a pointer to the IP and IGMP packets
    ip_hdr = (IP_HEADER *)&sptr_igmp_packet->ip_header;
    sptr_igmp_message = (IGMP_MESSAGE *) ((char *) ip_hdr + sptr_ip_parameters->header_length);

    group_address = (UINT32) net_to_host_long(sptr_igmp_message->group_address);
    //rx_max_resp_time = sptr_igmp_message->maximum_response_time;
    clnt_src_ip   = ntohl(sptr_ip_parameters->source_address);
    dest_ip = ntohl(sptr_ip_parameters->destination_address);

    mcast_init_addr(&group_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
    mcast_init_addr(&clnt_ip, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
    mcast_set_ipv4_addr(&group_addr, group_address);
    mcast_set_ipv4_addr(&clnt_ip, clnt_src_ip);
    mcast_set_ipv4_addr(&dest_addr, dest_ip);   
    vid = mld_l3_get_port_from_ifindex(rx_port_number,MLD_VLAN);

    L2MCD_VLAN_LOG_INFO(vid,"%s:%d:[vlan:%d] igmp_type:0x%x  rx_port_num:%d port:%s GA:%s DIP:0x%x SIP:0x%x ", 
            FN,LN, vid, sptr_igmp_message->type, sptr_ip_parameters->rx_phy_port_number, portdb_get_ifname_from_portindex(rx_phy_port),
            mcast_print_addr(&group_addr), dest_ip,clnt_src_ip);
    if (l2mcd_is_peerlink(portdb_get_ifname_from_portindex(multicast->source_port)) &&
        (sptr_igmp_message->type != IGMP_MEMBERSHIP_QUERY_TYPE)) {
        L2MCD_VLAN_LOG_ERR(vid,"%s:%d igmp_type:0x%x  Peer link rx_port_num:%d port:%s GA:%s DIP:0x%x SIP:0x%x ", 
            FN,LN, sptr_igmp_message->type, sptr_ip_parameters->rx_phy_port_number, portdb_get_ifname_from_portindex(sptr_ip_parameters->rx_phy_port_number),
            mcast_print_addr(&group_addr), dest_ip,clnt_src_ip);
            goto free_packet;
    }

    if (!MCGRP_IS_VALID_INTF(rx_port_number))
    {
        L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d] : Invalid Rx Port %s. Dropping packet",FN,LN, 
                vid, mld_get_if_name_from_port(rx_port_number));
        goto free_packet;
    }
    if ((igmp_vport = gIgmp.port_list[rx_port_number]) == NULL )
    {
        L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d]  [ Port %s,%s ] ignored received pkt as Port %s is down \n",FN,LN,
                vid, mld_get_if_name_from_ifindex(rx_phy_port), mld_get_if_name_from_port(rx_port_number),
                (igmp_vport == NULL ? mld_get_if_name_from_port(rx_port_number) : mld_get_if_name_from_ifindex(rx_phy_port)));
        igmp->rx_bad_if++;
        goto free_packet;
    }

    if (sptr_igmp_message->type == IGMP_V3_MEMBERSHIP_REPORT_TYPE &&
            dest_ip != IP_IGMPV3_REPORT_ADDRESS)
    {
        L2MCD_VLAN_LOG_ERR(vid,"%s:%d:[vlan:%d] .ERR: Rx Port %s Rcvd V3 Report Type with Des IP addr 0x%x. Dropping packet",FN,LN, 
                vid, mld_get_if_name_from_port(rx_port_number), ntohl(ip_hdr->destination_ip_address));
        goto free_packet;
    }
    igmp->igmp_stats[rx_port_number].recv_packets++;
    if (igmp_packet_size < sizeof(IGMP_MESSAGE))
    {

        L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d] ERR: Rx packet len %d too small. Dropping packet",FN,LN, 
                vid, igmp_packet_size);
        igmp->igmp_stats[rx_port_number].recv_size_or_range_error++;

        goto free_packet;
    }
    if (igmp_check_if_checksum_is_valid (sptr_igmp_message, igmp_packet_size) == FALSE)
    {
        L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d] ERR Rx packet has invalid checksum. Dropping packet",FN,LN, vid);
        igmp->igmp_stats[rx_port_number].recv_checksum_error++;

        goto free_packet;
    }
    igmpver = igmp_eval_version(sptr_igmp_message, igmp_packet_size);

    /*for version greater than 2 router alert needs to be present in all IGMP packet*/
    if(igmpver >= 2)    
    {
        if(igmp->router_alert_check_disable == FALSE)
        {   
            /*Check for Router alert option*/
            if(ip_hdr->version_header_length.header_length <= 5)
            {

                L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d] ERR IGMPv3 reports need to have the router alert option set",FN,LN,vid);
                goto free_packet;
            }

            if(sptr_igmp_packet->ip_options.code.option_number != IP_ROUTER_ALERT_OPTION)
            {

                L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d] ERR IGMPv2/v3 reports need to have the router alert option set",FN,LN,vid);
                goto free_packet;
            }
        }       
    }

    dbg_enabled = 0;
    if (mcast_validate_igmp_packet(sptr_igmp_message, igmp_packet_size, dbg_enabled) == FALSE)
    {
        L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d].ERR: Rx packet is invalid. Dropping packet",FN,LN, vid);
    }

    switch (sptr_igmp_message->type)
    {
        case IGMP_MEMBERSHIP_QUERY_TYPE:

            /* Query process
             *
             * The only reason to process this query is to find out if there is
             * another router with lower address than ourself on the port on which
             * we have received the packet, if there is one then we don't
             * stop sending queries on the port.
             *
             * Also if we are not querier then we need to process group specific query
             * in order to obtain the age time (pkt's max-resp-time) for group.
             *
             * We also check if there is an inconsistency in the version operating
             * on the network - all routers must operate at the same version, which should
             * be the lowest-versioned host's version.
             */
            L2MCD_VLAN_LOG_INFO(vid, "%s:%d:[vlan:%d] IGMP Query Port %s,%s Grp %s",FN,LN,vid,
                    portdb_get_ifname_from_portindex(rx_phy_port), portdb_get_ifname_from_portindex(rx_port_number), mcast_print_addr(&group_addr));
            igmp_process_query(igmp,rx_port_number,
                    rx_phy_port,
                    group_address,
                    sptr_igmp_message,
                    igmp_packet_size,
                    clnt_src_ip);

            break;

        case IGMP_V1_MEMBERSHIP_REPORT_TYPE:
            igmpver = IGMP_VERSION_1;
            igmp->igmp_stats[rx_port_number].igmp_recv_membership_ary[igmpver-1]++;

            L2MCD_VLAN_LOG_INFO(vid,"%s:%d:[vlan:%d] IGMP Type V%d Report Port %s,%s Grp %s",
                    FN,LN,vid, igmpver, mld_get_if_name_from_ifindex(rx_phy_port), mld_get_if_name_from_port(rx_port_number), mcast_print_addr(&group_addr));


        case IGMP_V2_MEMBERSHIP_REPORT_TYPE:

             /*This segment of code is here, because the v1 reports just fall through and call mcgrp_update_group_address_table here
              so need to put this explicit check so that this case is handled properly*/
            if(igmpver == IGMP_VERSION_NONE)
                igmpver = IGMP_VERSION_2;
            igmp->igmp_stats[rx_port_number].igmp_recv_membership_ary[igmpver-1]++;

            L2MCD_VLAN_LOG_INFO(vid,"%s:%d:[vlan:%d]  Type V%d Report, Port:%s,%s  Grp:%s",FN,LN,vid,
                    igmpver, portdb_get_ifname_from_portindex(rx_phy_port), portdb_get_ifname_from_portindex(rx_port_number), mcast_print_addr(&group_addr));



            if (igmp_check_valid_range(group_address))
            {   
                UINT8 v3_action = IS_EXCL;
                UINT16 num_srcs = 0;
                UINT32 *src_list = NULL;  //No sources              
    
                // IGMP_ADD_ADDRESS is equivalent to [ IS_EXCL {} ]
                //TODO: remove log
                igmp_mbrshp = mcgrp_update_group_address_table(igmp,
                        rx_port_number, 
                        rx_phy_port,
                        &group_addr,
                        &clnt_ip,
                        v3_action,
                        igmpver,
                        num_srcs,
                        (void *)src_list);
                if(igmp_mbrshp == NULL)
                    L2MCD_VLAN_LOG_ERR(vid,"%s(%d) igmp_mbrshp is NULL. port:%d GA:%s ", FN, LN,rx_phy_port,mcast_print_addr(&group_addr));

            }
            else
            {

                L2MCD_VLAN_LOG_ERR(vid,"IGMP:%s()%d IGMP.VRF%d.ERR: Pkt ignored as group address %s out of range\n",FN,LN, 
                        vrf_index, mcast_print_addr(&group_addr));
                igmp->igmp_stats[rx_port_number].recv_size_or_range_error++;

            }

            //if (IS_DEBUG_MCGRP_PROFILE(igmp, p_dbg))
            {
                if (IGMP_VERSION_1 == igmpver)
                    v1rep_time += (UINT32) (read_tb_msec() - init_time);
                else
                    v2rep_time += (UINT32) (read_tb_msec() - init_time);

                nreports++;
            }

            if(is_mld_snooping_enabled(igmp_vport, MCAST_IPV4_AFI)) 
            {
                MLD_LOG(MLD_LOGLEVEL7,MLD_IP_IPV4_AFI,"IGMP:%s()%d group_addr:%s send Report to rtr ports",FN,LN, mcast_print_addr(&group_addr));
                group_addr.ip.v4addr = ntohl(group_addr.ip.v4addr);
            }
            break;

        case IGMP_V3_MEMBERSHIP_REPORT_TYPE:

            igmpver = IGMP_VERSION_3;
            igmp->igmp_stats[rx_port_number].igmp_recv_membership_ary[igmpver-1]++;

            if (is_mld_snooping_enabled(igmp_vport, MCAST_IPV4_AFI)) {
                L2MCD_VLAN_LOG_INFO(vid,"%s:%d:[vlan:%d] send V3 Report to Rtr ports", __FUNCTION__, __LINE__,vid);   
            }

            igmp_process_v3_report(igmp, (IGMPV3_REPORT*)sptr_igmp_message,
                    igmp_packet_size,
                    rx_port_number, 
                    rx_phy_port,
                    clnt_src_ip);
            break;

        case IGMP_V2_LEAVE_GROUP_TYPE:

            if (igmp_check_valid_range(group_address))
            {

                mcast_init_addr(&group_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
                mcast_set_ipv4_addr(&group_addr, group_address);
                {
                    //process the v2 leave as v2 leave.
                    igmpver = IGMP_VERSION_2;
                }
                L2MCD_VLAN_LOG_INFO(rx_port_number, "%s:%d:[vlan:%d] IGMP Leave, Type V%d Report Port %s,%s Grp %s\n",
                        FN,LN,rx_port_number, igmpver, portdb_get_ifname_from_portindex(rx_phy_port), 
                        portdb_get_ifname_from_portindex(rx_port_number), mcast_print_addr(&group_addr));


                // IGMP_DELETE_ADDRESS is equivalent to [ IS_INCL {} ]
                mcgrp_update_group_address_table(igmp, rx_port_number,
                        rx_phy_port,
                        &group_addr,
                        &clnt_ip,
                        TO_INCL,
                        igmpver,
                        0, (void *)NULL /* No sources */);
                igmp->igmp_stats[rx_port_number].igmp_recv_leave_msg++;

            }
            else
            {

                igmp->igmp_stats[rx_port_number].recv_size_or_range_error++;

            }

            //if (IS_DEBUG_MCGRP_PROFILE(igmp, p_dbg))
            {
                v2leave_time += (UINT32) (read_tb_msec() - init_time);
                nleave++;
            }
            if(is_mld_snooping_enabled(igmp_vport, MCAST_IPV4_AFI)) {
                /*
                 * Send leave only if fast-leave is configured.
                 * Else send leave post processing GSQ
                 */
                if (is_mld_fast_leave_configured(igmp_vport)) {
                    MLD_LOG(MLD_LOGLEVEL7,MLD_IP_IPV4_AFI,"%s(%d) Send v2 Fast Leave for grp:%s to rtr ports", FN, LN, mcast_print_addr(&group_addr));
                    group_addr.ip.v4addr = ntohl(group_addr.ip.v4addr);
                }
            }

            break;

        default:
            break;                      
    }

free_packet:
    return 0; 
} /* receive_igmp_packet() */


UINT32 ip_get_lowest_ip_address_on_port(UINT16 port_number, uint8_t type)
{
    uint32_t gvid = 0;
    mld_vlan_node_t *vlan_node = NULL;
    UINT32 lowest_ip_address = 0xFFFFFFFF;  /* wwl: add 4 more Fs */
    UINT32 ip_address = 0;
    UINT16 port_id = 0;
    gvid = mld_get_vlan_id(port_number);
    vlan_node = mld_vdb_vlan_get(gvid, type);
    if (vlan_node && vlan_node->ve_ifindex) {
        if(l2mcd_ifindex_is_svi(vlan_node->ve_ifindex)) {
            port_id = l3_get_port_from_ifindex(vlan_node->ve_ifindex);
            ip_address = ve_mld_portdb_get_port_lowest_ipv4_addr_from_list(port_id);
        }   
        else 
            ip_address = mld_portdb_get_port_lowest_ipv4_addr_from_list(port_number);
    }
    if(ip_address < lowest_ip_address)
        lowest_ip_address = ip_address;
    return (lowest_ip_address);
}




BOOLEAN igmp_staticGroup_exists_on_port (IP_ADDRESS  group_addr, 
        PORT_ID     port_id, 
        //PORT_ID phy_port)
        UINT32 phy_port)
{
    VRF_INDEX vrf_index = IP6_PORT_VRF_INDEX(port_id);
    MCGRP_CLASS *igmp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(IP_IPV4_AFI, vrf_index);
    MCGRP_STATIC_ENTRY *igmp_entry = NULL;
    MADDR_ST grp_addr;
    MCGRP_L3IF          *mcgrp_vport = NULL;

    mcast_init_addr(&grp_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
    mcast_set_ipv4_addr(&grp_addr, group_addr);

    if (!igmp)
        return FALSE;

    mcgrp_vport = IS_IGMP_CLASS(igmp) ? gIgmp.port_list[port_id] : gMld.port_list[port_id];
    igmp_entry = mcgrp_vport->static_mcgrp_list_head;

    while (igmp_entry)
    {
        if (igmp_entry->port_num == port_id
                && 
                ((group_addr == 0) 
                 || 
                 (mcast_cmp_addr(&grp_addr, &igmp_entry->group_address) == 0)))
        {
            if (mld_is_member_tree(&(igmp_entry->port_tree), phy_port))
            {
                return TRUE;
            }
        }

        igmp_entry = igmp_entry->next;
    }

    return FALSE;
}

BOOLEAN igmp_update_ssm_parameters(MCGRP_CLASS         *mcgrp,
        MADDR_ST             *group_addr,
        UINT8                *version,
        PORT_ID               vir_port_id,
        UINT32                phy_port_id,
        UINT8                *igmp_action,
        UINT16               *num_srcs,
        UINT32               **src_list)
{
    MCGRP_L3IF          *mcgrp_vport;
    mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vir_port_id] : gMld.port_list[vir_port_id];
    if (mcgrp_vport == NULL || (! mcgrp_vport->is_up) )
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] Got a static group entry on a NULL vir port or vir port down", FN,LN,vir_port_id);
        if (mcgrp_vport)
        {
            L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] vport->is_up :%d", FN,LN,vir_port_id,mcgrp_vport->is_up);
        }
        return FALSE;

    }
    
    *src_list = NULL;           
    *num_srcs = 0;      
    L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] NON SSM group %s.  num_srcs would be 0. \n",FN,LN, vir_port_id, mcast_print_addr(group_addr));
    return TRUE;
}

/*---------------------------------------------------------------------------------------**
 ** This function constructs and send  a given IGMP message on a given port. Both IGMP V1 **
 ** and IGMP V2 messages are supported. The type of message constructed depends on the    **
 ** parameters passed.                                                                    **
 **---------------------------------------------------------------------------------------*/
// klin, BUG 8574, the last query use the default 5 seconds response time,
// but we remove the group in 3 second. Thus, we need a non-default response
// time. If response_time=0, we use default.
BOOLEAN igmp_send_igmp_message (MCGRP_CLASS *igmp,
        UINT16          tx_port_number,
        UINT32          physical_port,     // if valid send to this port only, else send to tx_port_number
        UINT8           type,
        UINT8           version,
        UINT32          group_address,     // 0 => general query
        UINT32          source_address,
        UINT16          response_time,     // 0 means use default
        MCGRP_SOURCE*   src_list,
        BOOLEAN         all_srcs,
        BOOLEAN         is_retx
        )
{
    IP_RX_PKT_MSG  itc_msg;
    IP_HEADER *iph = NULL;
    IP_ROUTER_ALERT_OPTION_BODY *options;
    union mld_in6_cmsg *cmsg;
    MADDR_ST  dest_addr;
    MCGRP_L3IF *mld_vport = gIgmp.port_list[tx_port_number];
    MCGRP_GLOBAL_CLASS *mcgrp_glb = (IS_IGMP_CLASS(igmp) ? &gIgmp : &gMld);
    uint32_t ifindex = 0;
    uint16_t vlan_id=0;
    int ret=0;


    IGMP_MESSAGE *sptr_igmp_message = NULL;
    IGMPV3_MESSAGE *sptr_igmpv3_message = NULL;
    IGMP_PACKET  *sptr_igmp_packet = NULL;
    IGMPV3_PACKET *sptr_igmpv3_packet = NULL;
    USHORT igmp_packet_size = sizeof(IGMP_PACKET);
    USHORT igmp_message_size = sizeof(IGMP_MESSAGE);
    int num_srcs = 0;
    IGMPV3_MESSAGE *igmpv3_msg = NULL;
    MADDR_ST group_addr;
    MADDR_ST source_addr;


    mcast_init_addr(&source_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
    mcast_init_addr(&group_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
    mcast_set_ipv4_addr(&group_addr, group_address);
    mcast_set_ipv4_addr(&source_addr, source_address);

    L2MCD_VLAN_LOG_DEBUG(tx_port_number, "%s:%d:[vlan:%d] type:%d ver:%d G:%s(0x%x),S:%s(0x%x) port:0x%x tx_port:0x%x type:%d", 
            __FUNCTION__, __LINE__, tx_port_number, type, version, mcast_print_addr(&group_addr),group_address, mcast_print_addr(&source_addr),source_address, physical_port,tx_port_number, type);

    if (version == IGMP_VERSION_NONE)
    {

        L2MCD_VLAN_LOG_ERR(tx_port_number,"IGMP:%s()%d IGMP. ERR: [ Port %s,%s, Grp %s ] BUG !!! Request to send a Version None pkt\n",FN,LN,
                 mld_get_if_name_from_ifindex(physical_port), mld_get_if_name_from_port(tx_port_number), mcast_print_addr(&group_addr));
        version = IGMP_VERSION_2;
    }


    if(version == IGMP_VERSION_1 || version == IGMP_VERSION_2)
    {
        sptr_igmp_packet = (IGMP_PACKET*)calloc(1, sizeof(IGMP_PACKET));
        if (sptr_igmp_packet == NULL)
        {

            L2MCD_VLAN_LOG_ERR(tx_port_number,"IGMP:%s()%d IGMP.VRF%d.ERR: Failed to allocate an IP pkt. Transmit failed\n",FN,LN, igmp->vrf_index);
            return FALSE;
        }
        sptr_igmp_message = (IGMP_MESSAGE *)((UINT8 *)sptr_igmp_packet + 
                IP_MINIMUM_HEADER_LENGTH + 
                IP_ROUTER_ALERT_OPTION_LENGTH);
    }
    else if(version == IGMP_VERSION_3) 
    {
        MCGRP_SOURCE *p_src = src_list;

        for(; p_src; p_src = p_src->next) 
        {
            if (is_retx || p_src->retx_cnt == 0)
            {
                num_srcs++;
                // send at most one packet size.
                if (num_srcs >= 365)
                    break;
            }
        }

        //Allocate for L3 IGMP
        sptr_igmpv3_packet = (IGMPV3_PACKET *)calloc(1, (sizeof(IGMPV3_PACKET) +
                    ((num_srcs>1)?((num_srcs-1)*sizeof(UINT32)):0 )));

        if (sptr_igmpv3_packet == NULL)
        {

            L2MCD_VLAN_LOG_ERR(tx_port_number,"IGMP:%s()%d IGMP.VRF%d.ERR: Failed to allocate an IP pkt. Transmit failed\n",FN,LN, igmp->vrf_index);
            return FALSE;
        }
        sptr_igmpv3_message = (IGMPV3_MESSAGE *)((UINT8 *)sptr_igmpv3_packet + 
                IP_MINIMUM_HEADER_LENGTH + 
                IP_ROUTER_ALERT_OPTION_LENGTH);
        num_srcs = 0;   
    }

    // For leave packets the response_time should be 0
    if ((response_time == 0) && (type == IGMP_MEMBERSHIP_QUERY_TYPE))
    {
        response_time = igmp->max_response_time * 10;
    }

    switch (version)
    {
        case IGMP_VERSION_1:
            {
                sptr_igmp_message->maximum_response_time = 0;
                sptr_igmp_message->type = type;
                break;
            }
        case IGMP_VERSION_2:
            {   
                /* the time is in 1/10 of a second */
                sptr_igmp_message->maximum_response_time = (UINT8)response_time;
                sptr_igmp_message->type = type;
                break;
            }
        case IGMP_VERSION_3:
            {
                igmpv3_msg = (IGMPV3_MESSAGE*) sptr_igmpv3_message;
                igmpv3_msg->type = type;
                igmpv3_msg->maximum_response_code = MCGRP_VAL_2_CODE(response_time);

                // Encode the src_list if it is present
                if (src_list) 
                    num_srcs = igmpv3_encode_src_list(igmpv3_msg, src_list, all_srcs, is_retx);
                else
                    num_srcs = 0;


                // Do not send a Grp-Src-Query w/ 0 sources
                if (group_address && src_list && num_srcs == 0)
                {
                    free(sptr_igmpv3_packet);

                    sptr_igmpv3_packet = NULL;

                    L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Skipped Grp-Src-Qry as num_srcs is 0. List %d",
                            FN,LN, tx_port_number, 
                            mld_get_if_name_from_ifindex(physical_port), mld_get_if_name_from_port(tx_port_number), 
                            mcast_print_addr(&group_addr),
                            (src_list != NULL));
                    break;

                }

                igmpv3_msg->reserved = 0;
                igmpv3_msg->suppress_router_process = (response_time > igmp->LMQ_interval);   // RFC 3376 6.6.3.1:
                igmpv3_msg->robustness_var = igmp->cfg_robustness_var;
                igmpv3_msg->query_interval_code = MCGRP_VAL_2_CODE(igmp->cfg_query_interval_time);
                igmpv3_msg->num_srcs = (htons)((UINT16) num_srcs);

                /* 
                 * Size of IGMPv3_packet is 40 bytes with already 4 bytes included 
                 * for holding 1 src_ip.Check IGMPV3_MESSAGE for reference. 
                 */
                igmp_packet_size = sizeof(IGMPV3_PACKET) + ((num_srcs>1)?((num_srcs-1)*sizeof(UINT32)):0);
                igmp_message_size = sizeof(IGMPV3_MESSAGE) + ((num_srcs>1)?((num_srcs-1)*sizeof(UINT32)):0);

                L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d] IGMPv3 num_srcs:%d igmp_packet_size:%d alloc_buff_size:%d igmp_type:%d", 
                    __FUNCTION__, __LINE__, tx_port_number,num_srcs, igmp_packet_size,igmp_message_size,type);
                break;
            }

        default:
            free(sptr_igmp_packet);
            sptr_igmp_packet = NULL;
            break;
    } /* switch (version) */

    if ((sptr_igmp_packet == NULL) && (sptr_igmpv3_packet == NULL))
        return FALSE;

    if (version == IGMP_VERSION_3) {
        sptr_igmpv3_message->group_address = host_to_net_long(group_address);
        sptr_igmpv3_message->checksum = 0x0000;
    } else {
        sptr_igmp_message->group_address = host_to_net_long(group_address);
        sptr_igmp_message->checksum = 0x0000;
    }

    if (version == IGMP_VERSION_3)
    {
        sptr_igmpv3_message->checksum = calculate_ip_checksum (NULL, (BYTE *)
                sptr_igmpv3_message, igmp_message_size);
    }
    else
    {
        sptr_igmp_message->checksum = calculate_ip_checksum (NULL, (BYTE *) 
                sptr_igmp_message, igmp_message_size);
    }
    cmsg = calloc (1, sizeof(union mld_in6_cmsg));
    ifindex = portdb_get_port_ifindex(mld_portdb_tree, tx_port_number);
    if(l2mcd_ifindex_is_physical(ifindex)) 
    {
        cmsg->vaddr.vlanid = mld_portdb_get_ivid_from_gvid(ifindex, MLD_ROUTE_PORT);
    }
    else
    {
        cmsg->vaddr.vlanid = mld_get_ivid_vport(tx_port_number,MCAST_IPV4_AFI);
    }
    cmsg->vaddr.port = physical_port;
    vlan_id = cmsg->vaddr.vlanid;

    /* Leave sent by switch should have system mac and not host mac as TTL is 1 */
    if ((type == IGMP_V2_LEAVE_GROUP_TYPE) || (type == IGMP_V2_MEMBERSHIP_REPORT_TYPE) ||
            (type == IGMP_V1_MEMBERSHIP_REPORT_TYPE)) {
        memcpy (cmsg->vaddr.src_mac, mcgrp_glb->mac, ETHER_ADDR_LEN);
    }

    if (version == IGMP_VERSION_3)
        iph = (IP_HEADER *)sptr_igmpv3_packet;
    else
        iph = (IP_HEADER *)sptr_igmp_packet;
    /* Populate the messasge structure */
    memset(&itc_msg, 0, sizeof (itc_msg));
    if (group_address == 0)
    {
#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
        iph->destination_ip_address =
            IP_ALL_NODES_MULTICAST_ADDRESS;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
        iph->destination_ip_address =
            htonl(IP_ALL_NODES_MULTICAST_ADDRESS);
#endif  /*__BYTE_ORDER == __BIG_ENDIAN */
#else 
#error "Byte order not define"
#endif 
    }
    else
    {
        if (type == IGMP_V2_LEAVE_GROUP_TYPE) {
#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
            iph->destination_ip_address = IP_ALL_ROUTERS_MULTICAST_ADDRESS;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
            iph->destination_ip_address =
                htonl(IP_ALL_ROUTERS_MULTICAST_ADDRESS);
#endif  /*__BYTE_ORDER == __BIG_ENDIAN */
#else
#error "Byte order not define"
#endif
        } else {
#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
            iph->destination_ip_address = group_address;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
            iph->destination_ip_address = htonl(group_address);
#endif  /*__BYTE_ORDER == __BIG_ENDIAN */
#else 
#error "Byte order not define"
#endif 
        }

    }
#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
    iph->source_ip_address = source_address;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    iph->source_ip_address = htonl(source_address);
#endif  /*__BYTE_ORDER == __BIG_ENDIAN */
#else 
#error "Byte order not define"
#endif 

    iph->version_header_length.version = IP_VERSION_NUMBER; //4 
    iph->version_header_length.header_length = (IP_MINIMUM_HEADER_LENGTH_BYTE +  IP_ROUTER_ALERT_OPTION_LENGTH) >> 2; //5 + 1 word
    iph->time_to_live = 1;
    iph->protocol = IGMP_PROTOCOL;
    iph->service_type.precedence = 6;
    iph->fragment_offset_least_significant_part = FALSE;
    iph->total_length = htons(igmp_packet_size); // + IP_ROUTER_ALERT_OPTION_LENGTH);

    if (version == IGMP_VERSION_3)
    {
        options = (IP_ROUTER_ALERT_OPTION_BODY *)((UINT8 *)sptr_igmpv3_packet + IP_MINIMUM_HEADER_LENGTH);
    }
    else
    {
        options = (IP_ROUTER_ALERT_OPTION_BODY *)((UINT8 *)sptr_igmp_packet + IP_MINIMUM_HEADER_LENGTH);
    }
    uint8_t option_type = IP_ROUTER_ALERT_OPTION_TYPE;
    memcpy(&options->code, &option_type, sizeof(uint8_t));  
    options->length = IP_ROUTER_ALERT_OPTION_LENGTH;
    itc_msg.ip_param.source_address = source_address;
    itc_msg.ip_param.rx_port_number = tx_port_number;
    iph->header_checksum = calculate_ip_checksum(NULL, (BYTE*)iph, (sizeof(IP_HEADER) + IP_ROUTER_ALERT_OPTION_LENGTH));//iph->version_header_length.header_length);

    itc_msg.ip_param.vrf_index = 1;
    itc_msg.ip_param.rx_phy_port_number = physical_port;
    if (version == IGMP_VERSION_3)
        itc_msg.ip_param.data = sptr_igmpv3_packet;
    else
        itc_msg.ip_param.data = sptr_igmp_packet;

    itc_msg.ip_param.total_length = igmp_packet_size; // + IP_ROUTER_ALERT_OPTION_LENGTH;
    itc_msg.header.msg_instance_id = (unsigned long)cmsg;

    L2MCD_VLAN_LOG_DEBUG(tx_port_number, "%s:%d:[vlan:%d] Tx dstip:0x%x srcip:0x%x iphlen:%d tot:%d chksum:0x%x phy_p:0x%x type:%d ver:%d group_adress:%d vlan:%d",
            __FUNCTION__, __LINE__, tx_port_number, ntohl(iph->destination_ip_address), 
            ntohl(iph->source_ip_address), iph->version_header_length.header_length, 
            ntohs(iph->total_length), ntohs(iph->header_checksum), 
            itc_msg.ip_param.rx_phy_port_number, type, version, group_address,vlan_id);

    if (type == IGMP_MEMBERSHIP_QUERY_TYPE && group_address == 0)
    {
        mcast_set_ipv4_addr(&dest_addr,  iph->destination_ip_address);
        ret=l2mcd_send_pkt (&itc_msg, physical_port != PORT_INDEX_INVALID ? physical_port : 0, vlan_id,  &dest_addr, igmp, mcgrp_glb,
                           0, (physical_port == PORT_INDEX_INVALID));
    } else if (type == IGMP_MEMBERSHIP_QUERY_TYPE && group_address) {
        mcast_set_ipv4_addr(&dest_addr, iph->destination_ip_address);
        ret=l2mcd_send_pkt (&itc_msg, (physical_port != PORT_INDEX_INVALID) ? physical_port :0, vlan_id, &dest_addr, igmp, mcgrp_glb,
                            0, (physical_port == PORT_INDEX_INVALID));
    } else if ((type == IGMP_V2_LEAVE_GROUP_TYPE) || (type == IGMP_V2_MEMBERSHIP_REPORT_TYPE) || (type == IGMP_V1_MEMBERSHIP_REPORT_TYPE)) {
        mcast_set_ipv4_addr(&dest_addr, iph->destination_ip_address);
        mld_tx_reports_leave_rcvd_on_edge_port(&itc_msg, &dest_addr, igmp, mld_vport);
    } else {
        mcast_set_ipv4_addr(&dest_addr, iph->destination_ip_address);
        ret=l2mcd_send_pkt(&itc_msg, (physical_port != PORT_INDEX_INVALID) ? physical_port : 0, vlan_id, &dest_addr, igmp, mcgrp_glb,
                            0 , (physical_port == PORT_INDEX_INVALID)); 
    }

    if (physical_port == PORT_INDEX_INVALID)
    {
        igmp->igmp_stats[tx_port_number].xmt_packets++;
    }
    else
    {
        igmp->igmp_stats[tx_port_number].xmt_packets++;
    }
   if (ret ==-1)  igmp->igmp_stats[tx_port_number].xmt_error++;

    L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d] IGMP.type:%d: [ Port %s(%d),  %s(%d) Grp 0x%x ] Sent version %d Query. size %d. Src 0x%x vlan:%d",FN,LN,
            tx_port_number,type, portdb_get_ifname_from_portindex(physical_port), physical_port, portdb_get_ifname_from_portindex(tx_port_number), tx_port_number,
            group_address,
            version,
            igmp_message_size,
            source_address,vlan_id);


    free(sptr_igmp_packet);
    free(cmsg);

    return TRUE;
}

void igmp_send_general_query( MCGRP_CLASS *igmp, 
        UINT16       tx_port_number,
        //    UINT16       physical_port,
        UINT32       physical_port,
        UINT8        version,
        UINT32       use_src,
        UINT16       response_time)
{
    UINT32 src_ip = 0;
    //uint32_t ifindex = 0;
    uint32_t gvid = 0;
    int port_id = 0;
    mld_vlan_node_t *vlan_node = NULL;
    MCGRP_L3IF        *mld_vport;   
    port_link_list_t *sptr_addr_entry = NULL;

    MADDR_ST src_addr;


    /*
     * Note : Here tx_port_number is based out of vlan_id ifindex.
     * If vlan has a Ve associated then, retrieve the Ve_port_id and
     * see whether there is any IP address associated with this ve_port_id
     * in mld_portdb_tree/ve_mld_portdb_tree.
     * This is needed when Vlan and VE ID are different.
     * When Vlan and VE are same id then, tx_port_number will be same.
     */
    mld_vport = IS_IGMP_CLASS(igmp) ? gIgmp.port_list[tx_port_number] : gMld.port_list[tx_port_number];
    if(mld_vport == NULL)
    {
        L2MCD_VLAN_LOG_ERR(tx_port_number,"%s mld_vport not found for %d", FN,tx_port_number);
        return;
    }
    gvid = mld_get_vlan_id(tx_port_number);
    vlan_node = mld_vdb_vlan_get(gvid, mld_vport->type);
    if (vlan_node && vlan_node->ve_ifindex) {
        if(l2mcd_ifindex_is_svi(vlan_node->ve_ifindex)) 
        {
            port_id = mld_l3_get_port_from_ifindex(vlan_node->ve_ifindex, vlan_node->type);
            sptr_addr_entry = (port_link_list_t *)(portdb_get_port_lowest_ipv4_addr_from_list(ve_mld_portdb_tree, port_id));
            L2MCD_VLAN_LOG_DEBUG(tx_port_number, "%s:%d:[vlan:%d] ifindex:0x%x ve_ifindex:0x%x port:0x%x", FN, LN, tx_port_number,vlan_node->ifindex, vlan_node->ve_ifindex,port_id);
        }
        else {
            //Router Port IP address
            port_id = tx_port_number;
            sptr_addr_entry = (port_link_list_t *)(portdb_get_port_lowest_ipv4_addr_from_list(mld_portdb_tree, port_id));
            L2MCD_VLAN_LOG_DEBUG(tx_port_number, "%s:%d:[vlan:%d] Router ifindex:0x%x port:0x%x ", FN, LN, tx_port_number, vlan_node->ifindex,port_id);
        }
    }


    L2MCD_VLAN_LOG_DEBUG(tx_port_number, "%s:%d:[vlan:%d] phy_port:0x%x version:%d vlan:%d ", 
            __FUNCTION__, __LINE__, tx_port_number, physical_port, version,gvid);   

    if (!sptr_addr_entry) {
        if (igmp_send_igmp_message(igmp, tx_port_number,
                    physical_port,
                    IGMP_MEMBERSHIP_QUERY_TYPE,
                    version,
                    0,                 // general query
                    0,
                    response_time,
                    NULL, FALSE,       // no srcs
                    FALSE)) // not retx
        {
            L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d] [ Port %d ] Sent General Query version %d using src 0x%x", FN, LN,
                    tx_port_number, physical_port, version, src_ip);
            // Update stats
            if (physical_port == PORT_INDEX_INVALID)
                igmp->igmp_stats[tx_port_number].igmp_xmt_gen_query_msg[version-1]++;
            else
                igmp->igmp_stats[tx_port_number].igmp_xmt_gen_query_msg[version-1]++;
        } else {
            L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d][ Port %d ] Skipped General Query version %d using src 0x%x\n",FN,LN,
                    tx_port_number, physical_port, version, src_ip);
        }
    } else {
        while(sptr_addr_entry != NULL)
        {
            if (use_src == 0)
                src_ip = sptr_addr_entry->value.ipaddress;
            else
                src_ip = use_src;
            mcast_init_addr(&src_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
            mcast_set_ipv4_addr(&src_addr, src_ip);

            L2MCD_VLAN_LOG_DEBUG(tx_port_number, "%s:%d:[vlan:%d] Outoing IGMP Query src_ip:0x%x version:%d ", FN, LN, tx_port_number,src_ip, version);

            if (igmp_send_igmp_message(igmp, tx_port_number,
                        physical_port,
                        IGMP_MEMBERSHIP_QUERY_TYPE, 
                        version,
                        0,                 // general query
                        src_ip,
                        response_time,
                        NULL, FALSE,       // no srcs
                        FALSE))            // not retx
            {

                L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d]: [ Port %d ] Sent General Query version %d using src 0x%x, src_entry:0x%x",FN,LN, 
                        tx_port_number, physical_port, version, src_ip,sptr_addr_entry->value.ipaddress);          
                igmp->igmp_stats[tx_port_number].igmp_xmt_gen_query_msg[version-1]++;
            } else {
                L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d]: [ Port %s,%s ] Skipped General Query version %d using src %x",FN,LN, 
                        tx_port_number, mld_get_if_name_from_ifindex(physical_port), mld_get_if_name_from_port(tx_port_number),    version, src_ip);           
            }
            // If we were requested to send packet on a specific subnet, we are done; break
            if (use_src != 0)
                break;
            sptr_addr_entry = sptr_addr_entry->next;

        }
    }
}


typedef struct s_IGMP_CLNT_LV_PARAM
{
    MCGRP_L3IF*        igmp_vport;
    MCGRP_MBRSHP*      igmp_mbrshp;
    UINT32             group_addr;
    SORTED_LINKLIST**  src_list;
    BOOLEAN            was_excl;
    UINT32             clnt_ip_addr;

} IGMP_CLNT_LV_PARAM;


static UINT32 igmp_track_v2_clnt_leave (MCGRP_CLASS         *igmp, 
        IGMP_CLNT_LV_PARAM  *p_param)
{
    UINT32 group_address         = p_param->group_addr;
    MCGRP_MBRSHP* igmp_mbrshp = p_param->igmp_mbrshp;
    MCGRP_L3IF    *igmp_vport      = p_param->igmp_vport;
    MADDR_ST group_addr, src_addr;
    //DEBUG_MCGRP *p_dbg = &debugGlobal.ip.igmp;


    igmpv3_destroy_client(igmp, &igmp_mbrshp->clnt_tree, p_param->clnt_ip_addr);

    if (M_AVLL_FIRST(igmp_mbrshp->clnt_tree) == NULL)
    {
        mcast_init_addr(&group_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));        
        mcast_init_addr(&src_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));      
        mcast_set_ipv4_addr(&group_addr, group_address);
        mcast_set_ipv4_addr(&src_addr, p_param->clnt_ip_addr);
        L2MCD_LOG_DEBUG("IGMP:%s()%d IGMP.VRF%d: [ Port %s,%s. Grp %s ] Fast-deleting grp on last client Leave %x \n",FN,LN, 
                igmp->vrf_index, igmp_mbrshp->phy_port_id, igmp_vport->vir_port_id,
                mcast_print_addr(&group_addr), p_param->clnt_ip_addr);          
        return 1;   // delete group membership
    }

    return 0;
}

BOOLEAN igmp_send_group_query(MCGRP_CLASS     *igmp, 
        MCGRP_MBRSHP*    igmp_mbrshp,
        UINT16           tx_port_number,
        UINT32           physical_port,
        UINT8            version,
        UINT32           group_address,
        UINT32           src_ip,
        UINT32           clnt_ip_addr,
        BOOLEAN          is_retx)
{
    BOOLEAN grp_deleted = FALSE;
    MADDR_ST group_addr, src_addr;
    MCGRP_L3IF        *igmp_vport = NULL;
    MCGRP_PORT_ENTRY  *igmp_pport = NULL;
    //DEBUG_MCGRP *p_dbg = &debugGlobal.ip.igmp;
    UINT32  response_time = 0;

    igmp_vport  = gIgmp.port_list[tx_port_number];
    igmp_pport  = mcgrp_find_phy_port_entry(igmp, igmp_vport, physical_port);

    if (igmp_vport->LMQ_100ms_enabled == TRUE)
    {
        // LMQI is msec. convert as per RFC response time in pkt
        response_time = (igmp_vport->LMQ_interval * 10)/1000;
    }
    else
    {   
        // convert as per RFC response time in pkt
        response_time = (igmp_vport->LMQ_interval * 10);
    }

    if(igmp_vport == NULL)
    {
        return grp_deleted; 
    }

    if(igmp_pport == NULL)
    {
        MLD_LOG(MLD_LOGLEVEL7,MLD_IP_IPV4_AFI,
                "IGMP:%s()%d  [ Port %d ] igmp_pport is NULL. ",FN,LN, 
                physical_port);
        return grp_deleted; 
    }

    if (igmp_vport->tracking_enabled &&
            igmp_pport->oper_version == IGMP_VERSION_2 && clnt_ip_addr)
    {
        IGMP_CLNT_LV_PARAM clnt_param;

        clnt_param.igmp_vport   = igmp_vport;
        clnt_param.igmp_mbrshp  = igmp_mbrshp;
        clnt_param.group_addr   = group_address;
        clnt_param.src_list     = NULL;
        clnt_param.was_excl     = TRUE;
        clnt_param.clnt_ip_addr = clnt_ip_addr;

        grp_deleted = igmp_track_v2_clnt_leave(igmp, &clnt_param);
    }

    mcast_init_addr(&group_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));        
    mcast_init_addr(&src_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));      
    mcast_set_ipv4_addr(&group_addr, group_address);
    mcast_set_ipv4_addr(&src_addr, src_ip);

    // Send the Query if there is not one already queued or if this is a retransmit
    if (igmp_mbrshp->retx_cnt == 0 || is_retx)
    {
        if (src_ip == 0)
            src_ip = ip_get_lowest_ip_address_on_port(tx_port_number, igmp_vport->type);

        if (igmp_send_igmp_message(igmp, tx_port_number,
                    physical_port,
                    IGMP_MEMBERSHIP_QUERY_TYPE, 
                    version,
                    group_address,
                    src_ip,
                    response_time,  
                    NULL, FALSE,       // no srcs
                    is_retx))
        {
            L2MCD_VLAN_LOG_INFO(tx_port_number,"%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Sent Grp-Qry Ver %d. ReTx %d(Cnt %d)",FN,LN,
                    tx_port_number, mld_get_if_name_from_port(physical_port), mld_get_if_name_from_port(tx_port_number), 
                    mcast_print_addr(&group_addr),
                    version,
                    is_retx,
                    igmp_mbrshp->retx_cnt);         


            // Update stats
            if (physical_port == PORT_INDEX_INVALID)
                igmp->igmp_stats[tx_port_number].igmp_xmt_grp_query_msg++;
            else
                igmp->igmp_stats[tx_port_number].igmp_xmt_grp_query_msg++;
        }
        else
        {
            L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Skipped Grp-Qry Ver %d. ReTx %d(Cnt %d)",FN,LN,
                    tx_port_number, mld_get_if_name_from_port(physical_port), mld_get_if_name_from_port(tx_port_number), 
                    mcast_print_addr(&group_addr),
                    version,
                    is_retx,
                    igmp_mbrshp->retx_cnt);         
        }
    }
    else
    {
        L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Skipped Grp-Qry Ver %d. ReTx %d(Cnt %d)",FN,LN,
                tx_port_number, mld_get_if_name_from_port(physical_port), mld_get_if_name_from_port(tx_port_number), 
                mcast_print_addr(&group_addr), version, is_retx, igmp_mbrshp->retx_cnt);            
    }

    return grp_deleted;
}

static UINT32 igmp_track_v3_clnt_leave(MCGRP_CLASS *igmp, 
        IGMP_CLNT_LV_PARAM* p_param)
{
    MCGRP_SOURCE *p_src = NULL, *p_next;
    UINT32 group_address  = p_param->group_addr;
    MCGRP_MBRSHP* igmp_mbrshp = p_param->igmp_mbrshp;
    MCGRP_L3IF * igmp_vport  = p_param->igmp_vport;
    BOOLEAN exclude_all = p_param->was_excl;
    BOOLEAN grp_delete = FALSE;
    MADDR_ST addr, src_addr;
    //DEBUG_MCGRP *p_dbg = &debugGlobal.ip.igmp;

    mcast_init_addr(&src_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));      
    mcast_init_addr(&addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));          
    mcast_set_ipv4_addr(&addr, group_address);


    // We do not correctly maintain the client-list when we are in the EXCL mode
    // So, if we were in the EXCLUDE mode then do not attempt Fast-Leave
    if (exclude_all)
    {
        return grp_delete;
    }

    p_src = (MCGRP_SOURCE*) *p_param->src_list;

    if (exclude_all)
    {
        igmpv3_destroy_client(igmp, &igmp_mbrshp->clnt_tree, p_param->clnt_ip_addr); 
        if (p_src == NULL) 
        {
            L2MCD_LOG_DEBUG("IGMP:%s()%d IGMP.VRF%d: [ Port %s,%s. Grp %s ] Fast-deleting grp on last client Leave %I\n",FN,LN, 
                    igmp->vrf_index, mld_get_if_name_from_ifindex(igmp_mbrshp->phy_port_id), mld_get_if_name_from_port(igmp_vport->vir_port_id),
                    mcast_print_addr(&addr),
                    p_param->clnt_ip_addr);
            //if it was exclude {} and new state is include {} then grp_delete
            return TRUE;
        }
        if (M_AVLL_FIRST(p_src->clnt_tree) == NULL)
        {

            L2MCD_LOG_DEBUG("IGMP:%s()%d IGMP.VRF%d: [ Port %s,%s. Grp %s ] Common client list empty; srclist not empty \n",FN,LN, 
                    igmp->vrf_index, mld_get_if_name_from_ifindex(igmp_mbrshp->phy_port_id), mld_get_if_name_from_port(igmp_vport->vir_port_id), mcast_print_addr(&addr));
        }
    }


    for (; p_src; p_src = p_next)
    {
        // Members of src_list may be deleted during the loop iteration.
        // So save the next pointer to enable us to correctly traverse the list.
        p_next = p_src->next;

        if (! p_src->include_in_query)
            continue;

        (void) igmpv3_destroy_client(igmp, &p_src->clnt_tree, p_param->clnt_ip_addr);

        if (M_AVLL_FIRST(p_src->clnt_tree) == NULL)
        {
            MCGRP_SOURCE* p_del;

            L2MCD_LOG_DEBUG("IGMP:%s()%d IGMP.VRF%d: [ Port %s,%s. Grp %s ] Fast-deleting src %s on last client Leave %I\n",FN,LN, 
                    igmp->vrf_index, mld_get_if_name_from_ifindex(igmp_mbrshp->phy_port_id), mld_get_if_name_from_port(igmp_vport->vir_port_id),
                    mcast_print_addr(&addr),
                    mcast_print_addr(&p_src->src_addr),
                    p_param->clnt_ip_addr);         



            p_del = mcgrp_delist_source(igmp_mbrshp, &p_src->src_addr, FILT_INCL);

            if (igmp_mbrshp->filter_mode == FILT_INCL)
            {
                if (igmp_mbrshp->src_list[FILT_INCL] == NULL)
                    grp_delete = TRUE;
            }
            else if (igmp_mbrshp->filter_mode == FILT_EXCL)
            {
                sorted_linklist_add_one_item(gIgmp.src_specific_pool, 
                        &igmpv3_src_keyinfo,
                        (SORTED_LINKLIST**)&igmp_mbrshp->src_list[FILT_EXCL], 
                        &p_src->src_addr);

                mcgrp_notify_source_list_add_blocked(igmp, 
                        &addr, 
                        igmp_vport, 
                        igmp_mbrshp, 
                        p_src, TRUE);

                mcast_init_addr(&src_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));                      
                mcast_set_ipv4_addr(&src_addr, p_param->clnt_ip_addr);

                L2MCD_LOG_DEBUG("IGMP:%s()%d IGMP.VRF%d: [ Port %s,%s. Grp %s ] Added blocked source %s on last INCL-clnt Leave %x\n",FN,LN, 
                        igmp->vrf_index, mld_get_if_name_from_ifindex(igmp_mbrshp->phy_port_id), mld_get_if_name_from_port(igmp_vport->vir_port_id),
                        mcast_print_addr(&addr),
                        mcast_print_addr(&p_src->src_addr),
                        p_param->clnt_ip_addr);         


            }

            // Mark source so that we do not send a query for it
            p_src->include_in_query = FALSE;


            // Notify mcast routing protocols et al
            mcgrp_notify_source_del_allowed(igmp, &addr, 
                    igmp_vport, igmp_mbrshp,
                    &p_src->src_addr, TRUE);

            mcgrp_free_source(igmp, p_del);
        }
    }

    return grp_delete;
}



BOOLEAN igmpv3_send_group_source_query(MCGRP_CLASS        *igmp, 
        MCGRP_MBRSHP       *igmp_mbrshp,
        UINT16              vir_port_id,
        UINT32              phy_port_id,
        UINT32              group_address,
        SORTED_LINKLIST**   p_src_list,
        BOOLEAN             was_excl,
        UINT32              clnt_ip_addr,
        BOOLEAN             is_retx)
{
    BOOLEAN grp_deleted = FALSE;
    MCGRP_L3IF        *igmp_vport = NULL;
    MCGRP_PORT_ENTRY  *igmp_pport = NULL;
    MADDR_ST addr;

    if (p_src_list == NULL || *p_src_list == NULL) // The source list is empty, then don't send GS query.
        return grp_deleted;
    mcast_init_addr(&addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));      
    mcast_set_ipv4_addr(&addr, group_address);

    // If Tracking is enabled, use the client data to forego the Query if possible
    igmp_vport  = gIgmp.port_list[vir_port_id];
    igmp_pport  = mcgrp_find_phy_port_entry(igmp, igmp_vport, phy_port_id);

    if(igmp_vport == NULL)
    {
        return grp_deleted; 
    }

    if(igmp_pport == NULL)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id,"IGMP:%s()%d  [ Port %d,%d.] igmp_pport is NULL. ",FN,LN, phy_port_id, vir_port_id);
        return grp_deleted; 
    }

    if (igmp_vport->tracking_enabled &&
            igmp_pport->oper_version == IGMP_VERSION_3 && clnt_ip_addr)
    {
        IGMP_CLNT_LV_PARAM clnt_param;

        clnt_param.igmp_vport   = igmp_vport;
        clnt_param.igmp_mbrshp  = igmp_mbrshp;
        clnt_param.group_addr   = group_address;
        clnt_param.src_list     = p_src_list;
        clnt_param.was_excl     = was_excl;
        clnt_param.clnt_ip_addr = clnt_ip_addr;

        // Check the source list if this is the only client for the sources.
        // If so, delete the source and skip sending a group-source-specific query
        grp_deleted = igmp_track_v3_clnt_leave(igmp, &clnt_param);
    }
    if (*p_src_list)
    {
        if (igmp_send_igmp_message(igmp, vir_port_id,
                    phy_port_id,
                    IGMP_MEMBERSHIP_QUERY_TYPE,                                   
                    IGMP_VERSION_3,
                    group_address,
                    ip_get_lowest_ip_address_on_port(vir_port_id,igmp_vport->type),
                    (igmp_vport->LMQ_interval * 10), // LMQI is msec. convert as per RFC response time in pkt
                    (MCGRP_SOURCE*) *p_src_list, FALSE /* all_srcs */,
                    is_retx))
        {
            L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d][ Port %d. Grp 0x%x ] Sent Grp-Src-Qry Ver %d. ReTx %d", 
                    FN,LN,vir_port_id, phy_port_id, group_address,IGMP_VERSION_3, is_retx);                      
            // Update stats
            if (phy_port_id == PORT_INDEX_INVALID)
                igmp->igmp_stats[vir_port_id].igmp_xmt_grp_src_query_msg++;
            else
                igmp->igmp_stats[vir_port_id].igmp_xmt_grp_src_query_msg++;
        }
        else
        {

            L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d][ Port %d. Grp 0x%x ] Skipped Grp-Src-Qry Ver %d", 
                    FN,LN,vir_port_id, phy_port_id, group_address,IGMP_VERSION_3);       
        }
    }
    return grp_deleted;
}

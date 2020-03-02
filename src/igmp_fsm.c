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

#include "l2mcd_mld_utils.h"
#include "l2mcd_mld_port.h"
#include "mld_vlan_db.h"
#include "l2mcd_portdb.h"

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

/* =============================================================================================== */
/* =============================================================================================== */
/* =============================================================================================== */
extern MCAST_GLOBAL_CLASS    gMulticast, *pgMulticast;
extern int mld_grp_exists_on_local_vlan(mld_vid_t vid, mcast_grp_addr_t *ip_addr);
extern BOOLEAN mld_is_snoop_mbrship_present(MCGRP_MBRSHP *mcgrp_mbrshp, 
        uint8_t *v1_mbr, uint8_t *v2_mbr, uint8_t *v3_mbr);

void mcgrp_notify_vif_add (MCGRP_CLASS   *mcgrp,
        MADDR_ST      *group_address,
        MCGRP_L3IF    *mcgrp_vport,
        MCGRP_MBRSHP  *mcgrp_mbrshp,
        MCGRP_ENTRY   *mcgrp_entry,
        BOOL           sigchange)
{
    UINT32             phy_port_id   = mcgrp_mbrshp->phy_port_id;
    UINT16             vir_port_id   = mcgrp_vport->vir_port_id;
    MCGRP_PORT_ENTRY  *mcgrp_pport = NULL;
    MADDR_ST           group;
    MADDR_ST           src_addr;
    UINT8              version = 0;
    mcast_grp_addr_t  *src_list = NULL;

    uint32_t  afi = (IS_IGMP_CLASS(mcgrp) ? IP_IPV4_AFI:IP_IPV6_AFI);
    uint32_t  num_srcs = 0;

    mcast_init_addr(&group, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));
    mcast_set_addr(&group, group_address);
    mcast_init_addr(&src_addr, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));
    if (IS_IGMP_CLASS(mcgrp))
    {
        mcast_set_ipv4_addr(&src_addr, PIM_ENCODE_SRC_ADDRESS_WC);
    }
    else
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] unsupported", FN,LN,vir_port_id);
        return; //MLD
    }

    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] [ Port %s,%d, %s. Grp %s ] Interface added to group. Chg %d",
            FN,LN,vir_port_id, mld_get_if_name_from_ifindex(phy_port_id),mcgrp_mbrshp->phy_port_id,
            mld_get_if_name_from_port(vir_port_id), mcast_print_addr(group_address),
            sigchange);

    // Notify mcast routing protocols
    mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);

    if (IS_IGMP_CLASS(mcgrp))
        version = IGMP_VERSION_3;   
    else
        version = MLD_VERSION_2;
    L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] version:%d ppport oper_version:%d filter_mode:%d, grp_compver=%d", 
            FN, LN, vir_port_id, version, mcgrp_pport ? mcgrp_pport->oper_version : 0, mcgrp_mbrshp->filter_mode, mcgrp_mbrshp->grp_compver);

    if (mcgrp_mbrshp && mcgrp_mbrshp->grp_compver == version)
    {
        if (mcgrp_mbrshp->filter_mode == FILT_INCL)
        {

            MCGRP_SOURCE* p_src_tmp = mcgrp_mbrshp->src_list[FILT_INCL];
            for (; p_src_tmp; p_src_tmp = p_src_tmp->next)
            {
                num_srcs++;
            }

            if (!num_srcs) {
                goto v2_update;
            }
            if(num_srcs)
            {
                src_list = malloc(sizeof(mcast_grp_addr_t) * num_srcs);  
            }
            //Reset num_src to 0
            num_srcs = 0;

            MCGRP_SOURCE* p_src = mcgrp_mbrshp->src_list[FILT_INCL];
            for (; p_src; p_src = p_src->next)
            {
                if(src_list)
                    mcast_set_address(&src_list[num_srcs++], &p_src->src_addr);

                L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] Sending to AppDb (%s, %s) mode:%d %s", 
                        FN, LN, vir_port_id, mcast_print_addr(&p_src->src_addr), mcast_print_addr(group_address), 
                        mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port_id));
                igmpv3_send_l2mcd_sync_group_add(group_address, vir_port_id, phy_port_id, 
                        &p_src->src_addr, mcgrp_mbrshp->filter_mode);
            }
        }
        else /* (mcgrp_mbrshp->filter_mode == FILT_EXCL) */
        {
            MCGRP_SOURCE* p_src_tmp = mcgrp_mbrshp->src_list[FILT_EXCL];
            num_srcs = 0;
            for (; p_src_tmp; p_src_tmp = p_src_tmp->next)
            {
                num_srcs++;
            }
            if(num_srcs)
            {
                src_list = malloc(sizeof(mcast_grp_addr_t) * num_srcs);  
            }

            if (!num_srcs)
                goto v2_update;

            MCGRP_SOURCE* p_src = mcgrp_mbrshp->src_list[FILT_EXCL];
            num_srcs = 0;
            for (; p_src; p_src = p_src->next)
            {
                if(src_list)
                    mcast_set_address(&src_list[num_srcs++], &p_src->src_addr);

                L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] Sending to AppDb (%s, %s) mode:%d %s", 
                        FN, LN, vir_port_id, mcast_print_addr(&p_src->src_addr), mcast_print_addr(group_address), 
                        mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port_id));
                igmpv3_send_l2mcd_sync_group_add(group_address, vir_port_id, phy_port_id, 
                        &p_src->src_addr, mcgrp_mbrshp->filter_mode);

            }
        }
        if (src_list) {
            free (src_list);
            src_list = NULL;
        }

    }
    else
    {

        /*
         * Notify mcastss and then PIM( if L3 is configured)
         */
v2_update:      
        L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] Sending to the L2MCD_SYNC %d %s %d %s snoop_enabled:%d", 
                FN, LN, vir_port_id, mld_get_vlan_id(vir_port_id), mcast_print_addr(group_address),
                mcgrp_mbrshp->phy_port_id, mld_get_if_name_from_ifindex(phy_port_id),
                (mcgrp_vport->flags & MLD_SNOOPING_ENABLED));

        if (is_mld_snooping_enabled(mcgrp_vport, afi)) {
            /* Notify to l2mcd_sync only if snooping is enabled */
            mld_send_l2mcd_sync_group_add(group_address, vir_port_id, phy_port_id, &src_addr, mcgrp_mbrshp->filter_mode);
        }
    }
}


void mcgrp_notify_vif_del(MCGRP_CLASS  *mcgrp, 
        MADDR_ST     *group_address,
        MCGRP_L3IF   *mcgrp_vport,
        MCGRP_ENTRY   *mcgrp_entry,
        BOOL          sigchange)
{
    UINT16        vir_port_id  =  mcgrp_vport->vir_port_id;
    MADDR_ST      src_addr;

    L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Interface deleted from group.Chg %d",
            FN,LN,vir_port_id,
            mld_get_if_name_from_port(vir_port_id), mld_get_if_name_from_port(vir_port_id), 
            mcast_print_addr(group_address),
            sigchange);
    mcast_init_addr(&src_addr, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));

    if (IS_IGMP_CLASS(mcgrp))
        mcast_set_ipv4_addr(&src_addr, PIM_ENCODE_SRC_ADDRESS_WC);
    else
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] unsupported", FN,LN,vir_port_id);
        return; //MLD
    }
}


void mcgrp_notify_phy_port_del (MCGRP_CLASS  *mcgrp, 
        MADDR_ST     *group_address,
        MCGRP_L3IF   *mcgrp_vport,
        //    PORT_ID       phy_port_id,
        UINT32        phy_port_id,
        BOOL          sigchange)
{
    UINT16        vir_port_id   = mcgrp_vport->vir_port_id;
    MADDR_ST      src_addr;
    MCGRP_ENTRY         *mcgrp_entry;
    MCGRP_MBRSHP        *mcgrp_mbrshp = NULL; 
    MCGRP_PORT_ENTRY  *mcgrp_pport = NULL;
    uint32_t phy_ifindex = phy_port_id;
    uint32_t vid = mld_get_vlan_id(vir_port_id);
    uint32_t ivid = 0;

    ivid = mld_portdb_get_ivid_from_gvid(vid,mcgrp_vport->type);
    mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
    if(mcgrp_pport == NULL)
    {
        L2MCD_LOG_INFO("%s(%d) grp:%s phy_port_id:%d mcgrp_pport is NULL in DB. ",
                FN, LN, mcast_print_addr(group_address), phy_port_id);
        return;
    }
    mcast_init_addr(&src_addr, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));
    if (IS_IGMP_CLASS(mcgrp))
    {
        mcast_set_ipv4_addr(&src_addr, PIM_ENCODE_SRC_ADDRESS_WC);
    }
    else
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] unsupported", FN,LN,vir_port_id);
        return;
    }
    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d][ Port %s,%s. Grp %s ] Physical port deleted from group. Chg %d\n",
            FN,LN,vir_port_id, mld_get_if_name_from_ifindex(phy_port_id), 
            mld_get_if_name_from_port(vir_port_id), mcast_print_addr(group_address), sigchange);


    // Update IGMP tables and sync with LP
    if (sigchange)
        L2MCD_LOG_INFO("%s(%d) group_addr:%s oper_version:%d ", 
                __FUNCTION__, __LINE__, mcast_print_addr(group_address), mcgrp_pport->oper_version);
    mcgrp_entry = mcgrp_find_group_address_entry(mcgrp, vir_port_id, group_address);
    if(mcgrp_entry)
        mcgrp_mbrshp = mcgrp_find_mbrshp_entry(mcgrp_entry, phy_port_id);
    /* If this mbr has received PIM snooping (*,G) join then send update
     * 1. Remove this port from all (S,G) entries for this Grp since it was inherited
     * 2. send update to mcastsss to delete this port
     */
    if(mcgrp_mbrshp && (mcgrp_mbrshp->pims_mbr_flags & PIMS_WG_MBR_PORT))   
    {
        mcgrp_mcast_change_vport_membership(mcgrp, &src_addr, group_address, vir_port_id,
                phy_port_id, MCGRP_DELETE_GROUP);
    }
    /* Now for each PIM snooping SGV entry on this port, send port del along with 
     * the inherited ports to mcastss 
     */
    if(mcgrp_mbrshp && mcgrp_mbrshp->pims_src_list)
    {
        MCGRP_SOURCE* p_src = mcgrp_mbrshp->pims_src_list;
        for (; p_src; p_src = p_src->next)
        {
            l2mcd_sync_inherit_and_send_rte(mcgrp, mcgrp_vport, mcgrp_entry,
                    mcgrp_mbrshp->phy_port_id, &p_src->src_addr, 0);
            mcgrp_mcast_change_vport_membership(mcgrp, &p_src->src_addr,
                    group_address, vir_port_id, phy_port_id, MCGRP_DELETE_GROUP);

        }
    }
    if (mcgrp_pport->oper_version == IGMP_VERSION_3) 
    {
        if (mcgrp_entry)
        {
            //mcgrp_mbrshp = mcgrp_find_mbrshp_entry(mcgrp_entry, phy_port_id);
            if (mcgrp_mbrshp && mcgrp_mbrshp->filter_mode == FILT_INCL)
            {
                MCGRP_SOURCE* p_src = mcgrp_mbrshp->src_list[FILT_INCL];

                // Operating in IGMPv3 mode but processed IGMPv2 
                if (!p_src)
                {
                    if(mcgrp_entry->pims_num_sg_join_ports > 0)
                    {
                        /* has pims (S,G) join need to update membership for all SG's */
                        l2mcd_sync_pims_upd_inherit_ports_to_sg(mcgrp_entry, mcgrp_mbrshp, vid, phy_ifindex,
                                mcgrp_entry->group_address.afi, FALSE/*del*/,ivid);
                    }
                    mcgrp_mcast_change_vport_membership(mcgrp, &src_addr, 
                            group_address, vir_port_id, 
                            phy_port_id, MCGRP_DELETE_GROUP);
                }

                for (; p_src; p_src = p_src->next)
                {

                    mcgrp_mcast_change_vport_membership(mcgrp, &p_src->src_addr, 
                            group_address, vir_port_id,
                            phy_port_id, MCGRP_DELETE_GROUP);

                }
            }
            else if (mcgrp_mbrshp && mcgrp_mbrshp->filter_mode == FILT_EXCL)
            {
                MCGRP_SOURCE* p_src = mcgrp_mbrshp->src_list[FILT_EXCL];

                // Operating in IGMPv3 mode but processed IGMPv2 
                if (!p_src)
                {
                    mcgrp_mcast_change_vport_membership(mcgrp, &src_addr, 
                            group_address, vir_port_id, 
                            phy_port_id, MCGRP_DELETE_GROUP);
                }

                for (; p_src; p_src = p_src->next)
                {

                    mcgrp_mcast_change_vport_membership(mcgrp, &p_src->src_addr, 
                            group_address, vir_port_id, 
                            phy_port_id, 
                            MCGRP_DELETE_GROUP);

                }
            }
        }
    }
    else
    {
        if(mcgrp_entry->pims_num_sg_join_ports > 0)
        {
            /* has pims (S,G) join need to update membership for all SG's */
            l2mcd_sync_pims_upd_inherit_ports_to_sg(mcgrp_entry, mcgrp_mbrshp, vid, phy_ifindex,
                    mcgrp_entry->group_address.afi, FALSE/*del*/,ivid);
        }
        // Notify mcast routing protocols
        mcgrp_mcast_change_vport_membership(mcgrp, &src_addr, 
                group_address, vir_port_id, 
                phy_port_id, MCGRP_DELETE_GROUP);
    }
}



// Add ALLOWED source-list
void mcgrp_notify_source_list_add_allowed (MCGRP_CLASS   *mcgrp,
        MADDR_ST      *group_address,
        MCGRP_L3IF    *mcgrp_vport,
        MCGRP_MBRSHP  *mcgrp_mbrshp,
        MCGRP_SOURCE  *src_list,
        BOOL           sigchange)
{
    MCGRP_SOURCE  *p_src = src_list;
    UINT32         phy_port_id   = mcgrp_mbrshp->phy_port_id;
    UINT16         vir_port_id   = mcgrp_vport->vir_port_id;
    MADDR_ST       group;
    mcast_init_addr(&group, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));
    mcast_set_addr(&group, group_address);

    for (; p_src; p_src = p_src->next)
    {

        L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] [ Port %s/%s. Grp %s ] Allowed-Source %s added to port in mode %d. Chg %d",
               FN,LN,vir_port_id, mld_get_if_name_from_ifindex(phy_port_id), 
                mld_get_if_name_from_port(vir_port_id), mcast_print_addr(group_address), 
                mcast_print_addr(&p_src->src_addr), 
                mcgrp_mbrshp->filter_mode, sigchange);
        if (sigchange) {
            L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s(%d) Sending to AppDB (%s, %s) mode:%d %s", 
                    FN, LN, mcast_print_addr(&p_src->src_addr), mcast_print_addr(group_address), 
                    mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port_id));

            igmpv3_send_l2mcd_sync_group_add(group_address, vir_port_id, phy_port_id, 
                    &p_src->src_addr, mcgrp_mbrshp->filter_mode);
        }
    }
}

// Add BLOCKED source-list
void mcgrp_notify_source_list_add_blocked (MCGRP_CLASS   *mcgrp, 
        MADDR_ST      *group_address,
        MCGRP_L3IF    *mcgrp_vport,
        MCGRP_MBRSHP  *mcgrp_mbrshp,
        MCGRP_SOURCE  *src_list,
        BOOL           sigchange)
{
    MCGRP_SOURCE  *p_src = src_list;
    UINT32         phy_port_id   = mcgrp_mbrshp->phy_port_id;
    UINT16         vir_port_id   = mcgrp_vport->vir_port_id;
    MADDR_ST       group;

    mcast_init_addr(&group, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));
    mcast_set_addr(&group, group_address);
    for (; p_src; p_src = p_src->next)
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d][ Port %s/%s. Grp %s ] Blked-Source %s added to port in mode %d. Chg %d",
                FN,LN,vir_port_id,
                mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id), 
                mcast_print_addr(group_address), 
                mcast_print_addr(&p_src->src_addr), 
                mcgrp_mbrshp->filter_mode, sigchange);
        if (sigchange) {
            L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] Sending to write AppDB (%s, %s) mode:%d %s", 
                    FN, LN, vir_port_id, mcast_print_addr(&p_src->src_addr), mcast_print_addr(group_address), 
                    mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port_id));
            igmpv3_send_l2mcd_sync_group_add(group_address, vir_port_id, phy_port_id, 
                    &p_src->src_addr, mcgrp_mbrshp->filter_mode);
        }

    }
}


// Delete ALLOWED source-list
void mcgrp_notify_source_list_del_allowed (MCGRP_CLASS   *mcgrp, 
        MADDR_ST      *group_address,
        MCGRP_L3IF    *mcgrp_vport,
        MCGRP_MBRSHP  *mcgrp_mbrshp,
        MCGRP_SOURCE  *src_list,
        BOOL           sigchange)
{
    MCGRP_SOURCE  *p_src = src_list;
    UINT32         phy_port_id   = mcgrp_mbrshp->phy_port_id;
    UINT16         vir_port_id   = mcgrp_vport->vir_port_id;
    MADDR_ST       group;

    mcast_init_addr(&group, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));
    mcast_set_addr(&group, group_address);
    for (; p_src; p_src = p_src->next)
    {       

        L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Allowed-Source %s deleted from port in mode %d. Chg %d",
                FN,LN,vir_port_id,
                mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id), 
                mcast_print_addr(group_address), 
                mcast_print_addr(&p_src->src_addr),
                mcgrp_mbrshp->filter_mode, sigchange);


        if (sigchange) {
            L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] Sending delete to AppDb (%s, %s) mode:%d %s", 
                    FN, LN, vir_port_id, mcast_print_addr(&p_src->src_addr), mcast_print_addr(group_address), 
                    mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port_id));

            igmpv3_send_l2mcd_sync_group_upd(group_address, vir_port_id, 0, 0, 1, 
                    phy_port_id, &p_src->src_addr, 0, mcgrp_mbrshp->filter_mode);
        }
    }
}

// Delete BLOCKED source-list
void mcgrp_notify_source_list_del_blocked (MCGRP_CLASS   *mcgrp,
        MADDR_ST      *group_address,
        MCGRP_L3IF    *mcgrp_vport,
        MCGRP_MBRSHP  *mcgrp_mbrshp,
        MCGRP_SOURCE  *src_list,
        BOOL            sigchange)
{

    MCGRP_SOURCE  *p_src = src_list;
    UINT32         phy_port_id   = mcgrp_mbrshp->phy_port_id;
    UINT16         vir_port_id   = mcgrp_vport->vir_port_id;
    MADDR_ST       group;

    mcast_init_addr(&group, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));
    mcast_set_addr(&group, group_address);  

    for (; p_src; p_src = p_src->next)
    {

        L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s(%d) Sending to AppDb (%s, %s) mode:%d %s", 
                FN, LN, mcast_print_addr(&p_src->src_addr), mcast_print_addr(group_address), 
                mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port_id));

        igmpv3_send_l2mcd_sync_group_upd(group_address, vir_port_id, 1,phy_port_id, 0, 
                0, &p_src->src_addr, 0, mcgrp_mbrshp->filter_mode);   
        L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Blked-Source %s deleted to port in mode %d. Chg %d",
                FN,LN,vir_port_id,
                mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id), 
                mcast_print_addr(group_address),
                mcast_print_addr(&p_src->src_addr), 
                mcgrp_mbrshp->filter_mode, sigchange);
    }
}


// Delete ALLOWED source
void mcgrp_notify_source_del_allowed (MCGRP_CLASS   *mcgrp, 
        MADDR_ST      *group_address,
        MCGRP_L3IF    *mcgrp_vport,
        MCGRP_MBRSHP  *mcgrp_mbrshp,
        MADDR_ST      *source_addr,
        BOOL           sigchange)
{
    MADDR_ST       group;
    UINT32         phy_port_id   = mcgrp_mbrshp->phy_port_id;
    UINT16         vir_port_id   = mcgrp_vport->vir_port_id;


    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d][ Port %s,%s. Grp %s ] Source %s deleted from port in mode %d. Chg %d",
            FN,LN,vir_port_id,
            mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id), 
            mcast_print_addr(group_address),
            mcast_print_addr(source_addr), 
            mcgrp_mbrshp->filter_mode, sigchange);
    mcast_init_addr(&group, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));

    if (sigchange) {
        /* If there is same source present in PIM snooping source list
         * then we should not send port delete to mcastss for this SGV
         */
        if(!mcgrp_pims_find_src_node_by_addr(mcgrp, mcgrp_mbrshp, source_addr))
        {
            L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s(%d) Sending delete to AppDb (%s, %s) mode:%d %s", 
                    FN, LN, mcast_print_addr(source_addr), mcast_print_addr(group_address), 
                    mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port_id));

            igmpv3_send_l2mcd_sync_group_upd(group_address, vir_port_id, 0, 0, 1, 
                    phy_port_id,source_addr, 0,mcgrp_mbrshp->filter_mode);
        }
    }
}

void mcgrp_notify_source_add_blocked (MCGRP_CLASS   *mcgrp, 
        MADDR_ST      *group_address,
        MCGRP_L3IF    *mcgrp_vport,
        MCGRP_MBRSHP  *mcgrp_mbrshp,
        MADDR_ST      *src_addr,
        BOOL           sigchange)
{
    UINT32         phy_port_id   = mcgrp_mbrshp->phy_port_id;
    UINT16         vir_port_id   = mcgrp_vport->vir_port_id;
    BOOLEAN        is_ssm = FALSE;
    MADDR_ST       group;

    mcast_init_addr(&group, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));
    mcast_set_addr(&group, group_address);

    L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] [ Port %s/%s. Grp %s ] Blked-Source %s added to port in mode %d. Chg %d",
            FN,LN,vir_port_id,
            mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id), 
            mcast_print_addr(group_address),
            mcast_print_addr(src_addr), mcgrp_mbrshp->filter_mode, sigchange);


    if (sigchange) {
        if(is_ssm) {
            L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] Sending add to AppDb (%s, %s) mode:%d %s", 
                    FN, LN, vir_port_id, mcast_print_addr(src_addr), mcast_print_addr(group_address), 
                    mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port_id));
            igmpv3_send_l2mcd_sync_group_upd(group_address, vir_port_id, 1, phy_port_id, 0, 0, src_addr, 0, mcgrp_mbrshp->filter_mode);

        }else  {
            L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] Sending delete to AppDb (%s, %s) mode:%d %s",
                    FN, LN, vir_port_id, mcast_print_addr(src_addr), mcast_print_addr(group_address), 
                    mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port_id));
            igmpv3_send_l2mcd_sync_group_upd(group_address, vir_port_id, 0, 0, 1, phy_port_id, src_addr, 0, mcgrp_mbrshp->filter_mode);
        }
    }
}

void mcgrp_transition_to_INCL (MCGRP_CLASS   *mcgrp, 
        MCGRP_L3IF    *mcgrp_vport, 
        MCGRP_MBRSHP  *mcgrp_mbrshp,
        MCGRP_ENTRY   *mcgrp_entry)
{
    MCGRP_SOURCE   **p_src;
    int              time_remaining; 

    mcgrp_mbrshp->filter_mode = FILT_INCL;
    mcgrp_mbrshp->group_timer = 0;                // stop the group timer
    mcgrp_mbrshp->retx_cnt    = 0;              // Reset ReTx count

    if (IS_IGMP_CLASS(mcgrp))
        // Delete EXCLUDE sources
        igmpv3_sorted_linklist_free_list(mcgrp, gIgmp.src_specific_pool, 
                &igmpv3_src_keyinfo, 
                (SORTED_LINKLIST*) mcgrp_mbrshp->src_list[FILT_EXCL]);
    else
        mldv2_sorted_linklist_free_list(mcgrp, gMld.src_specific_pool, 
                &mldv2_src_keyinfo, 
                (SORTED_LINKLIST*)mcgrp_mbrshp->src_list[FILT_EXCL]);

    mcgrp_mbrshp->src_list[FILT_EXCL] = NULL;

    // Delete aged-out INCLUDE sources
    p_src = &mcgrp_mbrshp->src_list[FILT_INCL];
    while (*p_src)
    {
        time_remaining = (int)((*p_src)->src_timer - read_tb_sec());
        if ((*p_src)->src_timer == 0 || time_remaining <= 0)
        {
            MCGRP_SOURCE* p_delsrc = (*p_src);

            *p_src = (*p_src)->next;
            mcgrp_free_source(mcgrp, p_delsrc);
        }
        else
        {
            p_src = &(*p_src)->next;
        }
    }
}

typedef struct s_UPDATE_SRC_PARAM
{
    UINT16  time;
    UINT16  retx_cnt;
    MADDR_ST  clnt_ip_addr;
    MCGRP_CLASS *mcgrp;
} UPDATE_SRC_PARAM;

// Update a source's client list with the supplied client address
UINT32 mcgrp_update_src_with_client (void    *node, 
        unsigned long   para)
{
    MCGRP_SOURCE      *p_src = (MCGRP_SOURCE*) node;
    UPDATE_SRC_PARAM  *param = (UPDATE_SRC_PARAM *)para;
    MADDR_ST           clnt_ip_addr;
    MCGRP_CLASS       *mcgrp = (MCGRP_CLASS *)param->mcgrp; //(MCGRP_CLASS *)p_src->mcgrp; YZ2-TODO

    mcast_init_addr(&clnt_ip_addr, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));    

    mcast_set_addr(&clnt_ip_addr, &param->clnt_ip_addr);
    mcgrp_add_update_client(mcgrp, &p_src->clnt_tree, &clnt_ip_addr);
    return 0;
}

static UINT32 mcgrp_mark_srcs_for_query_callback (void *node, ULONG param)
{
    MCGRP_SOURCE* p_src = (MCGRP_SOURCE*) node;
    p_src->include_in_query = TRUE;
    return 0;
}

void mcgrp_mark_srcs_for_query (MCGRP_CLASS     *mcgrp,
        MCGRP_MBRSHP    *mcgrp_mbrshp, 
        SORTED_LINKLIST *reference_list,
        MADDR_ST        *clnt_ip_addr)
{
    UPDATE_SRC_PARAM     param;
    MCGRP_GLOBAL_CLASS  *mcgrp_glb = (IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld);

    if (reference_list == NULL)
        return;

    mcast_set_addr(&param.clnt_ip_addr, clnt_ip_addr);

    sorted_linklist_traverse_by_reference(mcgrp_glb->mcgrp_src_keyinfo,
            mcgrp_mark_srcs_for_query_callback,
            (SORTED_LINKLIST*) mcgrp_mbrshp->src_list[FILT_INCL],
            reference_list,
            (unsigned long) &param);

}

static UINT32 mcgrp_update_age_for_srcs_callback (void* node, unsigned long param)
{
    UPDATE_SRC_PARAM   *p_param = (UPDATE_SRC_PARAM*) param;
    MCGRP_CLASS        *mcgrp = (MCGRP_CLASS *)p_param->mcgrp; 

    MCGRP_SOURCE       *p_src = (MCGRP_SOURCE*) node;
    UINT64              curr_time = read_tb_sec();
    UINT16              time = (UINT16)p_param->time;

    /* We need assign the time when the src will get expired */
    p_src->src_timer = (UINT64) (curr_time + time);

    if (p_param->retx_cnt == 0)
    {
        p_src->retx_cnt = 0;
        p_src->include_in_query = FALSE;
    }
    else if (p_src->retx_cnt == 0)
    {   
        // Update retx_cnt only if it is currently 0; if non-zero, count-down has begun
        p_src->retx_cnt = (UINT8)p_param->retx_cnt;
    }

    // Set the same time for all clients
    if (M_AVLL_FIRST(p_src->clnt_tree) != NULL)
    {
        UINT16 clnt_time = (UINT16)p_param->time; /* assign time when clnt expires */

        if (p_param->retx_cnt)
            clnt_time *= p_param->retx_cnt;

        mcgrp_update_age_for_clnts(mcgrp, &p_src->clnt_tree, 
                &p_param->clnt_ip_addr, clnt_time);
    }

    return 0;
}


void mcgrp_update_age_for_srcs (MCGRP_CLASS     *mcgrp, 
        MCGRP_MBRSHP    *mcgrp_mbrshp,
        SORTED_LINKLIST *reference_list,
        MADDR_ST        *clnt_ip_addr, 
        UINT16           time, 
        UINT8            retx_cnt)
{
    UPDATE_SRC_PARAM     param;
    MCGRP_GLOBAL_CLASS  *mcgrp_glb = (IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld);

    if (reference_list == NULL)
        return;

    param.time         = time;
    param.retx_cnt     = retx_cnt;
    mcast_set_addr (&param.clnt_ip_addr, clnt_ip_addr);
    param.mcgrp = mcgrp;

    sorted_linklist_traverse_by_reference(mcgrp_glb->mcgrp_src_keyinfo,
            mcgrp_update_age_for_srcs_callback, 
            (SORTED_LINKLIST*) mcgrp_mbrshp->src_list[FILT_INCL],
            reference_list,
            (unsigned long) &param);

}

static UINT32 mcgrp_update_uptime_for_srcs_callback (void* node, ULONG param)
{
    MCGRP_SOURCE       *p_src = (MCGRP_SOURCE*) node;
    UINT64              curr_time = read_tb_sec();

    /* We need assign the time when the src will get expired */
    p_src->src_uptime = (UINT64) (curr_time);
    return 0;
}

void mcgrp_update_uptime_for_srcs (MCGRP_CLASS     *mcgrp, 
        MCGRP_MBRSHP    *mcgrp_mbrshp,
        SORTED_LINKLIST *reference_list,
        MADDR_ST        *clnt_ip_addr, 
        UINT16           time, 
        UINT8            retx_cnt)
{
    UPDATE_SRC_PARAM     param;
    MCGRP_GLOBAL_CLASS  *mcgrp_glb = (IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld);

    if (reference_list == NULL)
        return;

    param.time         = time;
    param.retx_cnt     = retx_cnt;
    mcast_set_addr (&param.clnt_ip_addr, clnt_ip_addr);
    param.mcgrp = mcgrp;

    sorted_linklist_traverse_by_reference(mcgrp_glb->mcgrp_src_keyinfo,
            mcgrp_update_uptime_for_srcs_callback, 
            (SORTED_LINKLIST*) mcgrp_mbrshp->src_list[FILT_INCL],
            reference_list,
            (unsigned long) &param);

}

MCGRP_MBRSHP*mcgrp_update_group_address_table (MCGRP_CLASS  *mcgrp,
        UINT16        vir_port_id, 
        UINT32        phy_port_id, 
        MADDR_ST     *group_address, 
        MADDR_ST     *clnt_src_ip, 
        UINT8         action,
        UINT8         version,
        UINT16        num_srcs,
        void         *src_array)
{
    MCGRP_L3IF          *mcgrp_vport = NULL;
    MCGRP_PORT_ENTRY    *mcgrp_pport = NULL;
    MCGRP_ENTRY         *mcgrp_entry;
    MCGRP_MBRSHP        *mcgrp_mbrshp, *temp_mbrshp;
    MCGRP_GLOBAL_CLASS  *mcgrp_glb;
    BOOLEAN              new_port = FALSE, src_change = FALSE;
    BOOLEAN              is_leave, is_ssm_grp = FALSE;
    uint8_t v1_mbr = 0, v2_mbr = 0, v3_mbr = 0;
    BOOLEAN              is_static;
    BOOLEAN              mbrshp_del = FALSE;
    BOOLEAN              query_sent = FALSE;
    BOOLEAN              flag;
    MADDR_ST             tmp_addr;
    SORTED_LINKLIST    **p_X, *X;
    SORTED_LINKLIST    **p_Y, *Y;
    SORTED_LINKLIST     *new_src_list;
    SORTED_LINKLIST     *temp_list = NULL;
    MADDR_ST             group;
    MADDR_ST             source_address;
    UINT8                ver = 0;
    UINT32               min_elapse_time = MCGRP_MAX_ELAPSE_TIME, time_remaining = 0; 
    UINT32               min_elapse_time_lmq = MCGRP_MAX_ELAPSE_TIME; 
    UINT64               curr_time; 
    UINT64               curr_time_ms;
    MCGRP_SOURCE        *p_src = NULL;

    BOOLEAN              incl_src_list_empty = TRUE;
    int                  *srcarray= (int *)src_array;
    int i=0,j=0;
    MADDR_ST src_temp;
    MCGRP_SOURCE *igmpv3_src_temp;
	int is_remote=0, src_cnt=num_srcs;

    mcast_init_addr(&group, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));
    mcast_init_addr(&tmp_addr, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));
    mcast_set_addr(&group, group_address);

    curr_time    = read_tb_sec();
    curr_time_ms = read_tb_msec();

    if (IS_IGMP_CLASS(mcgrp))
    {
        mcgrp_vport = gIgmp.port_list[vir_port_id];
        mcast_set_ipv4_addr(&tmp_addr, 0);
        mcgrp_glb = &gIgmp;
    }
    else
    {   
        mcgrp_vport = gMld.port_list[vir_port_id];
        mcast_set_ipv6_addr(&tmp_addr, &ip6_unspecified_address);
        mcgrp_glb = &gMld;
    }

    if (mcgrp_vport == NULL)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id, "%s.ERR:(UPD) [ Port %s,%s ] Ignoring version %d pkt",
                " as Vir port is not initialized\n",
                mld_get_if_name_from_ifindex(phy_port_id),
                mld_get_if_name_from_port(vir_port_id), version);

        return NULL;
    }

    is_static  = MCGRP_IS_STATIC_MMBR(mcgrp, version);
    is_remote = IGMP_IS_REMOTE_MMBR(version);
    version    = MCGRP_GET_VERSION(version);


    L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] %s port:%s(%d) GA:%s is_static:%d SSM:%d  ver:%d Action:%s num_srcs:%d ",
            FN,LN, vir_port_id, portdb_get_ifname_from_portindex(vir_port_id), portdb_get_ifname_from_portindex(phy_port_id),phy_port_id,
            mcast_print_addr(group_address),is_static, is_ssm_grp, version,mcgrp_action_label[action],num_srcs);
    for (i=0;i<num_srcs;i++) 
         L2MCD_VLAN_LOG_DEBUG(vir_port_id,  "%s:%d:[vlan:%d] GA:%s Src:0x%x",  FN,LN, vir_port_id, ipaddr_print_str(group_address), *(srcarray+i));

    is_leave = (num_srcs == 0 && (action == TO_INCL || action == IS_INCL));

    mcgrp_pport  = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
    if (mcgrp_pport == NULL)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id,"%s:%d:[vlan:%d].[ Port %s,%s ] Ignoring version %d pkt as %s"
                " port is not initialized %d",
                __FUNCTION__, LN, vir_port_id,portdb_get_ifname_from_portindex(phy_port_id),
                portdb_get_ifname_from_portindex(vir_port_id), version,
                (mcgrp_vport == NULL ? "Vir" : "Phy"), phy_port_id);
        return NULL;
    }
    // Ignore PDUs if they are of a higher version than what we are configured to operate
    if (version > mcgrp_pport->oper_version)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id,"%s:%d:[vlan:%d].: [ Port %s,%s ] Ignoring version %d pkt due to"
                " version mismatch (portver %d) port:%d",
                FN,LN, vir_port_id, mld_get_if_name_from_ifindex(phy_port_id),
                mld_get_if_name_from_port(vir_port_id), version,
                mcgrp_pport->oper_version,phy_port_id);
        return NULL;
    }
    // SSM sanity checks
    if (is_ssm_grp && !is_leave)
    {
        if (num_srcs == 0) // Req 3.5, 3.7 (ID: draft-holbrook-idmr-igmpv3-ssm-07.txt)
        {

            L2MCD_VLAN_LOG_ERR(vir_port_id,"%s:%d:[vlan:%d].ERR: [ Port %d ] Ignoring request for SSM-grp %s",
                    FN,LN, vir_port_id,
                    phy_port_id,  mcast_print_addr(group_address));
            return NULL;
        }

        if (action == IS_EXCL || action == TO_EXCL)   /* Req 3.1 (ID: MCGRPv3/MLDv2 for SSM) */
        {

            L2MCD_VLAN_LOG_ERR(vir_port_id,"%s:%d:[vlan:%d].ERR: [ Port %d,%d ] Ignoring request for SSM-grp %s",
                    FN,LN, vir_port_id,
                    phy_port_id, vir_port_id, mcast_print_addr(group_address));
            return NULL;
        }
    }

    mcgrp_entry = mcgrp_find_group_address_entry(mcgrp, vir_port_id, group_address);
    if (mcgrp_entry == NULL)
    {
        // Ignore LEAVEs for non-existent groups
        if (is_leave || action == BLOCK_OLD)
        {
            L2MCD_VLAN_LOG_ERR(vir_port_id,"%s:%d:[vlan:%d] ERR: [ Port %s,%s, Grp %s ] Ignoring LEAVE/BLK-OLD "
                    "as grp does not exist",
                    FN, LN, vir_port_id,  mld_get_if_name_from_ifindex(phy_port_id),
                    mld_get_if_name_from_port(vir_port_id), mcast_print_addr(group_address));
            return NULL;
        }

        /* Create new entry */
        mcgrp_entry = mcgrp_alloc_group_entry(mcgrp, mcgrp_vport, group_address);
        if (mcgrp_entry == NULL)
        {
            L2MCD_VLAN_LOG_ERR(vir_port_id,"%s mcgrp_alloc_group_entry error", __FUNCTION__);
            return NULL;
        }
        if (is_ssm_grp)
            mcgrp_entry->is_ssm = TRUE;

    }
    mcgrp_mbrshp = mcgrp_find_mbrshp_entry(mcgrp_entry, phy_port_id);
    if (mcgrp_mbrshp == NULL)
    {
        // Ignore LEAVEs for non-existent group memberships
        if (is_leave || action == BLOCK_OLD)
        {
            L2MCD_VLAN_LOG_ERR(vir_port_id,"%s:%d:[vlan:%d] ERR: [ Port %s,%s, Grp %s ] Ignoring LEAVE/BLK-OLD"
                    " as grp-mbrshp does not exist",
                    FN,LN, vir_port_id, mld_get_if_name_from_ifindex(phy_port_id),
                    mld_get_if_name_from_port(vir_port_id), mcast_print_addr(group_address));
            return NULL;
        }
        mcgrp_mbrshp = mcgrp_alloc_add_mbrshp_entry(mcgrp, mcgrp_entry, 
                mcgrp_vport, phy_port_id, 
                is_static, version);
        if (mcgrp_mbrshp == NULL)
        {
            L2MCD_VLAN_LOG_ERR(vir_port_id,"%s:%d:[vlan:%d] mcgrp_alloc_add_mbrshp_entry error", FN,LN, vir_port_id);
            return NULL;
        }

        /* PIM snooping requirement */
        mcgrp_mbrshp->pims_mbr_flags |= MLD_OR_IGMP_JOIN_PORT;
        if(version == IGMP_VERSION_1)
            mcgrp_mbrshp->pims_mbr_flags |= IGMP_V1_MBR_PORT;
        if(version == IGMP_VERSION_2)
            mcgrp_mbrshp->pims_mbr_flags |= IGMP_V2_MBR_PORT;
        if(version == IGMP_VERSION_3)
            mcgrp_mbrshp->pims_mbr_flags |= IGMP_V3_MBR_PORT;

        L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d]  %s port:%s(%d) GA:%s,is_static:%d,SSM:%d,ver:%d,Action:%s num_srcs:%d, #num-groups:%d, is_ve:%d New group-membership added",
                FN,LN,vir_port_id, portdb_get_ifname_from_portindex(vir_port_id), portdb_get_ifname_from_portindex(phy_port_id),phy_port_id,
                mcast_print_addr(group_address),is_static, is_ssm_grp, version,mcgrp_action_label[action],num_srcs,mcgrp_entry->num_mbr_ports,mcgrp_vport->is_ve);

        new_port = TRUE;
    }
    else {
        /* mbrship node already present(can be PIM snp mbr),
         * just set the flag if already not set 
         */
        //Note: below only checking if mbrshp present, no dependency on PIM Snoop enable
        if(!mld_is_snoop_mbrship_present(mcgrp_mbrshp, &v1_mbr, &v2_mbr, &v3_mbr))
        {
            mcgrp_mbrshp->pims_mbr_flags |= MLD_OR_IGMP_JOIN_PORT;
        }
        if(version == IGMP_VERSION_1)
            mcgrp_mbrshp->pims_mbr_flags |= IGMP_V1_MBR_PORT;
        if(version == IGMP_VERSION_2)
            mcgrp_mbrshp->pims_mbr_flags |= IGMP_V2_MBR_PORT;
        if(version == IGMP_VERSION_3)
            mcgrp_mbrshp->pims_mbr_flags |= IGMP_V3_MBR_PORT;
        L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] pim_mbr_flags: 0x%x, mcgrp_mbrshp->filter_mode=%s ",
                FN, LN, vir_port_id, mcgrp_mbrshp->pims_mbr_flags, (mcgrp_mbrshp->filter_mode == 0) ? "FILT_INCL":"FILT_EXCL");
        if (is_ssm_grp && !mcgrp_entry->is_ssm) {
            new_port = TRUE;
            mcgrp_entry->is_ssm = TRUE;
            L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] Grp %s membership is added to SSM ", FN, LN, vir_port_id, mcast_print_addr(group_address));
        }
        else if(!is_ssm_grp && mcgrp_entry->is_ssm) {
            new_port = TRUE;
            mcgrp_entry->is_ssm = FALSE;
            L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] Grp %s membrship is removed from SSM ", FN, LN, vir_port_id, mcast_print_addr(group_address));
        }
    }


    if(!mcast_addr_any(clnt_src_ip)) { 
        mcast_set_addr(&mcgrp_mbrshp->last_reporter_ip_addr, clnt_src_ip);
    }
    if(is_static) {
        mcgrp_mbrshp->static_mmbr = TRUE;
    }


    if (IS_IGMP_CLASS(mcgrp))
        ver = IGMP_VERSION_3;
    else
        ver = MLD_VERSION_2;

    // Pre-Process received PDU according to the Group Compatibility Mode
    if ((mcgrp_mbrshp->grp_compver == 0) ||
            (version <= mcgrp_mbrshp->grp_compver))
    {
        mcgrp_mbrshp->grp_compver = version;
        if (version < ver)
        {
            mcgrp_mbrshp->host_present[version] = curr_time + mcgrp->older_host_present_time;
            if (min_elapse_time > mcgrp->older_host_present_time)
            {   
                min_elapse_time = mcgrp->older_host_present_time;
            }
        }
    }
    else /* (version > mcgrp_mbrshp->grp_compver) */
    {
        if (version == ver)
        {
            if (action == BLOCK_OLD)
            {
                L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d][Port %d Grp %s ] Ignoring BlkOld "
                        "as GrpCompVer %d < 3",
                        FN,LN,vir_port_id,
                        phy_port_id, mcast_print_addr(group_address),
                        mcgrp_mbrshp->grp_compver);
                return mcgrp_mbrshp;
            }

            if (action == TO_EXCL && num_srcs)
            {
                L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] [Port %d, Grp %s ] Ignoring TO_EXCL "
                        "SrcList as GrpCompVer %d < 3",
                        FN,LN,vir_port_id, phy_port_id,  
                        mcast_print_addr(group_address), 
                        mcgrp_mbrshp->grp_compver);
                num_srcs = 0;
            }
        }

        if (IS_IGMP_CLASS(mcgrp))
        {
            //Check valid only for IGMP version 1
            if (mcgrp_mbrshp->grp_compver == IGMP_VERSION_1)
            {
                // Ignore Leaves
                if (action == TO_INCL)
                {
                    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] FSM: [ Port %d, Grp %s ] Ignoring BlkOld"
                            " as GrpCompVer %d < 3",
                            FN,LN,vir_port_id, phy_port_id, mcast_print_addr(group_address), 
                            mcgrp_mbrshp->grp_compver);

                    return mcgrp_mbrshp;
                }
            }
        }
    }
    /*
     * Get the time remaining to expire mcgrp_mbrshp if it is already exisiting. 
     * As there may be few elements which may be expiring and we need to clean them up
     */
    if (WheelTimerSuccess != 
            WheelTimer_IsElementEnqueued(&mcgrp_mbrshp->mbrshp_tmr.mcgrp_wte))
    {
        /* This is new port thus still no elements that are will be expiring */
        if (min_elapse_time > mcgrp_vport->group_membership_time)
            min_elapse_time = mcgrp_vport->group_membership_time;
    }
    else
    {
        /* There may be few elements which may be expiring */
        time_remaining = MCGRP_TIMER_GET_REMAINING_TIME(mcgrp->mcgrp_wtid, 
                &mcgrp_mbrshp->mbrshp_tmr.mcgrp_wte);
        if (min_elapse_time > time_remaining)
            min_elapse_time = time_remaining;
    }
    //This code is used when the 100ms lmq is configured. i.e., when LMQ interval is less than 1000ms
    if (mcgrp_vport->LMQ_100ms_enabled == TRUE)
    {
        //if wheel timer for lmq is already started and it is enqueued - get remaining time and store as min_elapse_time_lmq
        if (WheelTimerSuccess == 
                WheelTimer_IsElementEnqueued(&mcgrp_mbrshp->lmq_tmr.mcgrp_wte))
        {
            /* There may be few elements which may be expiring */
            time_remaining = MCGRP_TIMER_GET_REMAINING_TIME(mcgrp->mcgrp_wtid_lmq, 
                    &mcgrp_mbrshp->lmq_tmr.mcgrp_wte);
            if (min_elapse_time_lmq > time_remaining)
                min_elapse_time_lmq = time_remaining;

        }
    }

    // Convert the received sources array into a sorted linklist
    new_src_list = sorted_linklist_convert_array_to_linklist(mcgrp_glb->src_specific_pool,
            mcgrp_glb->mcgrp_src_keyinfo,
            num_srcs, src_array);

    incl_src_list_empty = mcgrp_src_list_empty (mcgrp_mbrshp, FILT_INCL, mcgrp_pport->oper_version);

    p_X = (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL];
    X = (*p_X);

    p_Y = (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_EXCL];
    Y = (*p_Y);

    if (mcgrp_mbrshp->filter_mode == FILT_INCL)
    {
        SORTED_LINKLIST **p_A = (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL];
        SORTED_LINKLIST *A    = (*p_A);

        SORTED_LINKLIST **p_B = &new_src_list;
        SORTED_LINKLIST *B    = (*p_B);

        switch( action )
        {
            case IS_INCL:
            case TO_INCL:
            case ALLOW_NEW:
                {
                    // Given INCL(A) and IS_INCL(B)
                    //    or INCL(A) and TO_INCL(B), 
                    //    or INCL(A) and ALLOW_NEW(B), 
                    //
                    // New state = INCL ( A+B )
                    //
                    // Action    = (B) = GMI
                    //             Send Q(G, A-B) for TO_INCL(B) event

                    // The variable names in the following code follows the RFC convention

                    // If B brings in new sources, there will be a source change

                    src_change = ! sorted_linklist_is_subset(mcgrp_glb->mcgrp_src_keyinfo,
                            *p_X, B);
                    //SSM: IGMPv3 port mode, received IGMPv2 report with ssm_map source changed
                    //(action is awlays set to IS_INCL) notify pim for new mapped source.
                    if(action == IS_INCL && src_change)
                    {
                        L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s(%d) source changed setting new_port TRUE to notify pim.",FN, LN);
                        new_port = TRUE;
                    }
                    // A = A + B
                    //
                    sorted_linklist_add(mcgrp_glb->src_specific_pool, 
                            mcgrp_glb->mcgrp_src_keyinfo,
                            p_A, B);

                    A = *p_A;

                    if (mcgrp_vport->tracking_enabled)
                    {
                        UPDATE_SRC_PARAM param;

                        mcast_set_addr(&param.clnt_ip_addr, clnt_src_ip);
                        param.mcgrp = mcgrp;
                        sorted_linklist_traverse_by_reference(mcgrp_glb->mcgrp_src_keyinfo,
                                mcgrp_update_src_with_client,
                                A, B, (unsigned long)&param);
                    }

                    if (action == TO_INCL)
                    {
                        SORTED_LINKLIST* A_minus_B;

                        A_minus_B = sorted_linklist_make_minus(mcgrp_glb->src_specific_pool, 
                                mcgrp_glb->mcgrp_src_keyinfo,
                                A, B);

                        mcgrp_mark_srcs_for_query(mcgrp, mcgrp_mbrshp, 
                                A_minus_B, &tmp_addr);

                        mcgrp_send_group_source_query(mcgrp, mcgrp_mbrshp,
                                vir_port_id,
                                phy_port_id,
                                group_address,
                                (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL],
                                FALSE,         // 0 => was not EXCL mode
                                clnt_src_ip,
                                FALSE /* not retx */);
                        mcgrp_update_age_for_srcs (mcgrp, mcgrp_mbrshp,
                                A_minus_B, &tmp_addr,
                                mcgrp_vport->LMQ_interval,
                                mcgrp_vport->LMQ_count);

                        if (mcgrp_vport->LMQ_100ms_enabled == TRUE)
                        {
                            if (min_elapse_time_lmq > mcgrp_vport->LMQ_interval)
                                min_elapse_time_lmq = mcgrp_vport->LMQ_interval;
                        }
                        else
                        {
                            if (min_elapse_time > mcgrp_vport->LMQ_interval)
                                min_elapse_time = mcgrp_vport->LMQ_interval;
                        }

                        if (IS_IGMP_CLASS(mcgrp))
                            igmpv3_sorted_linklist_free_list(mcgrp,
                                    mcgrp_glb->src_specific_pool, 
                                    (&igmpv3_src_keyinfo),
                                    A_minus_B);
                        else
                            mldv2_sorted_linklist_free_list(mcgrp,
                                    mcgrp_glb->src_specific_pool, 
                                    (&mldv2_src_keyinfo),
                                    A_minus_B);
                    }

                    mcgrp_mbrshp->group_timer = curr_time + mcgrp_vport->group_membership_time;

                    if (min_elapse_time > mcgrp_vport->group_membership_time)
                        min_elapse_time = mcgrp_vport->group_membership_time;

                    mcgrp_mbrshp->retx_cnt = 0;

                    // (B) = GMI
                    mcgrp_update_age_for_srcs(mcgrp, mcgrp_mbrshp, B,
                            clnt_src_ip,
                            mcgrp_vport->group_membership_time, 0);
                    if(src_change)
                        mcgrp_update_uptime_for_srcs(mcgrp, mcgrp_mbrshp, B,
                                clnt_src_ip,
                                mcgrp_vport->group_membership_time, 0);

                    if (min_elapse_time > mcgrp_vport->group_membership_time)
                        min_elapse_time = mcgrp_vport->group_membership_time;

                    break;
                }

            case IS_EXCL:
            case TO_EXCL:
                {
                    L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s(%d) NewPort:%d Mode:%d Action:%d",
                            FN, LN, new_port, mcgrp_mbrshp->filter_mode, action); 

                    if ((!new_port) && (action == IS_EXCL)) {
                        temp_list = sorted_linklist_clone (mcgrp_glb->src_specific_pool, mcgrp_glb->mcgrp_src_keyinfo,
                                NULL, A);
                    }

                    // Given INCL(A) and IS_EXCL(B)
                    //    or INCL(A) and TO_EXCL(B), 
                    //
                    // New state = EXCL ( A*B, B-A )
                    //
                    // Action    = (B-A) = 0
                    //             Delete (A-B)
                    //             GrpTimer = GMI
                    //             Send Q(G, A*B), for TO_EXCL(B) event

                    // X = A*B
                    // This takes care of Delete (A-B)
                    if ((num_srcs == 0) && (mcgrp_vport->tracking_enabled) && 
                            ((mcgrp_pport->oper_version == IGMP_VERSION_3) || 
                             (mcgrp_pport->oper_version == MLD_VERSION_2)))
                    {
                        //this case could be combined with v2 case
                        //add this v3 client to the common client list 
                        mcgrp_add_update_client(mcgrp, &mcgrp_mbrshp->clnt_tree, clnt_src_ip);
                    }  

                    if (IS_IGMP_CLASS(mcgrp))
                        igmpv3_sorted_linklist_keep_common(mcgrp,
                                mcgrp_glb->src_specific_pool, 
                                (&igmpv3_src_keyinfo), p_A, B);
                    else
                        mldv2_sorted_linklist_keep_common(mcgrp, 
                                mcgrp_glb->src_specific_pool, 
                                (&mldv2_src_keyinfo), p_A, B);

                    A = *p_A;            // since p_A might have changed; update A

                    // Y = B-A
                    //
                    // Note that it is OK to do this operation after A has changed since the
                    // new A is nothing but A*B and B-A == B-(A*B)
                    if (IS_IGMP_CLASS(mcgrp))               
                        igmpv3_sorted_linklist_minus(mcgrp, mcgrp_glb->src_specific_pool, 
                                &igmpv3_src_keyinfo, 
                                p_B, A);   // B = B-A
                    else
                        mldv2_sorted_linklist_minus(mcgrp, mcgrp_glb->src_specific_pool, 
                                &mldv2_src_keyinfo, 
                                p_B, A);   // B = B-A

                    sorted_linklist_move(mcgrp_glb->src_specific_pool, 
                            mcgrp_glb->mcgrp_src_keyinfo,
                            p_Y, p_B);
                    mcgrp_mbrshp->filter_mode = FILT_EXCL;
                    mcgrp_mbrshp->group_timer = curr_time + mcgrp_vport->group_membership_time;

                    if (min_elapse_time > mcgrp_vport->group_membership_time)
                        min_elapse_time = mcgrp_vport->group_membership_time;

                    mcgrp_mbrshp->retx_cnt = 0;

                    if (action == TO_EXCL)
                    {
                        mcgrp_mark_srcs_for_query(mcgrp, mcgrp_mbrshp, A, &tmp_addr);
                        mcgrp_send_group_source_query(mcgrp, mcgrp_mbrshp,
                                vir_port_id,
                                phy_port_id,
                                group_address,
                                (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL],
                                FALSE,         //not a EXCLUDE_ALL case 
                                clnt_src_ip,
                                FALSE /* not retx */);
                        mcgrp_update_age_for_srcs (mcgrp, mcgrp_mbrshp, A, &tmp_addr,
                                mcgrp_vport->LMQ_interval, mcgrp_vport->LMQ_count);

                        if (mcgrp_vport->LMQ_100ms_enabled == TRUE)
                        {
                            if (min_elapse_time_lmq > mcgrp_vport->LMQ_interval)
                                min_elapse_time_lmq = mcgrp_vport->LMQ_interval;
                        }
                        else
                        {
                            if (min_elapse_time > mcgrp_vport->LMQ_interval)
                                min_elapse_time = mcgrp_vport->LMQ_interval;
                        }

                    }

                    mcgrp_update_age_for_srcs(mcgrp, mcgrp_mbrshp, *p_Y, 
                            clnt_src_ip, 0, 0);

                    /* When a Port moves from INCL to EXCL Mode. i.e., In V3 mode, it was in 
                     * INCL Mode with n number of sources, later it converted to EXCLUDE NONE state,
                     * then (S,G) entries need to be deleted and new (X,G) entry will be added */ 

                    if ((!new_port) && (action == IS_EXCL)) {
                        /* Deletion of old (S,G) entries */
                        for (p_src = (MCGRP_SOURCE *) temp_list; p_src; p_src = p_src->next)
                        {
                            L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] SrcAddr:%s", FN, LN, vir_port_id, mcast_print_addr(&p_src->src_addr));

                            igmpv3_send_l2mcd_sync_group_upd (&mcgrp_entry->group_address, mcgrp_vport->vir_port_id,
                                    0, 0, 1, mcgrp_mbrshp->phy_port_id, &p_src->src_addr, 0, mcgrp_mbrshp->filter_mode);
                        }

                        /* Add new (X,G) entry */
                        mcgrp_notify_vif_add (mcgrp, &mcgrp_entry->group_address, mcgrp_vport, mcgrp_mbrshp, mcgrp_entry, FALSE);

                        sorted_linklist_free_list (mcgrp_glb->src_specific_pool, mcgrp_glb->mcgrp_src_keyinfo, temp_list);
                    }
                    src_change = TRUE;      // A mode change would constitute a source-change

                    break;
                }

            case BLOCK_OLD:
                {
                    // Given INCL(A) and BLOCK_OLD(B)
                    //
                    // New state = INCL ( A )
                    //
                    // Action    = Send Q(G, A*B)

                    SORTED_LINKLIST* A_star_B;

                    A_star_B = sorted_linklist_make_common(mcgrp_glb->src_specific_pool,
                            mcgrp_glb->mcgrp_src_keyinfo,
                            A, B);

                    mcgrp_mark_srcs_for_query(mcgrp, mcgrp_mbrshp, A_star_B, &tmp_addr);


                    if(!is_mld_fast_leave_configured(mcgrp_vport))
                    {

                        mbrshp_del = mcgrp_send_group_source_query(mcgrp, mcgrp_mbrshp,
                                vir_port_id,
                                phy_port_id,
                                group_address,
                                (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL],
                                FALSE,         //not a EXCLUDE_ALL case 
                                clnt_src_ip,
                                FALSE /* not retx */);

                        mcast_set_addr(&mcgrp_mbrshp->client_source_addr, clnt_src_ip);
                    }
                    if(is_mld_fast_leave_configured(mcgrp_vport) || is_remote)
                        mbrshp_del = TRUE;

                    mcgrp_update_age_for_srcs(mcgrp, mcgrp_mbrshp,
                            A_star_B, &tmp_addr,
                            mcgrp_vport->LMQ_interval,
                            mcgrp_vport->LMQ_count);

                    if (mcgrp_vport->LMQ_100ms_enabled == TRUE)
                    {
                        if (min_elapse_time_lmq > mcgrp_vport->LMQ_interval)
                            min_elapse_time_lmq = mcgrp_vport->LMQ_interval;
                    }
                    else
                    {
                        if (min_elapse_time > mcgrp_vport->LMQ_interval)
                            min_elapse_time = mcgrp_vport->LMQ_interval;
                    }

                    //src-change occurs if tracking is enabled and we delete some sources
                    // in which case, A*B will not be a subset of the INCL list
                    src_change = !sorted_linklist_is_subset(mcgrp_glb->mcgrp_src_keyinfo,
                            *p_X, A_star_B);    

                    if (IS_IGMP_CLASS(mcgrp))               
                        igmpv3_sorted_linklist_free_list(mcgrp, 
                                mcgrp_glb->src_specific_pool, 
                                &igmpv3_src_keyinfo, A_star_B);
                    else
                        mldv2_sorted_linklist_free_list(mcgrp, 
                                mcgrp_glb->src_specific_pool, 
                                &mldv2_src_keyinfo, A_star_B);                  
                    break;
                }
        }
    }
    else /* mcgrp_mbrshp->filter_mode == FILT_EXCL */
    {
        SORTED_LINKLIST *A = new_src_list;

        switch( action )
        {
            case IS_INCL:
            case TO_INCL:
            case ALLOW_NEW:
                {
                    L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] NewPort:%d Mode:%d Action:%d Empty:%d NumSrc:%d",
                            FN, LN, vir_port_id, new_port, mcgrp_mbrshp->filter_mode, action, incl_src_list_empty, num_srcs); 

                    /* When a Port moves from EXCL to INCL Mode. i.e., In V3 mode, it was in 
                     * EXCL None Mode, later it converted to INCLUDE state with N sources,
                     * then (X,G) entries need to be deleted. Later (S,G) entries will be added */

                    if ((!new_port) && (mcgrp_mbrshp->filter_mode == FILT_EXCL) && (action == TO_INCL)) {
                        if ((incl_src_list_empty) && (num_srcs)) {
                            source_address.afi = group_address->afi;
                            mcast_set_addr_any (&source_address);

                            mld_send_l2mcd_sync_group_upd (&mcgrp_entry->group_address, mcgrp_vport->vir_port_id,
                                    0, 0 , 1 , mcgrp_mbrshp->phy_port_id, &source_address, 0);
                        }
                    }
                    // Given EXCL(X, Y) and IS_INCL(A)
                    //    or EXCL(X, Y) and TO_INCL(A), 
                    //    or EXCL(X, Y) and ALLOW_NEW(A), 
                    //
                    // New state = EXCL ( X+A, Y-A )
                    //
                    // Action    = (A) = GMI
                    //             Send Q(G, X-A) and Q(G) for TO_INCL(A) event

                    // If A brings in existing sources, there will be a source change

                    src_change = sorted_linklist_is_any_present(mcgrp_glb->mcgrp_src_keyinfo,
                            *p_Y, A);

                    // X = X+A
                    sorted_linklist_add(mcgrp_glb->src_specific_pool,
                            mcgrp_glb->mcgrp_src_keyinfo,
                            p_X, A);

                    if (mcgrp_vport->tracking_enabled)
                    {
                        UPDATE_SRC_PARAM param;

                        mcast_set_addr(&param.clnt_ip_addr, clnt_src_ip);
                        param.mcgrp = mcgrp;

                        sorted_linklist_traverse_by_reference(mcgrp_glb->mcgrp_src_keyinfo,
                                mcgrp_update_src_with_client,
                                *p_X, A, (unsigned long)&param);
                    }

                    if (IS_IGMP_CLASS(mcgrp))
                        // Y = Y-A
                        igmpv3_sorted_linklist_minus(mcgrp, mcgrp_glb->src_specific_pool, 
                                &igmpv3_src_keyinfo, p_Y, A);
                    else
                        mldv2_sorted_linklist_minus(mcgrp, mcgrp_glb->src_specific_pool, 
                                &mldv2_src_keyinfo, p_Y, A);

                    // (A) = GMI
                    mcgrp_update_age_for_srcs(mcgrp, mcgrp_mbrshp, A,
                            clnt_src_ip,
                            mcgrp_vport->group_membership_time, 0);

                    if (min_elapse_time > mcgrp_vport->group_membership_time)
                        min_elapse_time = mcgrp_vport->group_membership_time;
                    if (action == TO_INCL)
                    {
                        SORTED_LINKLIST *X_minus_A;

                        X_minus_A = sorted_linklist_make_minus(mcgrp_glb->src_specific_pool,
                                mcgrp_glb->mcgrp_src_keyinfo,
                                X, A);

                        // Send Q(G, X-A)
                        mcgrp_mark_srcs_for_query(mcgrp, mcgrp_mbrshp, X_minus_A, 
                                &tmp_addr);

                        mbrshp_del = mcgrp_send_group_source_query(mcgrp, mcgrp_mbrshp,
                                vir_port_id,
                                phy_port_id,
                                group_address,
                                (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL],
                                (A == NULL),  //Exclude ALL case;  only if TO_INCL list is {} which means it is a leave for all sources 
                                clnt_src_ip,
                                FALSE /* not retx */);
                        mcgrp_update_age_for_srcs(mcgrp, mcgrp_mbrshp,
                                X_minus_A, &tmp_addr,
                                mcgrp_vport->LMQ_interval,
                                mcgrp_vport->LMQ_count);

                        if (mcgrp_vport->LMQ_100ms_enabled == TRUE)
                        {
                            if (min_elapse_time_lmq > mcgrp_vport->LMQ_interval)
                                min_elapse_time_lmq = mcgrp_vport->LMQ_interval;
                        }
                        else
                        {
                            if (min_elapse_time > mcgrp_vport->LMQ_interval)
                                min_elapse_time = mcgrp_vport->LMQ_interval;
                        }

                        if(!is_mld_fast_leave_configured(mcgrp_vport))
                        {
                            if (IS_IGMP_CLASS(mcgrp))
                            {
                                // Send Q(G)
                                mbrshp_del = igmp_send_group_query(mcgrp, mcgrp_mbrshp,
                                        vir_port_id,
                                        phy_port_id,
                                        (UINT8) mcgrp_pport->oper_version,
                                        group_address->ip.v4addr, // group-specific query
                                        0,  // Use lowest IP addr of this port
                                        clnt_src_ip->ip.v4addr,
                                        FALSE);      // not retx
                            }
                            else 
                            { 
                                //MLD
                            }
       
                        }
                        if(is_mld_fast_leave_configured(mcgrp_vport) || is_remote)
                            mbrshp_del = TRUE;


                        query_sent = TRUE;
                        /* If there is a PIM snoop join received on this port, then
                         * the port mbr should not expire immediately.
                         * Just clear the flags mbr port, cleanup will happen as part 
                         * of PIM prune on this port
                         */
                        L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s(%d) Clear IGMP Join port from pim_mbr_flags ", FN, LN); 
                        mcgrp_mbrshp->pims_mbr_flags &= ~MLD_OR_IGMP_JOIN_PORT;
                        mcgrp_mbrshp->pims_mbr_flags &= ~IGMP_V1_MBR_PORT;
                        mcgrp_mbrshp->pims_mbr_flags &= ~IGMP_V2_MBR_PORT;
                        mcgrp_mbrshp->pims_mbr_flags &= ~IGMP_V3_MBR_PORT;

                        if(!pims_is_pim_snoop_mbrship(mcgrp_mbrshp)) { 
                            // Query sent; update age of group to LMQ Time = LMQ_count * LMQ_interva
                            if (mcgrp_vport->LMQ_100ms_enabled == TRUE)
                            {
                                mcgrp_mbrshp->lmq_timer = curr_time_ms + mcgrp->LMQ_interval;
                            }
                            else
                            {
                                mcgrp_mbrshp->group_timer = curr_time + (mcgrp->LMQ_interval);
                            }
                        }
                        else {
                            mcgrp_mbrshp->pims_mbr_flags |= IGMP_LEAVE_PENDING_MBR_PORT;
                        }

                        if (mcgrp_vport->LMQ_100ms_enabled == TRUE)
                        {
                            if (min_elapse_time_lmq > mcgrp_vport->LMQ_interval)
                                min_elapse_time_lmq = mcgrp_vport->LMQ_interval;
                        }
                        else
                        {
                            if (min_elapse_time > mcgrp_vport->LMQ_interval)
                                min_elapse_time = mcgrp_vport->LMQ_interval;
                        }


                        mcgrp_mbrshp->retx_cnt = mcgrp_vport->LMQ_count;
                        mcgrp_update_age_for_clnts(mcgrp, &mcgrp_mbrshp->clnt_tree,
                                clnt_src_ip,
                                mcgrp_vport->LMQ_interval * mcgrp_vport->LMQ_count);


                        // If this is a leave of a static group, enable aging for its membership
                        // on this port
                        if (is_static && is_leave)
                        {
                            mcgrp_mbrshp->aging_enabled = TRUE;
                            mcgrp_mbrshp->static_mmbr   = FALSE;
                        }

                        if (IS_IGMP_CLASS(mcgrp))
                            igmpv3_sorted_linklist_free_list(mcgrp, 
                                    mcgrp_glb->src_specific_pool, 
                                    &igmpv3_src_keyinfo, 
                                    X_minus_A);
                        else
                            mldv2_sorted_linklist_free_list(mcgrp, 
                                    mcgrp_glb->src_specific_pool, 
                                    &mldv2_src_keyinfo, 
                                    X_minus_A); 
                    }
                    break;
                }

            case IS_EXCL:
            case TO_EXCL:
                {
                    // Given EXCL(X, Y) and IS_EXCL(A)
                    //    or EXCL(X, Y) and TO_EXCL(A), 
                    //
                    // New state = EXCL ( A-Y, Y*A )
                    //
                    // Action    = (A-X-Y) = GMI or GrpTimer in case of TO_EXCL
                    //             Delete (X-A), (Y-A)
                    //             GrpTimer = GMI
                    //             Send Q(G, A-Y), for TO_EXCL(A) event

                    UINT16 time;
                    BOOLEAN prev_incl_empty = (X == NULL);

                    SORTED_LINKLIST *A_minus_Y, *A_minus_X_minus_Y, *X_minus_A, *Y_minus_A;

                    src_change = ! sorted_linklist_is_subset(mcgrp_glb->mcgrp_src_keyinfo,
                            A, *p_Y);

                    A_minus_Y = sorted_linklist_make_minus(mcgrp_glb->src_specific_pool, 
                            mcgrp_glb->mcgrp_src_keyinfo,
                            A, Y);

                    A_minus_X_minus_Y = sorted_linklist_make_minus(mcgrp_glb->src_specific_pool,
                            mcgrp_glb->mcgrp_src_keyinfo,
                            A_minus_Y, X);

                    X_minus_A = sorted_linklist_make_minus(mcgrp_glb->src_specific_pool,
                            mcgrp_glb->mcgrp_src_keyinfo,
                            X, A);

                    Y_minus_A = sorted_linklist_make_minus(mcgrp_glb->src_specific_pool,
                            mcgrp_glb->mcgrp_src_keyinfo,
                            Y, A);

                    // X = A-Y
                    // This takes care of Delete (X-A)
                    sorted_linklist_move_keep_old(mcgrp_glb->src_specific_pool,
                            mcgrp_glb->mcgrp_src_keyinfo,
                            p_X, &A_minus_Y);

                    // Y = Y*A
                    // This takes care of Delete (Y-A)
                    if (IS_IGMP_CLASS(mcgrp))
                        igmpv3_sorted_linklist_keep_common(mcgrp, mcgrp_glb->src_specific_pool, 
                                &igmpv3_src_keyinfo, p_Y, A);
                    else
                        mldv2_sorted_linklist_keep_common(mcgrp, mcgrp_glb->src_specific_pool, 
                                &mldv2_src_keyinfo, p_Y, A);
                    // (A-X-Y) = GMI or Group Timer
                    //
                    time = (action == TO_EXCL) ? (mcgrp_mbrshp->group_timer - curr_time) :
                        mcgrp_vport->group_membership_time;
                    mcgrp_update_age_for_srcs(mcgrp, mcgrp_mbrshp, 
                            A_minus_X_minus_Y, clnt_src_ip, 
                            time, 0);

                    if (min_elapse_time > time)
                        min_elapse_time = time;

                    if (!mcgrp_mbrshp->static_mmbr) {
                        //Version v2/v1 means Report received is V2 but port opertional
                        //mode v3, same applicable MLD operational mode MLDv2 and received MLDv1 report.
                        //This condition hit upon group refresh as first report Filter is INCL and
                        //Subsequent report filter mode changed to Fitler EXCL, skip updating below for (*,G)
                        if ( ((IS_IGMP_CLASS(mcgrp) && mcgrp_pport->oper_version == IGMP_VERSION_3) || 
                                    (IS_MLD_CLASS(mcgrp) && mcgrp_pport->oper_version == MLD_VERSION_2)) && 
                                ( (IS_IGMP_CLASS(mcgrp) && version == IGMP_VERSION_3) || 
                                  (IS_MLD_CLASS(mcgrp) && version == MLD_VERSION_2)) ) {
                            mcgrp_notify_source_list_del_blocked(mcgrp, 
                                    group_address, mcgrp_vport,
                                    mcgrp_mbrshp,
                                    (MCGRP_SOURCE*) X_minus_A, 
                                    TRUE);

                            mcgrp_notify_source_list_del_blocked(mcgrp, group_address, 
                                    mcgrp_vport, mcgrp_mbrshp,
                                    (MCGRP_SOURCE*) Y_minus_A, 
                                    TRUE);
                        } else {
                            L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] Skip soure_del version:%d oper_version:%d ", 
                                    FN, LN, vir_port_id, version, mcgrp_pport->oper_version);
                        }

                    }

                    if ((num_srcs == 0) && (mcgrp_vport->tracking_enabled) && 
                            ((mcgrp_pport->oper_version == IGMP_VERSION_3) ||
                             (mcgrp_pport->oper_version == MLD_VERSION_2)))
                    {
                        //this case could be combined with v2 case
                        //add this v3 client to the common client list 
                        mcgrp_add_update_client(mcgrp, &mcgrp_mbrshp->clnt_tree, clnt_src_ip);
                    }

                    if (action == TO_EXCL)
                    {
                        // Send Q(G, A-Y)
                        mbrshp_del = mcgrp_send_group_source_query(mcgrp, mcgrp_mbrshp,
                                vir_port_id,
                                phy_port_id,
                                group_address,
                                (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL],
                                (prev_incl_empty && (A != NULL)),         //EXCLUDE ALL Case ; check to see if there is any fast leaves in the common src list also
                                clnt_src_ip,
                                FALSE /* not retx */);
                        mcgrp_update_age_for_srcs (mcgrp, mcgrp_mbrshp, *p_X,
                                &tmp_addr, mcgrp_vport->LMQ_interval,
                                mcgrp_vport->LMQ_count);

                        if (mcgrp_vport->LMQ_100ms_enabled == TRUE)
                        {
                            if (min_elapse_time_lmq > mcgrp_vport->LMQ_interval)
                                min_elapse_time_lmq = mcgrp_vport->LMQ_interval;
                        }
                        else
                        {
                            if (min_elapse_time > mcgrp_vport->LMQ_interval)
                                min_elapse_time = mcgrp_vport->LMQ_interval;
                        }
                    }
                    // GrpTimer = GMI
                    mcgrp_mbrshp->group_timer = curr_time + mcgrp_vport->group_membership_time;
                    if (min_elapse_time > mcgrp_vport->group_membership_time)
                        min_elapse_time = mcgrp_vport->group_membership_time;
                    mcgrp_mbrshp->retx_cnt = 0;

                    // A_minus_Y is freed during move_keep_old
                    if (IS_IGMP_CLASS(mcgrp))
                    {
                        igmpv3_sorted_linklist_free_list(mcgrp, mcgrp_glb->src_specific_pool, 
                                &igmpv3_src_keyinfo, 
                                A_minus_X_minus_Y);

                        igmpv3_sorted_linklist_free_list(mcgrp, mcgrp_glb->src_specific_pool, 
                                &igmpv3_src_keyinfo, 
                                X_minus_A);
                        igmpv3_sorted_linklist_free_list(mcgrp, mcgrp_glb->src_specific_pool, 
                                &igmpv3_src_keyinfo, 
                                Y_minus_A);

                    }
                    else
                    {
                        mldv2_sorted_linklist_free_list(mcgrp, mcgrp_glb->src_specific_pool, 
                                &mldv2_src_keyinfo, 
                                A_minus_X_minus_Y);

                        mldv2_sorted_linklist_free_list(mcgrp, mcgrp_glb->src_specific_pool,
                                &mldv2_src_keyinfo, 
                                X_minus_A);

                        mldv2_sorted_linklist_free_list(mcgrp, mcgrp_glb->src_specific_pool,
                                &mldv2_src_keyinfo, 
                                Y_minus_A);

                    }
                    break;
                }

            case BLOCK_OLD:
                {
                    // Given EXCL(X, Y) and BLOCK_OLD(A)
                    //
                    // New state = EXCL ( X+(A-Y), Y )
                    //
                    // Action    = (A-X-Y) = Grp Timer
                    //             Send Q(G, A-Y)

                    SORTED_LINKLIST *A_minus_Y, *A_minus_X_minus_Y;

                    A_minus_Y = sorted_linklist_make_minus(mcgrp_glb->src_specific_pool,
                            mcgrp_glb->mcgrp_src_keyinfo,
                            A, Y);

                    A_minus_X_minus_Y = sorted_linklist_make_minus(mcgrp_glb->src_specific_pool,
                            mcgrp_glb->mcgrp_src_keyinfo,
                            A_minus_Y, X);

                    // X = X + (A-Y)
                    sorted_linklist_add(mcgrp_glb->src_specific_pool,
                            mcgrp_glb->mcgrp_src_keyinfo,
                            p_X, A_minus_Y);

                    // (A-X-Y) = Grp Timer
                    mcgrp_update_age_for_srcs(mcgrp, mcgrp_mbrshp, 
                            A_minus_X_minus_Y, clnt_src_ip, 
                            (mcgrp_mbrshp->group_timer - curr_time), 0);

                    if (min_elapse_time > (mcgrp_mbrshp->group_timer - curr_time))
                        min_elapse_time = mcgrp_mbrshp->group_timer - curr_time;

                    // Send Q(G, A-Y)
                    mcgrp_mark_srcs_for_query(mcgrp, mcgrp_mbrshp, A_minus_Y, 
                            &tmp_addr);

                    mcgrp_send_group_source_query(mcgrp, mcgrp_mbrshp,
                            vir_port_id,
                            phy_port_id,
                            group_address,
                            (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL],
                            FALSE,         //not a EXCLUDE_ALL case 
                            clnt_src_ip,
                            FALSE /* not retx */);
                    mcgrp_update_age_for_srcs (mcgrp, mcgrp_mbrshp,
                            A_minus_Y, &tmp_addr,
                            mcgrp_vport->LMQ_interval,
                            mcgrp_vport->LMQ_count);

                    if (mcgrp_vport->LMQ_100ms_enabled == TRUE)
                    {
                        if (min_elapse_time_lmq > mcgrp_vport->LMQ_interval)
                            min_elapse_time_lmq = mcgrp_vport->LMQ_interval;
                    }
                    else
                    {
                        if (min_elapse_time > mcgrp_vport->LMQ_interval)
                            min_elapse_time = mcgrp_vport->LMQ_interval;
                    }

                    if (IS_IGMP_CLASS(mcgrp))
                    {
                        igmpv3_sorted_linklist_free_list(mcgrp, 
                                mcgrp_glb->src_specific_pool,
                                &igmpv3_src_keyinfo, A_minus_Y);
                        igmpv3_sorted_linklist_free_list(mcgrp, 
                                mcgrp_glb->src_specific_pool, 
                                &igmpv3_src_keyinfo, A_minus_X_minus_Y);
                    }
                    else
                    {
                        mldv2_sorted_linklist_free_list(mcgrp, 
                                mcgrp_glb->src_specific_pool,
                                &mldv2_src_keyinfo, A_minus_Y);
                        mldv2_sorted_linklist_free_list(mcgrp, 
                                mcgrp_glb->src_specific_pool, 
                                &mldv2_src_keyinfo, A_minus_X_minus_Y);

                    }

                    src_change = FALSE;     // No change in the exclude list

                    break;
                }

        } /* switch (action) */

    } /* if (mcgrp_mbrshp->filter_mode == FILT_INCL) ... else ... */

    // On account of tracking (fast leave), we may have no longer have an activer member
    // Check and cleanup as required
    if (mbrshp_del)
    {
        if(new_src_list && mcgrp_pport->oper_version == IGMP_VERSION_3)
        {
            if (IS_IGMP_CLASS(mcgrp))
            {
                MCGRP_SOURCE* p_src = (MCGRP_SOURCE*) new_src_list;             
                MCGRP_SOURCE* p_del;

                for (; p_src; p_src = p_src->next)
                {
                    // Delete sources from the group;
                    p_del = mcgrp_delist_source(mcgrp_mbrshp, &p_src->src_addr, FILT_INCL);

                    // Notify mcast routing protocols et al
                    mcgrp_notify_source_del_allowed(mcgrp, group_address, mcgrp_vport, 
                            mcgrp_mbrshp, &p_src->src_addr, TRUE);
                    // TBD: host tracking..
                    mcgrp_free_source(mcgrp, p_del);

                }
            }
        }
        else
        {
            // Notify routing protocols of this port's departure
            mcgrp_notify_phy_port_del(mcgrp, group_address, mcgrp_vport, 
                    phy_port_id, TRUE);
        }

        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] FSM: [ Port %d Grp %s ] Fast-deleting grp-mbrshp on last client Leave %s", 
                FN,LN,vir_port_id, phy_port_id, 
                mcast_print_addr(group_address),
                mcast_print_addr(clnt_src_ip));

        temp_mbrshp = mcgrp_find_mbrshp_entry(mcgrp_entry, phy_port_id);
        if(temp_mbrshp && mcgrp_src_list_empty(mcgrp_mbrshp,FILT_INCL,mcgrp_pport->oper_version))
        {
            /* PIM snp member just RESET the IGMP snp flags for the member */
            //Note: Below flags are set irrespective of pim snoop enabled. RESET if IGMP membership is cleaned up.
            L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d]  Clear IGMP Join port from pim_mbr_flags ", FN, LN,vir_port_id); 
            temp_mbrshp->pims_mbr_flags &= ~MLD_OR_IGMP_JOIN_PORT;
            temp_mbrshp->pims_mbr_flags &= ~IGMP_V1_MBR_PORT;
            temp_mbrshp->pims_mbr_flags &= ~IGMP_V2_MBR_PORT;
            temp_mbrshp->pims_mbr_flags &= ~IGMP_V3_MBR_PORT;

            if (!pims_is_pim_snoop_mbrship(temp_mbrshp)) /* No PIM Snooping memeber present */
            {
                mcgrp_destroy_mbrshp_entry(mcgrp, mcgrp_entry,
                        mcgrp_find_mbrshp_entry(mcgrp_entry, phy_port_id));
                //mbrship_destroyed = TRUE;
            } else {    /* PIM Snooping Membership Present */


            }

        }

        // If there are no members left in this group, delete the group too
        if (mcgrp_entry->num_mbr_ports == 0)
        {
            mcgrp_notify_vif_del(mcgrp, group_address, mcgrp_vport, mcgrp_entry, TRUE);
            mcgrp_destroy_group_addr(mcgrp, mcgrp_vport, mcgrp_entry);
        }
    }
    else
    {
        if (src_change)
            L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s(%d) src_change=%d ", FN, LN, src_change); 

        switch (action)
        {
            case TO_INCL:
            case TO_EXCL:
            case IS_INCL:
            case IS_EXCL:
                if (new_port)
                    /* Update mcache; notify Routing Protocols */
                    mcgrp_notify_vif_add(mcgrp, group_address, 
                            mcgrp_vport, mcgrp_mbrshp, mcgrp_entry, FALSE);

                if ((mcgrp_mbrshp->filter_mode == FILT_EXCL) && (action == TO_INCL)) {
                    mcgrp_notify_source_list_del_blocked (mcgrp, group_address, mcgrp_vport,
                            mcgrp_mbrshp, (MCGRP_SOURCE*) new_src_list, src_change);
                }

                /* Fix for defect id : TR000620213*/
                if ((mcgrp_mbrshp->filter_mode == FILT_INCL) && (action == IS_INCL))
                    mcgrp_notify_source_list_add_allowed(mcgrp, group_address,
                            mcgrp_vport,
                            mcgrp_mbrshp,
                            (MCGRP_SOURCE*)new_src_list,
                            src_change);
                break;

            case ALLOW_NEW:
                if (new_port)
                    mcgrp_notify_vif_add(mcgrp, group_address,
                            mcgrp_vport, mcgrp_mbrshp, mcgrp_entry, FALSE);

                if (mcgrp_mbrshp->filter_mode == FILT_INCL)
                    mcgrp_notify_source_list_add_allowed(mcgrp, group_address, 
                            mcgrp_vport, 
                            mcgrp_mbrshp,
                            (MCGRP_SOURCE*) new_src_list,
                            src_change);
                else
                    mcgrp_notify_source_list_del_blocked(mcgrp, group_address, 
                            mcgrp_vport, 
                            mcgrp_mbrshp,
                            (MCGRP_SOURCE*)new_src_list, 
                            src_change);
                break;
            case BLOCK_OLD:
                if (mcgrp_mbrshp->filter_mode == FILT_INCL)
                    mcgrp_notify_source_list_del_allowed(mcgrp, group_address,
                            mcgrp_vport, mcgrp_mbrshp,
                            (MCGRP_SOURCE*) new_src_list, 
                            src_change);
                else
                    mcgrp_notify_source_list_add_blocked(mcgrp, group_address,
                            mcgrp_vport, mcgrp_mbrshp,
                            (MCGRP_SOURCE*) new_src_list,
                            src_change);
                break;
        }

        if (!mbrshp_del)
        {
            for (i = 0; i <= src_cnt; i++)
            {
                /* 
                 * If the type of (S,G) /(*,G) entry is changed between remote to dynamic or viceversa, 
                 * notify to update the DB with updated information on the entry.  
                 * TODO - change the timeout logic 
                 */ 
                if (!src_cnt) 
                {
                    if (mcgrp_mbrshp && (mcgrp_mbrshp->is_remote!= is_remote))
                    {
                        mcast_set_ipv4_addr(&src_temp, 0);
                        mcgrp_mbrshp->is_remote = is_remote;
                        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] rmt:%d", FN,LN,vir_port_id, is_remote);
                        l2mcd_system_group_entry_notify(group_address, &src_temp, vir_port_id, phy_port_id, TRUE, TRUE);
                    }
                }
                else 
                {
                    for (j = FILT_INCL; j <= FILT_EXCL; j++)
                    {
                        mcast_set_ipv4_addr(&src_temp, srcarray[i]);
                        igmpv3_src_temp = mcgrp_find_source(mcgrp_mbrshp, &src_temp, i);
                        if (igmpv3_src_temp && (igmpv3_src_temp->is_remote !=is_remote))
                        {
                            igmpv3_src_temp->is_remote = is_remote;
                            L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] SA:0x%x  rmt1:%d filter:%d", FN,LN,vir_port_id, srcarray[i],is_remote, j);
                            l2mcd_system_group_entry_notify(group_address, &src_temp, vir_port_id, phy_port_id, TRUE, TRUE);
                        }
                    }
                }
            }
        }

        // if tracking is enabled on this interface,
        //    If this is a JOIN, add this report's source to our tracking list
        //    Else /* Leave */ do nothing as deletion of the client and the group 
        //    has already
        //         been taken care of in Send G Query

        if (IS_IGMP_CLASS(mcgrp))
            ver = IGMP_VERSION_2;
        else
            ver = MLD_VERSION_1;

        if (mcgrp_vport->tracking_enabled &&
                (mcgrp_pport->oper_version == ver))
        {
            if (!is_leave)
            {
                mcgrp_add_update_client(mcgrp, &mcgrp_mbrshp->clnt_tree, 
                        clnt_src_ip);
            }
        }


        if (min_elapse_time && min_elapse_time != MCGRP_MAX_ELAPSE_TIME)
        {
            if (new_port || WheelTimerSuccess != 
                    WheelTimer_IsElementEnqueued(&mcgrp_mbrshp->mbrshp_tmr.mcgrp_wte))
            {
                mcgrp_mbrshp->mbrshp_tmr.timer_type              = MCGRP_WTE_MBRSHP;
                mcgrp_mbrshp->mbrshp_tmr.mcgrp                   = mcgrp;
                mcgrp_mbrshp->mbrshp_tmr.wte.mbrshp.mcgrp_mbrshp = mcgrp_mbrshp;
                mcgrp_mbrshp->mbrshp_tmr.wte.mbrshp.vport        = mcgrp_vport;
                mcgrp_mbrshp->mbrshp_tmr.wte.mbrshp.grp_entry    = mcgrp_entry;
                mcgrp_mbrshp->mbrshp_tmr.mcgrp_wte.data          = &mcgrp_mbrshp->mbrshp_tmr;

                L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] EVT: - Started FSM timer for %d seconds",
                        FN,LN, vir_port_id, min_elapse_time);

                WheelTimer_AddElement(mcgrp->mcgrp_wtid,
                        &mcgrp_mbrshp->mbrshp_tmr.mcgrp_wte,
                        min_elapse_time); 
            }
            else
            {
                L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] EVT: - Restarted FSM timer for %d seconds",
                        FN, LN, vir_port_id, min_elapse_time);
                WheelTimer_ReTimeElement(mcgrp->mcgrp_wtid, 
                        &mcgrp_mbrshp->mbrshp_tmr.mcgrp_wte, 
                        min_elapse_time); 
            }
        }
        if (mcgrp_vport->LMQ_100ms_enabled == TRUE)
        {
            if (min_elapse_time_lmq && min_elapse_time_lmq != MCGRP_MAX_ELAPSE_TIME)
            {
                if (WheelTimerSuccess != 
                        WheelTimer_IsElementEnqueued(&mcgrp_mbrshp->lmq_tmr.mcgrp_wte))
                {

                    mcgrp_mbrshp->lmq_tmr.timer_type              = MCGRP_WTE_LMQI;
                    mcgrp_mbrshp->lmq_tmr.mcgrp                   = mcgrp;
                    mcgrp_mbrshp->lmq_tmr.wte.mbrshp.mcgrp_mbrshp = mcgrp_mbrshp;
                    mcgrp_mbrshp->lmq_tmr.wte.mbrshp.vport        = mcgrp_vport;
                    mcgrp_mbrshp->lmq_tmr.wte.mbrshp.grp_entry    = mcgrp_entry;
                    mcgrp_mbrshp->lmq_tmr.mcgrp_wte.data          = &mcgrp_mbrshp->lmq_tmr;
                    L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d].EVT: - Started FSM timer for %d milli-seconds",
                            FN,LN,vir_port_id, min_elapse_time_lmq);

                    WheelTimer_AddElement(mcgrp->mcgrp_wtid_lmq,
                            &mcgrp_mbrshp->lmq_tmr.mcgrp_wte,
                            min_elapse_time_lmq/100); 
                }
                else
                {
                    L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d]: - Retime LMQ & Delete the group timer", FN,LN,vir_port_id);

                    WheelTimer_ReTimeElement(mcgrp->mcgrp_wtid_lmq, 
                            &mcgrp_mbrshp->lmq_tmr.mcgrp_wte, 
                            min_elapse_time_lmq); 
                }

            }
        }
    }

    if (new_src_list)
    {
        if (IS_IGMP_CLASS(mcgrp))
            igmpv3_sorted_linklist_free_list(mcgrp, mcgrp_glb->src_specific_pool, 
                    &igmpv3_src_keyinfo, new_src_list);
        else
            mldv2_sorted_linklist_free_list(mcgrp, mcgrp_glb->src_specific_pool, 
                    &mldv2_src_keyinfo, new_src_list);

    }

    // If a query was sent, trigger the static group memberships on this port
    // to generate a report
    if (query_sent)
    {
        if (IS_IGMP_CLASS(mcgrp))
        {
            flag = igmp_staticGroup_exists_on_port(group_address->ip.v4addr, vir_port_id, 
                    phy_port_id);
        }
        else
        {
			//MLD not supported
            flag = FALSE; 
        }
        mcast_grp_addr_t grp_addr;
        mcast_set_address(&grp_addr, group_address);
        flag = mld_l2_staticGroup_exists_on_port(&grp_addr, vir_port_id,
                phy_port_id);
        mcgrp_mbrshp->static_mmbr = flag;

        if (flag)
        {
            MADDR_ST source_address;
            mcast_init_addr(&source_address, MCGRP_AFI(mcgrp), MADDR_GET_FULL_PLEN(MCGRP_AFI(mcgrp)));

            if (IS_IGMP_CLASS(mcgrp))
            {
                mcast_set_ipv4_addr(&source_address, ip_get_lowest_ip_address_on_port(vir_port_id, mcgrp_vport->type));
                mcgrp_update_group_address_table(mcgrp, vir_port_id, 
                        phy_port_id,
                        group_address, 
                        &source_address,//use intf's addr as clnt src
                        IS_EXCL,
                        (mcgrp_pport->oper_version >= IGMP_VERSION_2) 
                        ? IGMP_STATIC_VER2 : IGMP_STATIC_VER1,
                        0, (void *)NULL /* No sources */);
            }
            else
            {
                //MLD         
            }
        }
    }

    return mcgrp_mbrshp;
}

/* *************************************************************
 *
 *  MCGRP_CLIENT list manipulation functions
 *
 * *************************************************************/

// Allocate and enlist a new MCGRP_CLIENT in the membership list anchored in IGMP_GROUP_ENTRY
MCGRP_CLIENT* mcgrp_alloc_client (MCGRP_CLASS  *mcgrp, 
        L2MCD_AVL_TREE  *clnt_tree, 
        MADDR_ST     *clnt_addr)
{
    return NULL;
}


// If the specified client exists, reset its age
// If not found, create an entry and enlist it in the tracking list
void mcgrp_add_update_client (MCGRP_CLASS  *mcgrp, 
        L2MCD_AVL_TREE  *clnt_tree,
        MADDR_ST     *clnt_addr)
{
    MCGRP_CLIENT* mcgrp_clnt;

    if (!mcgrp || !clnt_tree || !clnt_addr)
        return;

    mcgrp_clnt = M_AVLL_FIND(*clnt_tree, clnt_addr);

    if (mcgrp_clnt == NULL)
        mcgrp_alloc_client(mcgrp, clnt_tree, clnt_addr);
    else 
        WheelTimer_ReTimeElement(mcgrp->mcgrp_wtid, 
                &mcgrp_clnt->clnt_tmr.mcgrp_wte,
                mcgrp->group_membership_time); 
}

void mcgrp_update_age_for_clnts (MCGRP_CLASS  *mcgrp,
        L2MCD_AVL_TREE  *clnt_tree, 
        MADDR_ST     *clnt_ip_addr,
        UINT16        time)
{
}


// Given an MCGRP_MBRSHP entry, deletes all tracking clients hanging off of it
void mcgrp_destroy_tracking_list (MCGRP_CLASS  *mcgrp,
        L2MCD_AVL_TREE  *clnt_tree)
{
    MCGRP_CLIENT *mcgrp_clnt, *next_clnt;

    if (!mcgrp || !clnt_tree)
        return;

    M_AVLL_SET_REBALANCE(*clnt_tree, FALSE);
    mcgrp_clnt = M_AVLL_FIRST(*clnt_tree);

    while (mcgrp_clnt)
    {
        next_clnt = M_AVLL_NEXT(*clnt_tree, mcgrp_clnt->node);

        M_AVLL_DELETE(*clnt_tree, mcgrp_clnt);

        mcgrp_free_client(mcgrp, mcgrp_clnt);

        mcgrp_clnt = next_clnt;
    }
    M_AVLL_SET_REBALANCE(*clnt_tree, TRUE);
}



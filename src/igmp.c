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
#include "l2mcd_data_struct.h"
#include "l2mcd_portdb.h"
#include "l2mcd_mld_port.h"
#include "l2mcd_mcast_co.h"
#include "l2mcd_mld_utils.h"

extern MCGRP_GLOBAL_CLASS    gMld, *pgMld;
extern MCGRP_GLOBAL_CLASS    gIgmp, *pgIgmp;
extern MCAST_GLOBAL_CLASS    gMulticast, *pgMulticast;
extern MCGRP_CLASS           Mld0, *pMld0;
extern MCGRP_CLASS           Igmp0, *pIgmp0;

extern L2MCD_AVL_TREE *mld_portdb_tree;
extern void mld_clear_mask(PORT_MASK *mask);
extern void mld_copy_mask(PORT_MASK *target, PORT_MASK *source);
extern MCGRP_CLASS          mld;
extern struct cli *gcli;

extern void mcgrp_vport_start_querier_process(MCGRP_CLASS * mcgrp, MCGRP_L3IF * mcgrp_vport);


/* Max bit/byte length of IPv6 address. */
#define IPV6_MAX_BYTELEN     16
#define IPV6_MAX_BITLEN      128
#define IPV6_ADDR_CMP(D,S)   memcmp ((D), (S), IPV6_MAX_BYTELEN)
#define IPV6_ADDR_SAME(D,S)  (memcmp ((D), (S), IPV6_MAX_BYTELEN) == 0)
#define IPV6_ADDR_COPY(D,S)  memcpy ((D), (S), IPV6_MAX_BYTELEN)
#define PRINT_SEC_OR_MS ((mcgrp_vport->LMQ_100ms_enabled == TRUE) ? "MilliSeconds" : "Seconds") 

extern MCAST_GLOBAL_CLASS			gMulticast; //, gMulticast6,*pgMulticast6;

// Forward declarations
UINT32 config_version_less_than_3_4();

unsigned short l3_get_port_from_bd_id(unsigned int bd_id)
{
    return (0);
}

int l3_get_port_from_ifindex(int ifindex)
{
    return (ifindex);
}

/*--------------------------------------------------------------------------------- **
 **                                                                                    **
 ** This is Multicast initialization function, it is called when IGMP/MLD is enabled.**
 ** The function allcates memory for  its data structure and start a periodic timer  **
 ** for sending IGMP/MLD Membership query messages. If igmp/mld is not enabled then  **
 ** the function does nothing.                                                     **
 **--------------------------------------------------------------------------------*/
//v4/v6 compliant
MCGRP_CLASS  *mcgrp_vrf_alloc (UINT32 afi, VRF_INDEX  vrf_index)
{
    MCGRP_CLASS  *mcgrp=NULL;
    MCGRP_CLASS         *sptr_next, *sptr_prev;
    MCGRP_GLOBAL_CLASS  *mcgrp_glb = NULL;

    L2MCD_INIT_LOG("%s mcgrp alloc for afi:%d vrf:%d",__FUNCTION__, afi,vrf_index);
    if (vrf_index == IPVRF_DEFAULT_VRF_IDX)
    {
        mcgrp = (IP_IPV4_AFI == afi) ? pIgmp0 : pMld0;
    }
    else if (vrf_index < IPVRF_INVALID_VRF_IDX)
    {
        mcgrp = os_malloc_zero(sizeof(MCGRP_CLASS));
        L2MCD_LOG_DEBUG("%s %d %p vrf:%d",__FUNCTION__, __LINE__,mcgrp,vrf_index);
        L2MCD_INIT_LOG("%s %d %p vrf:%d",__FUNCTION__, __LINE__,mcgrp,vrf_index);
    }
    else
    {
        /* Will not reach Here */
        L2MCD_LOG_ERR ("%s.ERR: Failed to initialize  for invalid" 
                " vrf-index %d\n", 
                (afi == IP_IPV4_AFI) ? "IGMP" : "MLD", vrf_index);
        L2MCD_INIT_LOG("%s.ERR: Failed to initialize  for invalid" 
                " vrf-index %d\n", 
                (afi == IP_IPV4_AFI) ? "IGMP" : "MLD",  vrf_index);
        return NULL;
    }

    if (!mcgrp) 
    {
        L2MCD_INIT_LOG("%s %d %p vrf:%d mcgrp NULL",__FUNCTION__, __LINE__,mcgrp,vrf_index);
        return NULL;
    }
    mcgrp->vrf_index = vrf_index;
    mcgrp->afi = afi;
    mcgrp->inst_fwd = NULL;
    mcgrp->inst_bwd = NULL;

    if (IS_IGMP_CLASS(mcgrp)) 
    {
        sptr_next = gIgmp.instances_list;
        mcgrp_glb = &gIgmp;
    }
    else
    {
        sptr_next = gMld.instances_list;
        mcgrp_glb = &gMld;
    }

    if (!mcgrp_glb)
    {
        return NULL;
    }

    sptr_prev = NULL;
    while (sptr_next)
    {
        if (vrf_index < sptr_next->vrf_index)
        {
            break;
        }
        sptr_prev = sptr_next;
        sptr_next = sptr_next->inst_fwd;
    }

    mcgrp->inst_fwd = sptr_next;
    mcgrp->inst_bwd = sptr_prev;

    if (mcgrp->inst_fwd)
        mcgrp->inst_fwd->inst_bwd = mcgrp;

    if (mcgrp->inst_bwd)
        mcgrp->inst_bwd->inst_fwd = mcgrp;
    else
        mcgrp_glb->instances_list = mcgrp;

    mcgrp_glb->instances[vrf_index] = mcgrp;

    //Initialize global wheel timer
    mcgrp->mcgrp_wtid = WheelTimer_Create(MCGRP_MAX_TIME_SLOTS, mcgrp_process_wte_event, 
            NULL, WheelTimer2DLinkedList);


    //Initialize global wheel timer for LMQ Interval
    mcgrp->mcgrp_wtid_lmq = WheelTimer_Create(MCGRP_MAX_TIME_SLOTS, mcgrp_process_wte_event, 
            NULL, WheelTimer2DLinkedList);

    L2MCD_LOG_DEBUG("%s %d allocated  %p %p vrf:%d lmq_wheeltimer:%lu",__FUNCTION__, __LINE__, mcgrp, pIgmp0, vrf_index,mcgrp->mcgrp_wtid_lmq);
    L2MCD_INIT_LOG("%s %d allocated  %p %p vrf:%d lmq_wheeltimer:%lu",__FUNCTION__, __LINE__, mcgrp, pIgmp0, vrf_index,mcgrp->mcgrp_wtid_lmq);
    L2MCD_INIT_LOG("%s Done. mcgrp alloc for afi:%d vrf:%d",__FUNCTION__, afi,vrf_index);
    return mcgrp;
}


//v4/v6 compliant
void mcgrp_reset_default_values (MCGRP_CLASS *mcgrp)
{
    if (IS_IGMP_CLASS(mcgrp))
    {
        igmp_reset_default_values(mcgrp);
    }
    else { ;}//MLD
}


void mcgrp_set_max_group_address(UINT32 afi, VRF_INDEX vrf_index, UINT32 val)
{
    MCGRP_CLASS *mcgrp= MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrf_index);
    MCGRP_GLOBAL_CLASS  *mcgrp_glb;
    int pool_lmt;

    if (!mcgrp)
    {
        if (afi == IP_IPV4_AFI)
        {
            igmp_enable (vrf_index, 0);
        }
        else {;} //MLD

        mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX (afi, vrf_index);

        if (!mcgrp)
            return;
    }
    mcgrp_glb = IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld;
    mcgrp->max_groups = val;
    if(! mcgrp->max_groups)
        mcgrp->max_groups = CU_DFLT_MLD_MAX_GROUP_ADDRESS;

    // Update the pool's upper limit if feasible
    pool_lmt = generic_get_pool_upper_limit(mcgrp_glb->group_pool);
    if (pool_lmt < 0)
    {
        pool_lmt = generic_get_pool_total_number(mcgrp_glb->group_pool);
        if (pool_lmt < mcgrp->max_groups)
        {
            set_generic_pool_upper_limit(mcgrp_glb->group_pool, mcgrp->max_groups);
            set_generic_pool_upper_limit(mcgrp_glb->grp_mbrshp_pool, mcgrp->max_groups);
        }
    }
    else if (pool_lmt < mcgrp->max_groups)
    {
        set_generic_pool_upper_limit(mcgrp_glb->group_pool, mcgrp->max_groups);
        set_generic_pool_upper_limit(mcgrp_glb->grp_mbrshp_pool, mcgrp->max_groups);
    }
}



/* **********************************************************
 *
 * This function allocates various data objects used by IGMP
 * The contents of this function were earlier executed by
 * pim_initialize_port_entry_memory()
 * Moved it here for the sake of consistency.
 *
 */
//v4/v6 compliant 
BOOLEAN mcgrp_alloc_init (MCGRP_CLASS *mcgrp)
{
    int  num_mcgrp_intfs = MAX_MCGRP_INTFS, i;

    i = CU_DFLT_IGMP_MAX_GROUP_ADDRESS;
    mcgrp_set_max_group_address(mcgrp->afi, mcgrp->vrf_index, i);

    if (IS_IGMP_CLASS(mcgrp))
    {
        if (!mcgrp->igmp_stats)
        {
            mcgrp->igmp_stats =
                (IGMP_STATS*) dy_malloc_zero(sizeof(IGMP_STATS) * num_mcgrp_intfs);

            if (mcgrp->igmp_stats == NULL)
            {
                L2MCD_LOG_ERR("%s.VRF%d.ERR: memory allocation for stats failed.\n",  __FUNCTION__, mcgrp->vrf_index);
                return FALSE;
            }
        }
    }
    return TRUE;
}

// v4/v6 compliant
BOOL mcgrp_initialize (UINT32 afi, MCGRP_CLASS *mcgrp)
{
    mcgrp->afi = afi;
    L2MCD_LOG_INFO("Initializing data structures (%d)\n", mcgrp->vrf_index,  mcgrp->vrf_index);

    /* if IGMP is enabled then initialize data areas and setup timer */
    // Allocate the various data structures used by IGMP
    if (!mcgrp_alloc_init(mcgrp)) {
        return FALSE;
    }
    mcgrp_reset_default_values(mcgrp);
    mcgrp->static_mcgrp_list_head = NULL;
    return TRUE;
}


BOOLEAN mcgrp_initialize_port_db_array(UINT32 afi)
{
    if (afi == IP_IPV4_AFI)
    {
        gIgmp.port_list = (MCGRP_L3IF**) dy_malloc_zero(sizeof(MCGRP_L3IF *) * (MAX_MC_INTFS));
        gIgmp.mcgrp_src_keyinfo = &igmpv3_src_keyinfo;
        L2MCD_INIT_LOG("%s port_list_size:%d",__FUNCTION__,MAX_MC_INTFS);
    }
    else
    {
        gMld.port_list = (MCGRP_L3IF**) dy_malloc_zero(sizeof(MCGRP_L3IF *) * (MAX_MC_INTFS));
        gMld.mcgrp_src_keyinfo = &mldv2_src_keyinfo;
    }
    return TRUE;
}

//v4/v6 compliant
MCGRP_L3IF *mcgrp_alloc_init_l3if_entry (MCGRP_CLASS   *mcgrp,
        UINT16         vir_port_id)
{
    if(!mcgrp)
        return NULL;
    MCGRP_GLOBAL_CLASS  *mcgrp_glb;
    MCGRP_L3IF          *mcgrp_vport;


    if (!mcgrp->enabled)
        return NULL;

    mcgrp_glb = (IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld);
    mcgrp_vport = mcgrp_glb->port_list[vir_port_id];

    if (mcgrp_vport == NULL)
    {

        mcgrp_vport = dy_malloc_zero(sizeof(MCGRP_L3IF));
        if (mcgrp_vport == NULL)
        {
            L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] Failed to allocate an MCGRP for virtual port ",FN,LN,vir_port_id);
            return NULL;
        }

        mcgrp_vport->vir_port_id = vir_port_id;
        mcgrp_vport->ve_port_mask = NULL;

        if (is_ip_tnnl_port(vir_port_id))
        {
            mcgrp_vport->phy_port_id = mcast_tnnl_get_output_port(vir_port_id);
        }
        else
        {
            mcgrp_vport->phy_port_id = vir_port_id;

            // If this is virtual port, alloc a port-mask for the member ports of this VE
            if (is_virtual_port(vir_port_id))
            {
                mcgrp_vport->ve_port_mask = 
                    dy_malloc_zero(mld_get_port_bitmap_size()); 
            }
        }

        // Inherit the port's IGMP version from the global version
        mcgrp_vport->cfg_version  = IGMP_VERSION_NONE;
        /* 
         * Setting oper_version as v2 for IGMP and v1 for MLD
         * Upon V3 support this code will be re-visiting and 
         * version will be set according to config
         */
        if (mcgrp->afi == IP_IPV4_AFI)
            mcgrp_vport->oper_version = IGMP_VERSION_2; 
        else
            mcgrp_vport->oper_version = MLD_VERSION_1;

        mcgrp_vport->phy_port_list = NULL;
        mcgrp_vport->ngroups = 0;
        mcgrp_vport->static_mcgrp_list_head = NULL;
        mcgrp_vport->rtr_port_list = NULL;
        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] allocated  MCGRP for virtual port %s,phy_port_id:%d oper_ver:%d",
                    FN,LN,vir_port_id, mld_get_if_name_from_port(vir_port_id),mcgrp_vport->phy_port_id,mcgrp_vport->oper_version);

        static int group_address_offset = M_AVLL_OFFSETOF(MCGRP_ENTRY, group_address);
        mcgrp_vport->sptr_grp_tree=L2MCD_AVL_CREATE(mcgrp_addr_cmp_cb_param, (void *) &group_address_offset, NULL);

        mcgrp_glb->port_list[vir_port_id] = mcgrp_vport;
    }
    return mcgrp_vport;
}


//Routines to handle events from interface manager
void mcgrp_vport_state_notify (MCGRP_CLASS  *mcgrp,
        UINT16        vir_port_id,
        //UINT16        phy_port_id, 
        UINT32        phy_port_id, 
        BOOLEAN       up)
{
    mld_vport_state_notify(vir_port_id, phy_port_id, up, mcgrp);
}

//v4/v6 compliant
    void
mcgrp_start_vir_port (MCGRP_CLASS *mcgrp, MCGRP_L3IF *mcgrp_vport)
{
    UINT16           vir_port_id = mcgrp_vport->vir_port_id;
    mld_vid_t        gvid = mld_get_vlan_id (vir_port_id);
    mld_vlan_node_t  *vlan_node = mld_vdb_vlan_get (gvid, mcgrp_vport->type);
    MCGRP_PORT_ENTRY *mcgrp_pport = mcgrp_vport->phy_port_list;
    mld_vlan_port_t  *vlan_port = NULL;
    BOOL             state_up = 0;

    for (; mcgrp_pport; mcgrp_pport = mcgrp_pport->next)
    {
        vlan_port = M_AVLL_FIND (vlan_node->port_tree, &(mcgrp_pport->phy_port_id));

        state_up = (vlan_port ? vlan_port->lif_state : 0); 

        mld_vport_state_notify (vir_port_id, mcgrp_pport->phy_port_id, state_up, mcgrp);
    }
}

// Updates the physical port-mask for all static groups that exist on tunnel interfaces
// with the current outgoing port for that tunnel
// The outgoing port is retrieved from the corresponding mcgrp_vport struct
//v4/v6 compliant
void mcgrp_update_staticGroup_tnnl_portmask (MCGRP_CLASS  *mcgrp, 
        MCGRP_L3IF   *mcgrp_vport)
{
    MCGRP_STATIC_ENTRY *mcgrp_entry;

    mcgrp_entry = mcgrp->static_mcgrp_list_head;
    for (; mcgrp_entry; mcgrp_entry = mcgrp_entry->next)
    {
        if (mcgrp_entry->port_num == mcgrp_vport->vir_port_id)
        {
            mld_sg_delete_porttree(&(mcgrp_entry->port_tree));
            mld_sg_porttree_addport(&(mcgrp_entry->port_tree),mcgrp_vport->phy_port_id);
        }
    }
}

void mcgrp_update_static_groups (MCGRP_CLASS         *mcgrp,
        MCGRP_L3IF          *mcgrp_vport,
        MCGRP_STATIC_ENTRY  *mcgrp_entry,
        UINT8                mcgrp_action,
        L2MCD_AVL_TREE      *port_tree,
        UINT32               target_port)
{
    MCAST_CLASS       *multicast =  MCAST_GET_INSTANCE_FROM_VRFINDEX(MCGRP_AFI(mcgrp), mcgrp->vrf_index);
    UINT32             phy_port_id;
    MCGRP_PORT_ENTRY  *mcgrp_pport;
    MADDR_ST           addr;
    UINT8              v3_action = mcgrp_action;
    UINT32            *src_list  = NULL;  //No sources              
    UINT16             num_srcs  = 0;
    MADDR_ST           group_addr;
    UINT8              version  = 0;
    unsigned char  port_type;
    sg_port_t *sg_port = NULL;

    mcast_set_addr(&group_addr, &mcgrp_entry->group_address);

    if (target_port == PORT_INDEX_INVALID)
    {
        sg_port = M_AVLL_FIRST(*port_tree);
        if(sg_port)
            phy_port_id = sg_port->ifindex;
        else 
            return;    
    }
    else
    {
        phy_port_id = target_port;
    }

    /* Notify mcgrp static group membership for every port in port mask */
    while(phy_port_id)
    {
        if (!mld_is_member_tree(port_tree, phy_port_id))
            continue;
        port_type = portdb_get_port_type(mld_portdb_tree, mcgrp_vport->vir_port_id);
        if (is_virtual_port(mcgrp_vport->vir_port_id)|| (port_type == INTF_MODE_L3))
        {
			L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] port:%d type:%d not forwarding skipping static group",
                  FN,LN,mcgrp_vport->vir_port_id, phy_port_id, port_type);
            continue;
        }
        port_type = portdb_get_port_type(mld_portdb_tree, mcgrp_vport->vir_port_id);
        if (is_virtual_port(mcgrp_vport->vir_port_id)|| (port_type == INTF_MODE_L3))
        {
            mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
            if (mcgrp_pport == NULL || ! mcgrp_pport->is_up)
            {
                continue;
            }
        }
        else
        {
            mcgrp_pport = mcgrp_vport->phy_port_list;
        }
        // On update, the PIM/DVMRP functions get the port# from this data struct
        // Thus, it is essential to set it.
        multicast->source_port = phy_port_id;
        if (IS_IGMP_CLASS(mcgrp))
        {   
            version = ((mcgrp_pport->oper_version >= IGMP_VERSION_2) ? IGMP_STATIC_VER2 : IGMP_STATIC_VER1);                    
            mcast_set_ipv4_addr(&addr, ip_get_lowest_ip_address_on_port(mcgrp_vport->vir_port_id, mcgrp_vport->type));
            if (igmp_update_ssm_parameters(mcgrp, &group_addr, &version, mcgrp_vport->vir_port_id,
                        phy_port_id, &v3_action,  &num_srcs, &src_list) == FALSE)
                continue;
        }
        else
        {
            //MLD   
        }

        mcgrp_update_group_address_table(mcgrp, mcgrp_vport->vir_port_id, 
                phy_port_id,
                &mcgrp_entry->group_address, 
                &addr,    // use intf's addr as client source
                v3_action,
                version,
                num_srcs, (void *)src_list /* No sources */);

        if (target_port == PORT_INDEX_INVALID) {
            sg_port = M_AVLL_NEXT(*port_tree, sg_port->node);
            if(sg_port) 
                phy_port_id = sg_port->ifindex;
            else
                break;
        }else { 
            break;
        }
    }
}



//v4/v6 compliant
void mcgrp_activate_static_groups (MCGRP_CLASS  *mcgrp, 
        UINT16        vir_port_id, 
        //UINT16        target_port)
        UINT32        target_port)
{
    if (!mcgrp)
        return;
    MCGRP_L3IF          *mcgrp_vport;
    MCGRP_STATIC_ENTRY  *mcgrp_entry;
    mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vir_port_id] : gMld.port_list[vir_port_id];
    if (mcgrp_vport == NULL)
    {
		L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] vport not found", FN,LN, vir_port_id);
        return;
    }

    mcgrp_entry = mcgrp->static_mcgrp_list_head;

    for (; mcgrp_entry; mcgrp_entry = mcgrp_entry->next)
    {
        if (mcgrp_entry->port_num == vir_port_id)
        {
            if (is_ip_tnnl_port(vir_port_id) &&
                    (mcgrp_vport->phy_port_id == PORT_INDEX_INVALID))
            {
                mcgrp_vport->phy_port_id = mld_mcast_tnnl_get_output_ifindex(vir_port_id);

                if (mcgrp_vport->phy_port_id != PORT_INDEX_INVALID)
                    mcgrp_update_staticGroup_tnnl_portmask(mcgrp, mcgrp_vport);
            }
            mcgrp_update_static_groups(mcgrp, mcgrp_vport, mcgrp_entry, IS_EXCL, 
                &(mcgrp_entry->port_tree), target_port);
        }
    }
}



void mcgrp_start_phy_port (MCGRP_CLASS       *mcgrp, 
        MCGRP_L3IF        *mcgrp_vport, 
        MCGRP_PORT_ENTRY  *mcgrp_pport)
{

    if (!mcgrp || !mcgrp_vport || !mcgrp_pport)
        return;

    UINT16               vir_port_id = mcgrp_vport->vir_port_id;
    UINT16               phy_port_id = NO_SUCH_PORT;
    if(is_ip_tnnl_port(vir_port_id))
    {
        mcgrp_pport->phy_port_id = mcast_tnnl_get_output_port(mcgrp_vport->vir_port_id);

        if(mcgrp_pport->phy_port_id > MAX_PORT)
        {
            mcgrp_pport->is_up = FALSE;
            return;
        }
    }

    phy_port_id = mcgrp_pport->phy_port_id;
    if (!is_physical_or_lag_port(phy_port_id))
        return;

    // We would like to send out queries on this port in order to learn
    // membership information on this port. So start the query process
    mcgrp_activate_static_groups(mcgrp, vir_port_id, mcgrp_pport->phy_port_id);
    mcgrp_activate_l2_static_groups(mcgrp, vir_port_id, mcgrp_pport->phy_port_id);

}

// Find a MCGRP_MBRSHP in the membership list anchored in MCGRP_ENTRY
//v4/v6 compliant
MCGRP_MBRSHP* mcgrp_find_mbrshp_entry (MCGRP_ENTRY  *grp_entry, 
        //    UINT16        phy_port_id)
    UINT32        phy_port_id)
{
    if (grp_entry == NULL)
        return NULL;
    if (grp_entry->mbr_port && (grp_entry->mbr_port->phy_port_id == phy_port_id))
        return grp_entry->mbr_port;

    return  M_AVLL_FIND(grp_entry->mbr_ports_tree, &phy_port_id);
}

// Stopping IGMP/MLD operation on a port
// Clean up the port's membership in all groups on the interface
// Note that we clean up the port's membership in static groups too,
// since we will re-activate the membership when the port comes up
//v4/v6 compliant
void mcgrp_stop_phy_port (MCGRP_CLASS       *mcgrp, 
        MCGRP_L3IF        *mcgrp_vport, 
        MCGRP_PORT_ENTRY  *mcgrp_pport)
{
    if (!mcgrp || !mcgrp_vport || !mcgrp_pport)
        return;

    MCGRP_ENTRY         *mcgrp_entry, *next_entry;
    MCGRP_MBRSHP        *mcgrp_mbrshp;
    MCGRP_STATIC_ENTRY  *mcgrp_static_entry;
    UINT16               vir_port_id = mcgrp_vport->vir_port_id;
    UINT32               phy_port_id = mcgrp_pport->phy_port_id;


    mcgrp_entry = (MCGRP_ENTRY *) M_AVLL_FIRST(mcgrp_vport->sptr_grp_tree);
    while (mcgrp_entry)
    {
        next_entry = (MCGRP_ENTRY *)M_AVLL_NEXT(mcgrp_vport->sptr_grp_tree,
                mcgrp_entry->node);

        mcgrp_mbrshp = mcgrp_find_mbrshp_entry(mcgrp_entry, phy_port_id);
        if (mcgrp_mbrshp == NULL)
        {
            L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] Vlan %s. Grp %s: failed to find mbrshp entry for port:%s, num_mbr_ports:%d \n",
                    FN, LN, vir_port_id, mld_get_if_name_from_port(vir_port_id),
                    mcast_print_addr(&mcgrp_entry->group_address), mld_get_if_name_from_ifindex(phy_port_id),mcgrp_entry->num_mbr_ports);
            mcgrp_entry = next_entry;
            continue;
        }
        
        // Notify Phy_port del to mcastss before destroying group membership entry.
        mcgrp_notify_phy_port_del(mcgrp, &mcgrp_entry->group_address,
                mcgrp_vport, phy_port_id, TRUE);

        //Stop wheeltimer on static group 
        mcgrp_static_entry = mcgrp_find_l2_staticGroup(mcgrp, vir_port_id, &mcgrp_entry->group_address);
        if (mcgrp_static_entry != NULL)
        {
             if (WheelTimerSuccess == WheelTimer_IsElementEnqueued
                                        (&mcgrp_static_entry->l2_static_grp_tmr.mcgrp_wte))
            {
                WheelTimer_DelElement(mcgrp->mcgrp_wtid,  &mcgrp_static_entry->l2_static_grp_tmr.mcgrp_wte);
                L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] Wheeltimer deleted from static Port:%d ", FN, LN, vir_port_id, phy_port_id);
            }
        }

        // Remove this port from the group membership
        L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] pim_snoop_mbrship:%d  w_g:%d %d ", FN, LN,vir_port_id,
                pims_is_pim_snoop_mbrship(mcgrp_mbrshp),
                mcgrp_mbrshp->pims_mbr_flags, (mcgrp_mbrshp->pims_mbr_flags & PIMS_WG_MBR_PORT));

        mcgrp_destroy_mbrshp_entry(mcgrp, mcgrp_entry, mcgrp_mbrshp);

        if(pims_is_pim_snoop_mbrship(mcgrp_mbrshp))
        {
            if(mcgrp_entry->pims_num_wg_join_ports > 0)
                mcgrp_entry->pims_num_wg_join_ports--;
            if(mcgrp_entry->pims_num_sg_join_ports > 0)
                mcgrp_entry->pims_num_sg_join_ports--;
            MLD_LOG(MLD_LOGLEVEL8, mcgrp->afi, "%s(%d) wg_join_ports:%d sg_join_ports:%d ",
                    FN, LN, mcgrp_entry->pims_num_wg_join_ports,
                    mcgrp_entry->pims_num_sg_join_ports);
        }
        //else
        mcgrp_mbrshp->pims_mbr_flags &= ~MLD_OR_IGMP_JOIN_PORT;

        // If no member ports left in this group, remove this group from this virtual port
        if (mcgrp_entry->num_mbr_ports == 0)
        {
            mcgrp_notify_vif_del(mcgrp, &mcgrp_entry->group_address, 
                    mcgrp_vport, mcgrp_entry, TRUE);

            mcgrp_destroy_group_addr(mcgrp, mcgrp_vport, mcgrp_entry);
        }
        mcgrp_entry = next_entry;

    } /* while (grp_entry) */
    mcgrp_pport->is_up = FALSE;
    if (is_ip_tnnl_port(vir_port_id))
        mcgrp_pport->phy_port_id = PORT_INDEX_INVALID;  
}


//v4/v6 compliant
void mcgrp_stop_vir_port (MCGRP_CLASS  *mcgrp, 
        MCGRP_L3IF   *mcgrp_vport)
{
    MCGRP_PORT_ENTRY* mcgrp_pport;

    mcgrp_pport = mcgrp_vport->phy_port_list;
    while (mcgrp_pport)
    {
        mcgrp_stop_phy_port(mcgrp, mcgrp_vport, mcgrp_pport);
        mcgrp_pport = mcgrp_pport->next;
    }
    if (WheelTimerSuccess ==
            WheelTimer_IsElementEnqueued(&mcgrp_vport->vport_tmr.mcgrp_wte))
        WheelTimer_DelElement(mcgrp->mcgrp_wtid,
                &mcgrp_vport->vport_tmr.mcgrp_wte);

    // Stop/Reset the querier process and any other timers
    mcgrp_vport->querier = TRUE;
    mcgrp_vport->v1_rtr_present = FALSE;
}

//v4/v6 compliant
MCGRP_PORT_ENTRY* mcgrp_add_phy_port (MCGRP_CLASS  *mcgrp,
        MCGRP_L3IF   *mcgrp_vport,
        //UINT16        phy_port_id)
        UINT32        phy_port_id)
{
    MCGRP_PORT_ENTRY  *new_mcgrp_pport;

    // Alloc init appropriate data structures
    new_mcgrp_pport = dy_malloc_zero(sizeof(MCGRP_PORT_ENTRY));
    if (new_mcgrp_pport == NULL)
    {
        L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] Failed to allocate an MCGRP_PORT_ENTRY for physical port %s ", 
             FN,LN,mcgrp_vport->vir_port_id, mld_get_if_name_from_ifindex(phy_port_id));
        return NULL;
    }

    new_mcgrp_pport->phy_port_id = phy_port_id;

    if (mcgrp_vport->is_ve)
    {
        if(mcgrp_vport->ve_port_mask)
            set_mask_bit((PORT_MASK *)mcgrp_vport->ve_port_mask, phy_port_id);
    }
    // Inherit the operating version from the virtual port's version
    new_mcgrp_pport->cfg_version  = IGMP_VERSION_NONE;

    new_mcgrp_pport->oper_version = mcgrp_vport->oper_version;
    L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] add phy_port:%d oper_version:%d list_p:0x%p ve_port_mask:%p to  phy_port_list", 
            __FUNCTION__, __LINE__, mcgrp_vport->vir_port_id, 
            new_mcgrp_pport->phy_port_id, new_mcgrp_pport->oper_version,mcgrp_vport->phy_port_list,mcgrp_vport->ve_port_mask);

    // Prepend the port to the list of ports
    new_mcgrp_pport->next       = mcgrp_vport->phy_port_list;
    mcgrp_vport->phy_port_list  = new_mcgrp_pport;

    return new_mcgrp_pport;
}


//v4/v6 compliant
MCGRP_PORT_ENTRY* mcgrp_find_phy_port_entry (MCGRP_CLASS  *mcgrp,
        MCGRP_L3IF   *mcgrp_vport,
        //UINT16        phy_port_id)
        UINT32        phy_port_id)
{
    MCGRP_PORT_ENTRY* mcgrp_pport = NULL;

    if (!mcgrp || !mcgrp_vport)
    {
        L2MCD_LOG_INFO("%s mcgrp or  mcgrp_vport NULL for phy_port_id:%d", __FUNCTION__, phy_port_id);
        return NULL;
    }

    mcgrp_pport = mcgrp_vport->phy_port_list;

    while (mcgrp_pport && (mcgrp_pport->phy_port_id != phy_port_id) )
        mcgrp_pport = mcgrp_pport->next;

    return mcgrp_pport;
}

MCGRP_MBRSHP* mcgrp_find_first_mbrshp (MCGRP_ENTRY *mcgrp_grp)
{
    if (mcgrp_grp->mbr_port)
    {
        return mcgrp_grp->mbr_port;
    }
    else
    {
        return M_AVLL_FIRST(mcgrp_grp->mbr_ports_tree);
    }
}

MCGRP_MBRSHP* mcgrp_find_next_mbrshp (MCGRP_ENTRY   *mcgrp_grp,
        MCGRP_MBRSHP  *mcgrp_mbrshp)
{
    if (!mcgrp_grp || !mcgrp_mbrshp)
        return NULL;

    if (mcgrp_grp->mbr_port == mcgrp_mbrshp)
        return NULL;
    else
        return M_AVLL_NEXT(mcgrp_grp->mbr_ports_tree, mcgrp_mbrshp->node);
}

// Find a MCGRP_SOURCE in the mode-specific source list anchored in MCGRP_MBRSHP
//v4/v6 compliant
MCGRP_SOURCE* mcgrp_find_source (MCGRP_MBRSHP      *mcgrp_mbrshp, 
        MADDR_ST          *src_addr, 
        MCGRP_FILTER_MODE  src_mode)
{
    MCGRP_SOURCE* mcgrp_src;

    if (mcgrp_mbrshp == NULL)
        return NULL;
    if(FILT_PIMS == src_mode)   //PIm snoop source
        mcgrp_src = mcgrp_mbrshp->pims_src_list;
    else    //IGMPv3 source
        mcgrp_src = mcgrp_mbrshp->src_list[src_mode];
    while (mcgrp_src &&
            (mcast_cmp_addr(&mcgrp_src->src_addr, src_addr) != 0))
        mcgrp_src = mcgrp_src->next;

    return mcgrp_src;
}



//v4/v6 compliant
MCGRP_ROUTER_ENTRY* mcgrp_find_rtr_port_entry (MCGRP_CLASS  *mcgrp,
        MCGRP_L3IF   *mcgrp_vport,
        UINT32        phy_port_id)
{
    MCGRP_ROUTER_ENTRY* mcgrp_rport = NULL;

    if (!mcgrp || !mcgrp_vport)
        return NULL;

    mcgrp_rport = mcgrp_vport->rtr_port_list;

    while (mcgrp_rport && (mcgrp_rport->phy_port_id != phy_port_id) )
        mcgrp_rport = mcgrp_rport->next;

    return mcgrp_rport;
}

void mcgrp_delete_phy_port (MCGRP_CLASS       *mcgrp,
        MCGRP_L3IF        *mcgrp_vport,
        MCGRP_PORT_ENTRY  *mcgrp_pport)
{
    if (!mcgrp || !mcgrp_vport || !mcgrp_pport)
        return; 
    L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] [ Port %s/%s ] : Deleted phy-port",
            FN,LN,mcgrp_vport->vir_port_id, mld_get_if_name_from_ifindex(mcgrp_pport->phy_port_id), 
            mld_get_if_name_from_port(mcgrp_vport->vir_port_id));


    // Remove the phy port from the VE port mask
    if (mcgrp_vport->ve_port_mask)
        clear_mask_bit((PORT_MASK *)mcgrp_vport->ve_port_mask, mcgrp_pport->phy_port_id);
    dy_free(mcgrp_pport);
}


// The physical port members of this virtual port may already.
// So, get the membership mask of this VE and create structures for its member ports
//v4/v6 compliant
void mcgrp_create_veport_members (MCGRP_CLASS  *mcgrp,
        MCGRP_L3IF   *mcgrp_vport)
{
    UINT16      vir_port_id, ve_id;
    PORT_MASK  *ve_mmbr_mask;
    vir_port_id = mcgrp_vport->vir_port_id;
    ve_id = ROUTER_INT_TO_VID(vir_port_id);
    if (VELIB_IS_VALID_VID(ve_id))
    {
        UINT16 ve_port;

        ve_mmbr_mask   = VELIB_GET_CONFIG_MASK(ve_id);

        // Allocate an entry for each of the physical ports of the VE
        for (ve_port=0; ve_port < MAX_PORT; ve_port++)
        {
            TRUNK_STATE trk_state;
            if (!mld_is_member2((PORT_MASK *)ve_mmbr_mask, ve_port))
                continue;
            trk_state = trunk_port_state(ve_port);
            if (trk_state == TRUNK_NONE || trk_state == TRUNK_PRIMARY)
            {
                MCGRP_PORT_ENTRY* mcgrp_pport;

                mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, ve_port);
                if (mcgrp_pport == NULL)
                {
                    mcgrp_pport = mcgrp_add_phy_port(mcgrp, mcgrp_vport, ve_port);
                    L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] [ Port %s/%s ] : Created phy-port",
                            FN,LN,vir_port_id, mld_get_if_name_from_ifindex(ve_port), mld_get_if_name_from_port(mcgrp_vport->vir_port_id));
                }
            }
        }
    }
}


// The virtual port just went down
// Destruct the physical port members of the virtual port
//v4/v6 compliant
void mcgrp_delete_veport_members (MCGRP_CLASS  *mcgrp,
        MCGRP_L3IF   *mcgrp_vport)
{
    MCGRP_PORT_ENTRY* mcgrp_pport;

    if (!mcgrp || !mcgrp_vport)
    {
        return;
    }

    mcgrp_pport = mcgrp_vport->phy_port_list;
    while (mcgrp_pport)
    {
        MCGRP_PORT_ENTRY* next_entry = mcgrp_pport->next;

        mcgrp_delete_phy_port(mcgrp, mcgrp_vport, mcgrp_pport);
        L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] phy_port:%d delete from phy_port_list",FN,LN,mcgrp_vport->vir_port_id,mcgrp_pport->phy_port_id);
        mcgrp_pport = next_entry;
    }
    mcgrp_vport->phy_port_list = NULL;
}


//v4/v6 compliant
void mcgrp_delete_veport (MCGRP_CLASS  *mcgrp,
        MCGRP_L3IF   *mcgrp_vport,
        UINT32       phy_port_id)
{
    MCGRP_PORT_ENTRY  *mcgrp_pport = NULL, *mcgrp_prev_pport = NULL;
    mcgrp_pport = mcgrp_vport->phy_port_list;

    while (mcgrp_pport && (mcgrp_pport->phy_port_id != phy_port_id))
    {
        mcgrp_prev_pport = mcgrp_pport;
        mcgrp_pport = mcgrp_pport->next;
    }
    if(!mcgrp_pport)
    {
        L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] phy_port:%d not found",FN,LN,mcgrp_vport->vir_port_id,phy_port_id);
        return;
    }
    L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] phy_port:%d delete from  phy_port_list",FN,LN,mcgrp_vport->vir_port_id,phy_port_id);
    if(mcgrp_prev_pport) {
        mcgrp_prev_pport->next = mcgrp_pport->next;
    } else { 
        mcgrp_vport->phy_port_list = mcgrp_pport->next;
    }

    mcgrp_delete_phy_port(mcgrp, mcgrp_vport, mcgrp_pport);
}

//v4/v6 compliant
void mcgrp_delete_staticGroup (MCGRP_CLASS         *mcgrp, 
        PORT_ID              port_id, 
        MCGRP_STATIC_ENTRY  *mcgrp_entry)
{
    WheelTimer_DelElement(mcgrp->mcgrp_wtid, &mcgrp_entry->static_grp_tmr.mcgrp_wte);
    if (mcgrp_entry)
    {
        linklist_delete_pointer((LINKLIST_TYPE **)&mcgrp->static_mcgrp_list_head, 
                (LINKLIST_TYPE *)mcgrp_entry);
    }

    return;
}

//v4/v6 compliant
void mcgrp_delete_static_groups_on_if (MCGRP_CLASS  *mcgrp,
        UINT16        vir_port_id, 
        //UINT16        target_port)
        UINT32        target_port)
{
    MCGRP_L3IF          *mcgrp_vport;
    MCGRP_STATIC_ENTRY  *mcgrp_entry, *next;
    if (!mcgrp)
    {
        return;
    }

    mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vir_port_id] : gMld.port_list[vir_port_id];
    if (mcgrp_vport == NULL)
    {
       	L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] vport not found", FN,LN, vir_port_id);
        return;
    }

    mcgrp_entry = mcgrp->static_mcgrp_list_head;

    for (; mcgrp_entry; mcgrp_entry = next)
    {
        next = mcgrp_entry->next;

        if (mcgrp_entry->port_num == vir_port_id)
        {
            mcgrp_update_static_groups(mcgrp,  mcgrp_vport, mcgrp_entry, TO_INCL, 
                    &(mcgrp_entry->port_tree), target_port);

            // Now delete mcgrp_entry
            mcgrp_delete_staticGroup(mcgrp, vir_port_id, mcgrp_entry);
            dy_free(mcgrp_entry);
        }
    }
}


// We have been called to delete an interface
//
// Delete all group entries on this port and then delete the port entry itself
//v4/v6 compliant
void mcgrp_delete_l3intf (MCGRP_CLASS  *mcgrp, 
        UINT16        vir_port_id)
{

    MCGRP_GLOBAL_CLASS  *mcgrp_glb  = (IS_IGMP_CLASS(mcgrp) ? &gIgmp : & gMld);
    MCGRP_ENTRY         *grp_entry, *next_grp_entry;
    MCGRP_L3IF          *mcgrp_vport;

    if (! MCGRP_IS_VALID_INTF(vir_port_id))
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] Port %s. Ignoring Delete on invalid intf",
                  FN, LN, vir_port_id,mld_get_if_name_from_port(vir_port_id));
        return;
    }
    L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] Port %s: Delete event",
            FN,LN,vir_port_id,  mld_get_if_name_from_port(vir_port_id));
    mcgrp_vport = mcgrp_glb->port_list[vir_port_id];
    if (!mcgrp_vport)
    {
        L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d].ERR: Port %s: Port already deleted; skipping member port delete",
                FN,LN,vir_port_id,  mld_get_if_name_from_port(vir_port_id));
        return;
    }

    M_AVLL_SET_REBALANCE(mcgrp_vport->sptr_grp_tree, FALSE);

    // Clean up all group memberships on this port
    grp_entry = M_AVLL_FIRST(mcgrp_vport->sptr_grp_tree);
    while (grp_entry)
    {
        next_grp_entry = M_AVLL_NEXT(mcgrp_vport->sptr_grp_tree, grp_entry->node);

        mcgrp_destroy_group_addr(mcgrp, mcgrp_vport, grp_entry);

        grp_entry = next_grp_entry;

    } /* while (grp_entry) */

    // Delete the static group configurations on this interface
    mcgrp_delete_static_groups_on_if(mcgrp, vir_port_id, PORT_INDEX_INVALID);
    mcgrp_delete_all_router_ports(mcgrp, mcgrp_vport);
    // If this is a virtual port bring down the physical port members of the virtual port

    unsigned char port_type = portdb_get_port_type(mld_portdb_tree, vir_port_id);
    if (is_virtual_port(vir_port_id) || (port_type == INTF_MODE_L3))

    {
        mcgrp_delete_veport_members(mcgrp, mcgrp_vport);

        // Free the port mask
        dy_free(mcgrp_vport->ve_port_mask);
    }
    else 
    {       
        if (mcgrp_vport->phy_port_list)
        {
            MCGRP_PORT_ENTRY  *mcgrp_pport = mcgrp_vport->phy_port_list;

            mcgrp_delete_phy_port(mcgrp, mcgrp_vport, mcgrp_pport);

        }       
    }
    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] Delete event",  FN,LN,vir_port_id);
    // Free the port-entry itself
    dy_free(mcgrp_vport);
    mcgrp_glb->port_list[vir_port_id] = NULL;
    
}


//v4/v6 compliant
MCGRP_L3IF* mcgrp_create_l3intf (MCGRP_CLASS  *mcgrp,
        UINT16        vir_port_id)
{
    MCGRP_L3IF          *mcgrp_vport;
    MCGRP_GLOBAL_CLASS  *mcgrp_glb;
    unsigned char  port_type;
    if (!mcgrp || ! mcgrp->enabled)
        return NULL;

    mcgrp_glb = IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld;

    if (!MCGRP_IS_VALID_INTF(vir_port_id))
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id,"%s:%d:[vlan:%d] Port %s. Ignoring Create on invalid intf\n", 
                FN,LN,vir_port_id,
                mld_get_if_name_from_port(vir_port_id));
        return NULL;
    }
    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] Port %s. Create event", 
            FN,LN,vir_port_id,
            mld_get_if_name_from_port(vir_port_id));

    vir_port_id = trunk_primary_port(vir_port_id);
    mcgrp_vport = mcgrp_glb->port_list[vir_port_id];
    // If an entry for this port already exists, verify, it is what we need
    if (mcgrp_vport != NULL)
    {   
        if ((mcgrp_vport->vir_port_id != vir_port_id) ||
                ((mcgrp_vport->phy_port_id != vir_port_id) &&
                 !is_ip_tnnl_port(vir_port_id)))
        {
            L2MCD_VLAN_LOG_ERR(vir_port_id,"%s:%d:[vlan:%d] [Port %s ] BUG!!!  invalid port configuration %s/%s",
                    FN, LN, vir_port_id,
                    mld_get_if_name_from_port(vir_port_id), mld_get_if_name_from_ifindex(mcgrp_vport->phy_port_id), 
                    mld_get_if_name_from_port(mcgrp_vport->vir_port_id));
            //RD: Need to check if any phy port has been allocated and free them up
            // Before freeing the l3 interface.
            mcgrp_glb->port_list[vir_port_id] = NULL;
            dy_free(mcgrp_vport);
        }
    }

    if (mcgrp_vport == NULL)
    {
        mcgrp_vport = mcgrp_alloc_init_l3if_entry(mcgrp, vir_port_id);
        if (!mcgrp_vport)
            return NULL;
        mcgrp_glb->port_list[vir_port_id] = mcgrp_vport;
    }

    // By default, we will always create it in the DN state
    mcgrp_vport->is_up = FALSE;

    // Now if this is a virtual port, bring up the physical port members of 
    // this VE else create just one physical port info.
    // in NOS, router port also considered as vlan
    port_type = portdb_get_port_type(mld_portdb_tree, vir_port_id);
    if (is_virtual_port(vir_port_id) || (port_type == INTF_MODE_L3))
    {
        mcgrp_vport->is_ve = TRUE;
        mcgrp_create_veport_members(mcgrp, mcgrp_vport);
    }
    else if (is_ip_tnnl_port(vir_port_id))
    {
        MCGRP_PORT_ENTRY  *mcgrp_pport = NULL;

        mcgrp_vport->is_ve = FALSE;
        mcgrp_pport = mcgrp_add_phy_port(mcgrp, mcgrp_vport, mcast_tnnl_get_output_port(vir_port_id));

        if (mcgrp_pport == NULL)
        {
            mcgrp_glb->port_list[vir_port_id] = NULL;
            dy_free(mcgrp_vport);
            return NULL;
        }
    }
    else
    {
        MCGRP_PORT_ENTRY  *mcgrp_pport = NULL;

        mcgrp_vport->is_ve = FALSE;
        mcgrp_pport = mcgrp_add_phy_port(mcgrp, mcgrp_vport, vir_port_id);
        if (mcgrp_pport == NULL)
        {
            mcgrp_glb->port_list[vir_port_id] = NULL;
            dy_free(mcgrp_vport);
            return NULL;
        }
    }
    mcgrp_vport->cfg_query_interval_time = MLD_DFLT_QUERY_INTERVAL;
    mcgrp_vport->query_interval_time = MLD_DFLT_QUERY_INTERVAL;
    mcgrp_vport->max_response_time  =   MLD_DFLT_RESPONSE_TIME;
    mcgrp_vport->robustness_var  = MLD_DFLT_ROBUSTNESS;
    mcgrp_vport->cfg_robustness_var = MLD_DFLT_ROBUSTNESS;
    mcgrp_vport->group_membership_time   = ((MLD_DFLT_QUERY_INTERVAL *
                mcgrp_vport->robustness_var) +
            (MLD_DFLT_RESPONSE_TIME));
    mcgrp_vport->older_host_present_time = CU_DFLT_IGMP_OLDER_HOST_PRESENT_TIME;
    mcgrp_vport->LMQ_interval            = MLD_DFLT_LLQI;      /* seconds */
    mcgrp_vport->LMQ_count               = mcgrp_vport->robustness_var;
    mcgrp_vport->start_up_query_count = mcgrp_vport->robustness_var;
    mcgrp_vport->start_up_query_interval = MLD_DFLT_QUERY_INTERVAL >> 2;
    return mcgrp_vport;
}


//v4/v6 compliant
void mcgrp_age_clnt_timers (MCGRP_CLASS   *mcgrp,
        L2MCD_AVL_TREE   *clnt_tree,
        MCGRP_CLIENT  *mcgrp_clnt) 
{
    if (!mcgrp || !mcgrp_clnt || !clnt_tree)
        return;

    M_AVLL_DELETE(*clnt_tree, mcgrp_clnt);
    mcgrp_free_client(mcgrp, mcgrp_clnt);

} /* mcgrp_age_clnt_timers() */


//v4/v6 compliant
UINT32 mcgrp_age_src_timers (MCGRP_CLASS     *mcgrp, 
        MCGRP_L3IF      *mcgrp_vport,
        MCGRP_ENTRY     *mcgrp_entry,
        MCGRP_MBRSHP    *mcgrp_mbrshp,
        UINT64           curr_time)
{
    MCGRP_SOURCE        **p_src;
    BOOL                  need_query = FALSE;
    MCGRP_GLOBAL_CLASS   *mcgrp_glb;
    UINT32                min_elapse_time = MCGRP_MAX_ELAPSE_TIME;
    MADDR_ST temp_addr;
    UINT8 default_lmq_handling = FALSE;

    if (!mcgrp || !mcgrp_vport || !mcgrp_entry || !mcgrp_mbrshp)
        return min_elapse_time; 

    mcgrp_glb = IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld;
    p_src = &mcgrp_mbrshp->src_list[FILT_INCL];

    while (*p_src)
    {
        BOOL deleted = FALSE;

        if ( mcgrp_vport->LMQ_100ms_enabled != TRUE )
        {
            if ((*p_src)->retx_cnt > 1)
            {
                (*p_src)->retx_cnt--;
                (*p_src)->src_timer = curr_time + mcgrp_vport->LMQ_interval; 
                (*p_src)->include_in_query = TRUE;
                if (min_elapse_time > mcgrp_vport->LMQ_interval)
                    min_elapse_time = mcgrp_vport->LMQ_interval;
                need_query = TRUE;
            }
            else if ((*p_src)->retx_cnt != 0)
            {
                //2nd time lmq timer expiry handling
                default_lmq_handling = TRUE;
            }
        }

        if ( ((*p_src)->retx_cnt==0) || (default_lmq_handling == TRUE) )
        {
            if ((*p_src)->src_timer <= curr_time)
            {
                // The source timer has expired. If we have retx attempts left,
                // restart the timer otherwise, if we are in the INCL mode, delete
                // the source and notify routing protocols

                MCGRP_SOURCE* p_delsrc = (*p_src);
                *p_src = (*p_src)->next;

                if (mcgrp_mbrshp->filter_mode == FILT_INCL)
                {
                    // Notify mcast routing protocols et al
                    mcgrp_notify_source_del_allowed(mcgrp, &mcgrp_entry->group_address, 
                            mcgrp_vport, mcgrp_mbrshp, 
                            &p_delsrc->src_addr, TRUE);
                }
                else
                {
                    // Src-Timer expired => nobody is interested in this source -
                    // move it to the EXCLuded list
                    sorted_linklist_add_one_item(mcgrp_glb->src_specific_pool,
                            mcgrp_glb->mcgrp_src_keyinfo,
                            (SORTED_LINKLIST**)&mcgrp_mbrshp->src_list[FILT_EXCL], 
                            &p_delsrc->src_addr);

                    mcgrp_notify_source_add_blocked(mcgrp, 
                            &mcgrp_entry->group_address, 
                            mcgrp_vport, mcgrp_mbrshp, 
                            &p_delsrc->src_addr, TRUE);
                    L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d]  Port %s,%s. Grp %s ] Added blocked source %s on src-timer expiry",
                                FN,LN,mcgrp_vport->vir_port_id, mld_get_if_name_from_port(mcgrp_mbrshp->phy_port_id), mld_get_if_name_from_port(mcgrp_vport->vir_port_id),
                            mcast_print_addr(&mcgrp_entry->group_address), mcast_print_addr(&p_delsrc->src_addr));
                }

                mcgrp_free_source(mcgrp, p_delsrc);
                deleted = TRUE;
            }
            else
            {
                if (min_elapse_time > (UINT32)((*p_src)->src_timer - curr_time))
                    min_elapse_time = (UINT32)((*p_src)->src_timer - curr_time); 
            }
        }

        if (!deleted)
        {
            if (IS_IGMP_CLASS(mcgrp))
            {
                mcast_init_addr(&temp_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
                mcast_set_ipv4_addr(&temp_addr, 0);
            }
            else
            {
                mcast_init_addr(&temp_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
                mcast_set_ipv6_addr(&temp_addr, &ip6_unspecified_address);
            }

            // Age client timers
            mcgrp_update_age_for_clnts(mcgrp, &(*p_src)->clnt_tree, 
                    &temp_addr, 
                    -MCGRP_PERIODIC_1_SECOND_TIMER);

            p_src = & (*p_src)->next;
        }
    }

    // If we need to send out a group-source-specific query, do so.
    if (need_query)
    {
        if (IS_IGMP_CLASS(mcgrp))
        {
            igmpv3_send_group_source_query(mcgrp, mcgrp_mbrshp,
                    mcgrp_vport->vir_port_id,
                    mcgrp_mbrshp->phy_port_id,
                    mcgrp_entry->group_address.ip.v4addr,
                    (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL],
                    (mcgrp_mbrshp->filter_mode == FILT_EXCL),
                    0, TRUE);     // is retx
        }
        else
        {
             //MLD
        }
    }



    return min_elapse_time;

} /* mcgrp_age_src_timers() */

UINT32 mcgrp_age_src_lmq_timers (MCGRP_CLASS *mcgrp, 
        MCGRP_L3IF      *mcgrp_vport,
        MCGRP_ENTRY     *mcgrp_entry,
        MCGRP_MBRSHP    *mcgrp_mbrshp,
        UINT64           curr_time)
{
    MCGRP_SOURCE        **p_src;
    BOOL                  need_query = FALSE;
    MCGRP_GLOBAL_CLASS   *mcgrp_glb;
    UINT32                min_elapse_time = MCGRP_MAX_ELAPSE_TIME;
    MADDR_ST temp_addr;

    if (!mcgrp || !mcgrp_vport || !mcgrp_entry || !mcgrp_mbrshp)
        return min_elapse_time; 

    mcgrp_glb = IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld;

    p_src = &mcgrp_mbrshp->src_list[FILT_INCL];
    while (*p_src)
    {
        BOOL deleted = FALSE;

        // the source and notify routing protocols
        if ((*p_src)->retx_cnt != 0)
        {
            if ((*p_src)->src_timer <= curr_time)
            {
                // The source timer has expired. If we have retx attempts left,
                // restart the timer otherwise, if we are in the INCL mode, delete
                // the source and notify routing protocols
                if ((*p_src)->retx_cnt > 1)
                {
                    (*p_src)->retx_cnt--;
                    (*p_src)->src_timer = curr_time + mcgrp_vport->LMQ_interval; 
                    (*p_src)->include_in_query = TRUE;
                    if (min_elapse_time > mcgrp_vport->LMQ_interval)
                        min_elapse_time = mcgrp_vport->LMQ_interval;
                    need_query = TRUE;
                }
                else /* we've exhausted our retx counts; delete source */
                {
                    MCGRP_SOURCE* p_delsrc = (*p_src);
                    *p_src = (*p_src)->next;

                    if (mcgrp_mbrshp->filter_mode == FILT_INCL)
                    {
                        // Notify mcast routing protocols et al
                        mcgrp_notify_source_del_allowed(mcgrp, &mcgrp_entry->group_address, 
                                mcgrp_vport, mcgrp_mbrshp, 
                                &p_delsrc->src_addr, TRUE);
                    }
                    else
                    {
                        // Src-Timer expired => nobody is interested in this source -
                        // move it to the EXCLuded list
                        sorted_linklist_add_one_item(mcgrp_glb->src_specific_pool,
                                mcgrp_glb->mcgrp_src_keyinfo,
                                (SORTED_LINKLIST**)&mcgrp_mbrshp->src_list[FILT_EXCL], 
                                &p_delsrc->src_addr);

                        mcgrp_notify_source_add_blocked(mcgrp, 
                                &mcgrp_entry->group_address, 
                                mcgrp_vport, mcgrp_mbrshp, 
                                &p_delsrc->src_addr, TRUE);

                        L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Added blocked source %s on src-timer expiry", 
                                FN,LN,mcgrp_vport->vir_port_id,
                                mld_get_if_name_from_ifindex(mcgrp_mbrshp->phy_port_id), mld_get_if_name_from_port(mcgrp_vport->vir_port_id),
                                mcast_print_addr(&mcgrp_entry->group_address),
                                mcast_print_addr(&p_delsrc->src_addr));
                    }

                    mcgrp_free_source(mcgrp, p_delsrc);
                    deleted = TRUE;
                }
            }
            else
            {
                if (min_elapse_time > (UINT32)((*p_src)->src_timer - curr_time))
                    min_elapse_time = (UINT32)((*p_src)->src_timer - curr_time); 
            }
        }

        if (!deleted)
        {
            if (IS_IGMP_CLASS(mcgrp))
            {
                mcast_init_addr(&temp_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
                mcast_set_ipv4_addr(&temp_addr, 0);
            }
            else
            {
                mcast_init_addr(&temp_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
                mcast_set_ipv6_addr(&temp_addr, &ip6_unspecified_address);
            }

            // Age client timers
            mcgrp_update_age_for_clnts(mcgrp, &(*p_src)->clnt_tree, 
                    &temp_addr, 
                    -MCGRP_PERIODIC_1_SECOND_TIMER);

            p_src = & (*p_src)->next;
        }
    }

    // If we need to send out a group-source-specific query, do so.
    if (need_query)
    {
        if (IS_IGMP_CLASS(mcgrp))
        {
            igmpv3_send_group_source_query(mcgrp, mcgrp_mbrshp,
                    mcgrp_vport->vir_port_id,
                    mcgrp_mbrshp->phy_port_id,
                    mcgrp_entry->group_address.ip.v4addr,
                    (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL],
                    (mcgrp_mbrshp->filter_mode == FILT_EXCL),
                    0, TRUE);     // is retx
        }
        else
        {
            //MLD
        }
    }

    return min_elapse_time;

} /* mcgrp_age_src_lmq_timers() */

// This function ages a port's membership in a particular group
//v4/v6 compliant
    void
mcgrp_age_group_mbrshp (MCGRP_CLASS   *mcgrp,
        MCGRP_L3IF    *mcgrp_vport, 
        MCGRP_ENTRY   *mcgrp_entry,
        MCGRP_MBRSHP  *mcgrp_mbrshp) 
{

    if (!mcgrp || !mcgrp_vport || !mcgrp_entry || !mcgrp_mbrshp)
        return;

    MCAST_CLASS         *multicast = NULL;
    uint8_t afi;

    UINT8                version, ver_min, ver_max;
    UINT16               vir_port_id = mcgrp_vport->vir_port_id;
    UINT32               phy_port_id = mcgrp_mbrshp->phy_port_id;
    MCGRP_PORT_ENTRY    *mcgrp_pport;
    MADDR_ST             addr;
    UINT32               min_elapsed_time = MCGRP_MAX_ELAPSE_TIME;
    UINT64               curr_time = read_tb_sec();
    MCGRP_SOURCE* mcgrp_src = NULL;
    uint8_t mclag_remote=0;
    UINT8  default_lmq_handling = FALSE;    

    multicast = MCAST_GET_INSTANCE_FROM_VRFINDEX(MCGRP_AFI(mcgrp), mcgrp->vrf_index);


    if (IS_IGMP_CLASS(mcgrp)) {
        afi = MCAST_IPV4_AFI;
    } else {
        afi = MCAST_IPV6_AFI;
    }
    if(multicast == NULL)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id,"%s(%d) multicast instance is NULL. ", FN, LN);
        return;
    }

    mcgrp_src = mcgrp_mbrshp->src_list[FILT_INCL];

    if (mcgrp_src == NULL)
    {
        if (mcgrp_mbrshp->is_remote)
        {
            L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] (*, %s) Mclag remote mbr restart on port %s.", 
                    FN,LN,vir_port_id, mcast_print_addr(&mcgrp_entry->group_address), 
                    mld_get_if_name_from_ifindex(phy_port_id));
            
            WheelTimer_ReTimeElement(mcgrp->mcgrp_wtid_lmq, 
                    &mcgrp_mbrshp->lmq_tmr.mcgrp_wte, 
                    260);
            mclag_remote=1;
        }
        
    }
    else
    {
        for (; mcgrp_src; mcgrp_src = mcgrp_src->next)
        {
            if(mcgrp_src->is_remote)
            {
                L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] (%s, %s) Mclag remote mbr restart on port %s.", 
                        FN,LN,vir_port_id, mcast_print_addr(&mcgrp_src->src_addr), mcast_print_addr(&mcgrp_entry->group_address), 
                        mld_get_if_name_from_ifindex(phy_port_id));

                WheelTimer_ReTimeElement(mcgrp->mcgrp_wtid_lmq, 
                        &mcgrp_mbrshp->lmq_tmr.mcgrp_wte, 
                        260);
                mclag_remote=1;
            }
        }
    }

    if (mclag_remote)
        return;

    L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] Group %s aged out on port %s.", 
            FN,LN,vir_port_id,                      
            mcast_print_addr(&mcgrp_entry->group_address), mld_get_if_name_from_ifindex(phy_port_id));

    mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
    // Age all source timers
    min_elapsed_time = mcgrp_age_src_timers(mcgrp, mcgrp_vport, mcgrp_entry,
            mcgrp_mbrshp, curr_time);

    // Age out older hosts that may be present on this port for this group
    // Note that we do not maintain a timer for V3 hosts and so do not perform
    // any aging action for V3 hosts
    if (IS_IGMP_CLASS(mcgrp))
    {
        ver_min = IGMP_VERSION_1;
        ver_max = IGMP_VERSION_2;
    }
    else
    {
        ver_min = ver_max = MLD_VERSION_1;
    }

    for (version = ver_min; version <= ver_max; version++)
    {
        if (mcgrp_mbrshp->host_present[version] > 0)
        {
            if (mcgrp_mbrshp->host_present[version] <= curr_time)
            {
                // There no longer exist any hosts at this version
                // So, increase the Group Compatibility version if we were
                // at this version
                if (mcgrp_mbrshp->grp_compver == version)
                {
                    UINT8 v;

                    for (v=version+1; v < mcgrp_pport->oper_version; v++) 
                    {
                        if ((int)(mcgrp_mbrshp->host_present[v] - curr_time) > 0)
                        {
                            mcgrp_mbrshp->grp_compver = v;
                            break;
                        }
                    }

                    if (v >= mcgrp_pport->oper_version)
                        mcgrp_mbrshp->grp_compver = (UINT8)mcgrp_pport->oper_version;
                }

                mcgrp_mbrshp->host_present[version] = 0;
            }
            else
            {
                if ( min_elapsed_time > (mcgrp_mbrshp->host_present[version] - curr_time))
                    min_elapsed_time = mcgrp_mbrshp->host_present[version] - curr_time;
            }
        }
    }

    // If we are in the EXCL mode, we must have group timers running. Age out the group
    if (mcgrp_mbrshp->filter_mode == FILT_EXCL) 
    {
        if (mcgrp_vport->LMQ_100ms_enabled != TRUE)
        {
            if (mcgrp_mbrshp->retx_cnt > 1)
            {
                mcgrp_mbrshp->retx_cnt--;
                if (min_elapsed_time > mcgrp_vport->LMQ_interval)
                    min_elapsed_time = mcgrp_vport->LMQ_interval;

                mcgrp_mbrshp->group_timer = curr_time + mcgrp_vport->LMQ_interval;

                if (IS_IGMP_CLASS(mcgrp))
                {
                    igmp_send_group_query(mcgrp, mcgrp_mbrshp,
                            vir_port_id,
                            phy_port_id,
                            (UINT8) mcgrp_pport->oper_version,
                            mcgrp_entry->group_address.ip.v4addr, //GSQ 
                            0,   // Use lowest IP addr of this port
                            0,
                            TRUE);  // retx

                    mcast_init_addr(&addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
                    mcast_set_ipv4_addr(&addr, 0);
                }
                else                                        
                {
                    //MLD                 
                }
            }
            else if (mcgrp_mbrshp->retx_cnt != 0)
            {
                //2nd time lmq expiry
                default_lmq_handling = TRUE;

            }

        }

        // The group timer has expired.
        // If there are any retransmit attempts, decrement retx count and 
        // restart timer
        // otherwise it is time to transition this group to the INCL mode
        if (mcgrp_mbrshp->retx_cnt == 0 || (default_lmq_handling == TRUE) )
        {
            if (mcgrp_mbrshp->group_timer <= curr_time)
            {

                L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d]. Group %s EXCL mode aged out on port %s. Moving to INCL",
                        FN,LN,vir_port_id,                      
                        mcast_print_addr(&mcgrp_entry->group_address), mld_get_if_name_from_ifindex(phy_port_id));

                // Make sure we remove this port from all entries
                multicast->source_port = phy_port_id;

                if (mcgrp_mbrshp->src_list[FILT_EXCL] != NULL)
                {
                    mcgrp_notify_phy_port_del(mcgrp, &mcgrp_entry->group_address, 
                            mcgrp_vport, phy_port_id, TRUE);
                }

                // There is no longer a host asserting an EXCLUDE condition for this group 
                // on this port
                // Transition to the INCLUDE state
                mcgrp_transition_to_INCL(mcgrp, mcgrp_vport, mcgrp_mbrshp, mcgrp_entry);

                if (mcgrp_mbrshp->src_list[FILT_INCL] != NULL)
                {
                    MADDR_ST group_addr;

                    group_addr.afi = MCGRP_AFI(mcgrp);
                    mcast_set_addr(&group_addr, &mcgrp_entry->group_address);
                    {
                        /* Update mcache; notify Routing Protocols */
                        multicast->source_port = phy_port_id;

                        mcgrp_notify_vif_add(mcgrp, &mcgrp_entry->group_address, 
                                mcgrp_vport, mcgrp_mbrshp, mcgrp_entry, TRUE);
                    }
                }
                else
                {
                    // For deletion of this group entry, see below
                }
            }
            else
            {
                if ((mcgrp_mbrshp->group_timer - curr_time) < min_elapsed_time)
                    min_elapsed_time = mcgrp_mbrshp->group_timer - curr_time;
            }
        }


    }

    // If this group is in the INCL mode but has no sources left, delete
    // this port's membership in the group.
    if (mcgrp_mbrshp->filter_mode == FILT_INCL &&
            mcgrp_mbrshp->src_list[FILT_INCL] == NULL)
    {

        if (mcgrp_mbrshp->retx_cnt == 0 || (default_lmq_handling == TRUE) )
        {

            if(is_mld_snooping_enabled(mcgrp_vport, afi) ||
                    is_mld_l3_configured(mcgrp_vport)) {
                if (IS_IGMP_CLASS(mcgrp)) {
                    igmp_send_igmp_message(mcgrp, vir_port_id, phy_port_id, IGMP_V2_LEAVE_GROUP_TYPE, mcgrp_vport->oper_version,
                            mcgrp_entry->group_address.ip.v4addr, mcgrp_mbrshp->client_source_addr.ip.v4addr, 0, NULL, 0, 0);
                } else {     
                    //MLD
                }
            }
            L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d:[vlan:%d] mcgrp_entry->group_address %s pims_mbr_flags 0x%x ", 
                    FN, LN, vir_port_id,
                    mcast_print_addr(&mcgrp_entry->group_address), mcgrp_mbrshp->pims_mbr_flags);
            //NOTE: IGMPv3 and PIM snooping sharing same ageout handler which can cause to destroy membership
            //for one of the (IGMPv3 INC or PIM snooping) entry ageout. 
            //Alternative to have separate handler for pim snooping wg ageout.
            /* Mmbr port ages out when both IGMP and PIM snooping membership is 
             * not available. If any one join is active
             * it will refresh the member port so no ageout happens.
             */
            if(pims_is_pim_snoop_mbrship(mcgrp_mbrshp) && mcgrp_entry->pims_num_wg_join_ports > 0)
                mcgrp_entry->pims_num_wg_join_ports--;

            /* Clear IGMPv3 flag on mbr port. By this time we would have notified pim
             */
            mcgrp_mbrshp->pims_mbr_flags &= ~MLD_OR_IGMP_JOIN_PORT;
            mcgrp_mbrshp->pims_mbr_flags &= ~IGMP_V3_MBR_PORT;
            if(NULL == mcgrp_mbrshp->pims_src_list)
            {
                mcgrp_notify_phy_port_del(mcgrp, &mcgrp_entry->group_address, 
                        mcgrp_vport, phy_port_id, TRUE);
                mcgrp_destroy_mbrshp_entry(mcgrp, mcgrp_entry, mcgrp_mbrshp);
            }

            if (mcgrp_entry->num_mbr_ports == 0)
            {
                L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d]  Age:%s(%d) GA:0x%x",
                        FN,LN, vir_port_id, portdb_get_ifname_from_portindex(phy_port_id),phy_port_id, htonl(mcgrp_entry->group_address.ip.v4addr));
                mcgrp_notify_vif_del(mcgrp, &mcgrp_entry->group_address, 
                        mcgrp_vport, mcgrp_entry, TRUE);
                mcgrp_destroy_group_addr(mcgrp, mcgrp_vport, mcgrp_entry); 
            }
        }
    }
    else
    {
        if (min_elapsed_time && (min_elapsed_time < MCGRP_MAX_ELAPSE_TIME))
        {
            // Add to the wheel timer.
            mcgrp_mbrshp->mbrshp_tmr.timer_type              = MCGRP_WTE_MBRSHP;
            mcgrp_mbrshp->mbrshp_tmr.mcgrp                   = mcgrp;
            mcgrp_mbrshp->mbrshp_tmr.wte.mbrshp.mcgrp_mbrshp = mcgrp_mbrshp;
            mcgrp_mbrshp->mbrshp_tmr.wte.mbrshp.vport        = mcgrp_vport;
            mcgrp_mbrshp->mbrshp_tmr.wte.mbrshp.grp_entry    = mcgrp_entry;
            mcgrp_mbrshp->mbrshp_tmr.mcgrp_wte.data          = &mcgrp_mbrshp->mbrshp_tmr;

            WheelTimer_AddElement(mcgrp->mcgrp_wtid, 
                    &mcgrp_mbrshp->mbrshp_tmr.mcgrp_wte,
                    min_elapsed_time); 
            L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] Started timer for ageing group membership %s on port %s/%s for %d %s",
                    FN,LN,vir_port_id, mcast_print_addr(&mcgrp_entry->group_address), mld_get_if_name_from_port(vir_port_id), 
                    mld_get_if_name_from_ifindex(phy_port_id), min_elapsed_time, PRINT_SEC_OR_MS);


        } 
        else
        {
            L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] ERR: - Unable to start timer for group membership since time is %d %s",
                    FN,LN,vir_port_id, min_elapsed_time, PRINT_SEC_OR_MS);
        }
    }
} /* mcgrp_age_group_mbrshp() */

// This function ages a port's membership in a particular group
//v4/v6 compliant
    void
mcgrp_age_group_mbrshp_and_lmq (MCGRP_CLASS   *mcgrp,
        MCGRP_L3IF    *mcgrp_vport, 
        MCGRP_ENTRY   *mcgrp_entry,
        MCGRP_MBRSHP  *mcgrp_mbrshp) 
{

    if (!mcgrp || !mcgrp_vport || !mcgrp_entry || !mcgrp_mbrshp)
        return;

    MCAST_CLASS         *multicast = NULL;
    //MCGRP_GLOBAL_CLASS  *mcgrp_glb = NULL;
    uint8_t afi;

    UINT16               vir_port_id = mcgrp_vport->vir_port_id;
    UINT32               phy_port_id = mcgrp_mbrshp->phy_port_id;
    MCGRP_PORT_ENTRY    *mcgrp_pport;
    MADDR_ST             addr;
    UINT32               min_elapsed_time = MCGRP_MAX_ELAPSE_TIME;
    UINT64               curr_time = read_tb_msec();  

    multicast = MCAST_GET_INSTANCE_FROM_VRFINDEX(MCGRP_AFI(mcgrp), mcgrp->vrf_index);
    if (IS_IGMP_CLASS(mcgrp)) {
        //mcgrp_glb = &gIgmp;
        afi = MCAST_IPV4_AFI;
    } else {
        //mcgrp_glb = &gMld;
        afi = MCAST_IPV6_AFI;
    }
    if(multicast == NULL)
    {
        //L2MCD_LOG_INFO("%s(%d) multicast instance is NULL. ", FN, LN);
        return;
    }
    mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);

    // Age all source timers
    min_elapsed_time = mcgrp_age_src_lmq_timers (mcgrp, mcgrp_vport, mcgrp_entry,
            mcgrp_mbrshp, curr_time);


    // If we are in the EXCL mode, we must have group timers running. Age out the group
    if (mcgrp_mbrshp->filter_mode == FILT_EXCL) 
    {
        // The group timer has expired.
        // If there are any retransmit attempts, decrement retx count and 
        // restart timer
        // otherwise it is time to transition this group to the INCL mode
        if (mcgrp_mbrshp->retx_cnt != 0)
        {
            if (mcgrp_mbrshp->lmq_timer <= curr_time)
            {

                if (mcgrp_mbrshp->retx_cnt > 1)
                {
                    mcgrp_mbrshp->retx_cnt--;
                    if (min_elapsed_time > mcgrp_vport->LMQ_interval)
                        min_elapsed_time = mcgrp_vport->LMQ_interval;
                    mcgrp_mbrshp->lmq_timer = curr_time + mcgrp_vport->LMQ_interval;
                    if (IS_IGMP_CLASS(mcgrp))
                    {
                        igmp_send_group_query(mcgrp, mcgrp_mbrshp,
                                vir_port_id,
                                phy_port_id,
                                (UINT8) mcgrp_pport->oper_version,
                                mcgrp_entry->group_address.ip.v4addr, //GSQ 
                                0,   // Use lowest IP addr of this port
                                0,
                                TRUE);  // retx

                        mcast_init_addr(&addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
                        mcast_set_ipv4_addr(&addr, 0);
                    }
                    else                                        
                    {
                        //MLD                  
                    }
                }
                else
                {   
                    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] Group %s EXCL mode aged out on port %s. Moving to INCL",
                            FN,LN,vir_port_id,                   
                            mcast_print_addr(&mcgrp_entry->group_address), mld_get_if_name_from_ifindex(phy_port_id));

                    // Make sure we remove this port from all entries
                    multicast->source_port = phy_port_id;

                    if (mcgrp_mbrshp->src_list[FILT_EXCL] != NULL)
                    {
                        mcgrp_notify_phy_port_del(mcgrp, &mcgrp_entry->group_address, 
                                mcgrp_vport, phy_port_id, TRUE);
                    }

                    // There is no longer a host asserting an EXCLUDE condition for this group 
                    // on this port
                    // Transition to the INCLUDE state
                    mcgrp_transition_to_INCL(mcgrp, mcgrp_vport, mcgrp_mbrshp, mcgrp_entry);

                    if (mcgrp_mbrshp->src_list[FILT_INCL] != NULL)
                    {
                        MADDR_ST group_addr;

                        group_addr.afi = MCGRP_AFI(mcgrp);
                        mcast_set_addr(&group_addr, &mcgrp_entry->group_address);
                        {
                            /* Update mcache; notify Routing Protocols */
                            multicast->source_port = phy_port_id;

                            mcgrp_notify_vif_add(mcgrp, &mcgrp_entry->group_address, 
                                    mcgrp_vport, mcgrp_mbrshp, mcgrp_entry, TRUE);

                        }
                    }
                    else
                    {
                        // For deletion of this group entry, see below
                    }
                }
            }
            else
            {
                if ((mcgrp_mbrshp->lmq_timer - curr_time) < min_elapsed_time)
                    min_elapsed_time = mcgrp_mbrshp->lmq_timer - curr_time;
            }
        }

    }

    // If this group is in the INCL mode but has no sources left, delete
    // this port's membership in the group.
    if (mcgrp_mbrshp->filter_mode == FILT_INCL &&
            mcgrp_mbrshp->src_list[FILT_INCL] == NULL)
    {
        if (mcgrp_mbrshp->retx_cnt != 0)
        {
            if(is_mld_snooping_enabled(mcgrp_vport, afi) ||
                    is_mld_l3_configured(mcgrp_vport)) {
                if (IS_IGMP_CLASS(mcgrp)) {
                    igmp_send_igmp_message(mcgrp, vir_port_id, phy_port_id, IGMP_V2_LEAVE_GROUP_TYPE, mcgrp_vport->oper_version,
                            mcgrp_entry->group_address.ip.v4addr, mcgrp_mbrshp->client_source_addr.ip.v4addr, 0, NULL, 0, 0);
                } else {     
                    //MLD
                }
            }
            MLD_LOG(MLD_LOGLEVEL7, afi, 
                    "%s(%d)  mcgrp_entry->group_address %s pims_mbr_flags 0x%x ", FN, LN, 
                    mcast_print_addr(&mcgrp_entry->group_address), mcgrp_mbrshp->pims_mbr_flags);

            //NOTE: IGMPv3 and PIM snooping sharing same ageout handler which can cause to destroy membership
            //for one of the (IGMPv3 INC or PIM snooping) entry ageout. 
            //Alternative to have separate handler for pim snooping wg ageout.
            /* Mmbr port ages out when both IGMP and PIM snooping membership is 
             * not available. If any one join is active
             * it will refresh the member port so no ageout happens.
             */
            if(pims_is_pim_snoop_mbrship(mcgrp_mbrshp) && mcgrp_entry->pims_num_wg_join_ports > 0)
                mcgrp_entry->pims_num_wg_join_ports--;

            /* Clear IGMPv3 flag on mbr port. By this time we would have notified pim
             */
            mcgrp_mbrshp->pims_mbr_flags &= ~MLD_OR_IGMP_JOIN_PORT;
            mcgrp_mbrshp->pims_mbr_flags &= ~IGMP_V3_MBR_PORT;
            if(NULL == mcgrp_mbrshp->pims_src_list)
            {
                mcgrp_notify_phy_port_del(mcgrp, &mcgrp_entry->group_address, 
                        mcgrp_vport, phy_port_id, TRUE);
                mcgrp_destroy_mbrshp_entry(mcgrp, mcgrp_entry, mcgrp_mbrshp);
            }
            if (mcgrp_entry->num_mbr_ports == 0)
            {
                mcgrp_notify_vif_del(mcgrp, &mcgrp_entry->group_address, 
                        mcgrp_vport, mcgrp_entry, TRUE);
                mcgrp_destroy_group_addr(mcgrp, mcgrp_vport, mcgrp_entry); 
            }
        }
    }
    else
    {
        if (min_elapsed_time && (min_elapsed_time < MCGRP_MAX_ELAPSE_TIME))
        {
            // Add to the wheel timer.
            mcgrp_mbrshp->lmq_tmr.timer_type              = MCGRP_WTE_LMQI;
            mcgrp_mbrshp->lmq_tmr.mcgrp                   = mcgrp;
            mcgrp_mbrshp->lmq_tmr.wte.mbrshp.mcgrp_mbrshp = mcgrp_mbrshp;
            mcgrp_mbrshp->lmq_tmr.wte.mbrshp.vport        = mcgrp_vport;
            mcgrp_mbrshp->lmq_tmr.wte.mbrshp.grp_entry    = mcgrp_entry;
            mcgrp_mbrshp->lmq_tmr.mcgrp_wte.data          = &mcgrp_mbrshp->lmq_tmr;

            WheelTimer_AddElement(mcgrp->mcgrp_wtid, 
                    &mcgrp_mbrshp->lmq_tmr.mcgrp_wte,
                    min_elapsed_time/100); 
            L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] EVT: - Started timer for ageing group membership %s on port %s/%s for %d %s",
                    FN,LN,vir_port_id, mcast_print_addr(&mcgrp_entry->group_address), mld_get_if_name_from_port(vir_port_id), 
                    mld_get_if_name_from_ifindex(phy_port_id), min_elapsed_time, PRINT_SEC_OR_MS);


        } 
        else
        {
            L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d]ERR: - Unable to start timer for group membership since time is %d %s",
                    FN,LN,vir_port_id, min_elapsed_time, PRINT_SEC_OR_MS);

        }
    }
} /* mcgrp_age_group_mbrshp() */


//v4/v6 compliant
void mcgrp_age_query_timers (MCGRP_CLASS       *mcgrp,
        MCGRP_L3IF  *mcgrp_vport)

{
    if (!mcgrp || !mcgrp_vport)
        return;   
    if (is_mld_l3_configured(mcgrp_vport))
    {
        L2MCD_VLAN_LOG_DEBUG(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] [ Vlan %s ] General Query Timer expired/ starting L3 querier. Sending Query version %d",
                FN,LN,mcgrp_vport->vir_port_id,
                mld_get_if_name_from_port(mcgrp_vport->vir_port_id),
                mcgrp_vport->oper_version);

        mcgrp_vport_start_querier_process (mcgrp, mcgrp_vport);
    } 
    else if (is_mld_snooping_querier_enabled(mcgrp_vport)) {
        L2MCD_VLAN_LOG_DEBUG(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] [ Vlan %s ] General Query Timer expired/ starting snooping querier. Sending Query version %d",
                FN,LN,mcgrp_vport->vir_port_id, 
                mld_get_if_name_from_port(mcgrp_vport->vir_port_id),
                mcgrp_vport->oper_version);
        mcgrp_vport_start_querier_process (mcgrp, mcgrp_vport);
    }
} /* mcgrp_age_query_timers() */

BOOLEAN pim_enabled (UINT32 afi, UINT16 port)
{
    if (afi == IP_IPV4_AFI)
    {
        return ((gMulticast.instances[IP_PORT_VRF_INDEX(port)]) &&
                (gMulticast.instances[IP_PORT_VRF_INDEX(port)]->allocated));
    }
    return (FALSE);
}

// Find a MCGRP_ENTRY in group list for a given port
//v4/v6 compliant
MCGRP_ENTRY* mcgrp_find_group_address_entry (MCGRP_CLASS  *mcgrp, 
        UINT16        vir_port_id,
        MADDR_ST     *group_address)
{
    MCGRP_L3IF   *mcgrp_vport = NULL;

    mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vir_port_id] : gMld.port_list[vir_port_id];
    if(!mcgrp_vport)
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] vport_not found", FN,LN,vir_port_id);
        return NULL;
    }
    return M_AVLL_FIND(mcgrp_vport->sptr_grp_tree, group_address);  
}

/* update the forwarding entries and add/delete the physical port;
 * virtual interface is still up and runing 
 */
//v4/v6 compliant 
void mcgrp_mcast_change_vport_membership (MCGRP_CLASS  *mcgrp, 
        MADDR_ST     *source_address,
        MADDR_ST     *group_address,
        UINT16        router_port, 
        UINT32        phy_port,
        UINT32        mcgrp_op)
{
    uint32_t            afi = (IS_IGMP_CLASS(mcgrp) ? MCAST_IPV4_AFI:MCAST_IPV6_AFI);
    MCGRP_L3IF          *mcgrp_vport    = NULL;
    mcast_grp_addr_t    grp_addr, src_addr;
    MCGRP_PORT_ENTRY    *mcgrp_pport    = NULL;
    MCGRP_ENTRY         *mcgrp_entry    = NULL;
    MCGRP_MBRSHP        *mcgrp_mbrshp   = NULL;
    BOOLEAN             is_pim_snp_mbr  = FALSE;
    MADDR_ST            addr_any;

    if (afi == MCAST_IPV4_AFI)
        mcgrp_vport = gIgmp.port_list[router_port];
    else
        mcgrp_vport = gMld.port_list[router_port];

    mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port);
    mcgrp_entry = mcgrp_find_group_address_entry(mcgrp, router_port, group_address);

    mcgrp_entry = mcgrp_find_group_address_entry(mcgrp, router_port, group_address);

    if (mcgrp_entry != NULL)
        mcgrp_mbrshp = mcgrp_find_mbrshp_entry(mcgrp_entry, phy_port);

    if (mcgrp_mbrshp == NULL)
    {

        L2MCD_VLAN_LOG_INFO(router_port, "%s:%d:[vlan:%d] Membership entry is not present for (%s, %s) port %d",
                __FUNCTION__, __LINE__, router_port, mcast_print_addr(source_address), mcast_print_addr(group_address), phy_port);

        return;
    }

    is_pim_snp_mbr = pims_is_pim_snoop_mbrship(mcgrp_mbrshp);
    if(mcgrp_op == MCGRP_ADD_GROUP) {
        if (mcgrp_pport && mcgrp_pport->oper_version == IGMP_VERSION_3) {
            MLD_LOG(MLD_LOGLEVEL6, MCGRP_AFI(mcgrp), "%s(%d) Sending to McastSS (%s, %s) mode:%d ", FN, LN,
                    mcast_print_addr(source_address), mcast_print_addr(group_address), mcgrp_mbrshp->filter_mode);
            igmpv3_send_l2mcd_sync_group_upd(group_address, router_port, 1, phy_port, 0, 0, source_address, 0, 0);
        } else {
            mld_send_l2mcd_sync_group_upd(group_address, router_port, 1, phy_port, 0, 0, source_address, 0);
        }
    } else {
        /* PIM snooping : This phy_port_id can be learnt from PIM joins so
         * check before we send the delete to mcastss
         */

        mcgrp_entry = mcgrp_find_group_address_entry(mcgrp, router_port, group_address);
        if(mcast_is_valid_unicast(source_address))
        {
            if (mcgrp_pport && (mcgrp_pport->oper_version == IGMP_VERSION_3) &&
                    (!mcast_addr_any(source_address))) 
            {

                L2MCD_VLAN_LOG_INFO(router_port, "%s:%d:[vlan:%d] Sending delete to McastSS (%s, %s) mode:%d %s", 
                        FN, LN, router_port, mcast_print_addr(source_address), mcast_print_addr(group_address), 
                        mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port));

                igmpv3_send_l2mcd_sync_group_upd(group_address, router_port,
                        0, 0 , 1 , phy_port, source_address, 0, 0);
            }
            else 
            {
                L2MCD_VLAN_LOG_INFO(router_port, "%s:%d:[vlan:%d]Sending delete to McastSS (%s, %s) mode:%d %s", 
                        FN, LN, router_port, mcast_print_addr(source_address), mcast_print_addr(group_address), 
                        mcgrp_mbrshp->filter_mode, mld_get_if_name_from_ifindex(phy_port));

                mld_send_l2mcd_sync_group_upd(group_address, router_port, 
                        0, 0 , 1 , phy_port, source_address, 0);
            }
        }
        else {
            if(!is_pim_snp_mbr)
                mld_send_l2mcd_sync_group_upd(group_address, router_port, 
                        0, 0 , 1 , phy_port, source_address, 0);
        }
    }
    //}
    //NOTE: For IGMPv3 source add/delete will take care notifying PIM.
    //if (is_mld_l3_configured(mcgrp_vport) && (mcgrp_vport->oper_version != IGMP_VERSION_3)) {
    if (is_mld_l3_configured(mcgrp_vport)) { 
        mcast_set_address(&grp_addr, group_address);
        //Initialize src_addr to 0. 
        mcast_init_addr(&addr_any, group_address->afi, MADDR_GET_FULL_PLEN(group_address->afi));
        mcast_set_addr_any(&addr_any);
        mcast_set_address(&src_addr, &addr_any);


        if((!mcast_addr_any(source_address)) && mcast_is_valid_unicast(source_address))
        {
            mcast_set_address(&src_addr, source_address);
        }
    }
}



UINT8 mcgrp_val2code (UINT16 val)
{
    UINT8 exp, mant;

    if (val < 0x80)
        return (UINT8)val;

    // Determine the mantissa
    mant = val & 0x7F;
    mant = ( (mant < 0x10) ? 0 : ((mant > 0x1F) ? 0xF : (mant & 0xF)) );

    // And now the exponent
    exp = 0;
    val >>= 8;
    for (; val > 0; val >>= 1, exp++);

    return (0x80 | (exp << 4) | mant);
}

/* *************************************************************
 *
 *  MCGRP_ENTRY list manipulation functions
 *
 * *************************************************************/

// Allocate and enlist a new MCGRP_ENTRY in the group list for a given port
//v4/v6 compliant
MCGRP_ENTRY* mcgrp_alloc_group_entry (MCGRP_CLASS  *mcgrp,
        MCGRP_L3IF   *mcgrp_l3if, 
        MADDR_ST     *group_address) 
{
    MCGRP_ENTRY         *new_grp_entry;
    new_grp_entry = calloc(1, sizeof(MCGRP_ENTRY));
    if (!new_grp_entry)
        return NULL;

    memset(new_grp_entry, 0, sizeof(MCGRP_ENTRY));
    M_AVLL_INIT_NODE(new_grp_entry->node); 
    mcast_set_addr(&new_grp_entry->group_address, group_address);
    new_grp_entry->num_mbr_ports = 0;
    new_grp_entry->mbr_port      = NULL;

    // Enlist the entry in the port's membership queue
    if (!M_AVLL_INSERT(mcgrp_l3if->sptr_grp_tree, new_grp_entry))
    {
        free(new_grp_entry);
        return NULL;
    }

    mcgrp_l3if->ngroups++;

    static int phy_port_id_offset= M_AVLL_OFFSETOF(MCGRP_MBRSHP, phy_port_id);
    new_grp_entry->mbr_ports_tree=L2MCD_AVL_CREATE(l2mcd_avl_compare_u32, (void *) &phy_port_id_offset, NULL);
    return new_grp_entry;
}

//v4/v6 compliant
void mcgrp_free_group_entry (MCGRP_CLASS  *mcgrp, 
        MCGRP_ENTRY  *grp_entry)
{
    if (grp_entry)
    {
        free(grp_entry);
    }
}

// Given a pointer to a GROUP_ENTRY, destroys all the members in the group
//v4/v6 compliant
void mcgrp_destroy_grp_mbrshp_list (MCGRP_CLASS  *mcgrp, 
        MCGRP_ENTRY  *mcgrp_entry)
{
    MCGRP_MBRSHP *mbrshp, *next_mbrshp;

    mbrshp = mcgrp_find_first_mbrshp(mcgrp_entry);
    while (mbrshp)
    {
        next_mbrshp = mcgrp_find_next_mbrshp(mcgrp_entry, mbrshp);

        mcgrp_destroy_mbrshp_entry(mcgrp, mcgrp_entry, mbrshp);

        mbrshp = next_mbrshp;
    }
}

// Find and delete (delink + free) a MCGRP_ENTRY from the list 
// anchored in a port's group list
void mcgrp_destroy_group_addr (MCGRP_CLASS  *mcgrp,
        MCGRP_L3IF   *vport, 
        MCGRP_ENTRY  *del_group)
{
    if (!vport || !del_group)
        return;
    
    L2MCD_VLAN_LOG_INFO(vport->vir_port_id, "%s:%d:[vlan:%d] Destroying Group 0x%x vport->ngroups:%d",FN,LN,vport->vir_port_id,htonl(del_group->group_address.ip.v4addr),vport->ngroups);

    M_AVLL_DELETE(vport->sptr_grp_tree, del_group);
    vport->ngroups--;
    mcgrp_destroy_grp_mbrshp_list(mcgrp, del_group);
    mcgrp_free_group_entry(mcgrp, del_group);
}

/* *************************************************************
 *
 *  MCGRP_MBRSHP list manipulation functions
 *
 * *************************************************************/

// Allocate and enlist a new MCGRP_MBRSHP in the membership list anchored in MCGRP_ENTRY
//v4/v6 compliant
MCGRP_MBRSHP* mcgrp_alloc_add_mbrshp_entry (MCGRP_CLASS  *mcgrp, 
        MCGRP_ENTRY  *grp_entry, 
        MCGRP_L3IF   *mcgrp_vport, 
        UINT32        phy_port_id,
        BOOLEAN       is_static, 
        UINT8         version)
{
    MCGRP_MBRSHP        *new_mbrshp;

    new_mbrshp  = calloc (1, sizeof(MCGRP_MBRSHP));
    if (new_mbrshp == NULL)
    {
        L2MCD_VLAN_LOG_ERR(mcgrp_vport->vir_port_id,"%s:%d mbrship alloc err ",__FUNCTION__, __LINE__);
        return NULL;
    }

    memset(new_mbrshp, 0, sizeof(MCGRP_MBRSHP));

    new_mbrshp->phy_port_id = phy_port_id;

    new_mbrshp->static_mmbr    = is_static;
    new_mbrshp->aging_enabled  = ! is_static;

    new_mbrshp->filter_mode = FILT_INCL;

    static int clnt_addr_offset= M_AVLL_OFFSETOF(MCGRP_CLIENT, clnt_addr);
    new_mbrshp->clnt_tree= L2MCD_AVL_CREATE(mcgrp_addr_cmp_cb_param, (void *) &clnt_addr_offset, NULL);


    if (!mcgrp_vport->is_ve) {
        grp_entry->mbr_port = new_mbrshp;
    }
    else
    {
        M_AVLL_INIT_NODE(new_mbrshp->node);
        if (!M_AVLL_INSERT(grp_entry->mbr_ports_tree, new_mbrshp))
        {
            free(new_mbrshp);
            return NULL;
        }
    }

    new_mbrshp->group_uptime =  mld_get_current_monotime();
    new_mbrshp->group_timer = 0; 

    grp_entry->num_mbr_ports++;
    return new_mbrshp;
}



// Find a MCGRP_MBRSHP in the membership list anchored in MCGRP_ENTRY
//v4/v6 compliant
MCGRP_MBRSHP* mcgrp_find_mbrshp_entry_for_grpaddr (MCGRP_CLASS  *mcgrp, 
        MADDR_ST     *group_address, 
        UINT16        vir_port_id, 
        UINT32        phy_port_id)
{
    MCGRP_ENTRY   *grp_entry;

    grp_entry = mcgrp_find_group_address_entry(mcgrp, vir_port_id, group_address);
    if (grp_entry == NULL)
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] GA %s entry not found for phy_port_id:%d ", FN,LN,vir_port_id,mcast_print_addr(group_address), phy_port_id);
        return NULL;
    }
    return mcgrp_find_mbrshp_entry(grp_entry, phy_port_id);
}




//v4/v6 compliant
void mcgrp_free_mbrshp_entry (MCGRP_CLASS   *mcgrp, 
        MCGRP_MBRSHP  *mcgrp_mbrshp)
{
    if (mcgrp_mbrshp)
    {
        free(mcgrp_mbrshp);
    }
}

/* Clear commands */
void mcgrp_pims_destroy_src_list(MCGRP_CLASS *mcgrp,
        MCGRP_MBRSHP *mcgrp_mbrshp)
{
    MCGRP_SOURCE *pims_src_entry, *next = NULL;
    if(!mcgrp || !mcgrp_mbrshp || !mcgrp_mbrshp->pims_src_list)
        return;
    MLD_LOG(MLD_LOGLEVEL5, MLD_IP_IPV4_AFI, "%s(%d): PIMS: Enter", FN, LN);
    pims_src_entry = mcgrp_mbrshp->pims_src_list;
    while(pims_src_entry)
    {
        next = pims_src_entry->next;
        /* remove src timer */
        if (WheelTimerSuccess ==
                WheelTimer_IsElementEnqueued(&pims_src_entry->pims_src_tmr.mcgrp_wte))
        {
            WheelTimer_DelElement(mcgrp->mcgrp_wtid,
                    &pims_src_entry->pims_src_tmr.mcgrp_wte);
        }
        MLD_LOG(MLD_LOGLEVEL9, MLD_IP_IPV4_AFI, 
                "%s(%d): source %s being freed from port:%d", FN, LN,
                mcast_print_addr(&pims_src_entry->src_addr), mcgrp_mbrshp->phy_port_id);
        mcgrp_free_source(mcgrp, pims_src_entry);
        pims_src_entry = next;
    }
    mcgrp_mbrshp->pims_src_list = NULL;
    return;
}

// Given a MCGRP_MBRSHP entry, deletes all sources (both INCL and EXCL lists)
// hanging off of it
//v4/v6 compliant
void mcgrp_destroy_source_list (MCGRP_CLASS   *mcgrp, 
        MCGRP_MBRSHP  *mcgrp_mbrshp)
{
    MCGRP_SOURCE  *mcgrp_src, *next_src;
    UINT8          mode;

    for (mode = FILT_INCL; mode <= FILT_EXCL; mode++)
    {
        mcgrp_src = mcgrp_mbrshp->src_list[mode];
        while (mcgrp_src)
        {
            next_src = mcgrp_src->next;
            mcgrp_free_source(mcgrp, mcgrp_src);

            mcgrp_src = next_src;
        }
    }
}

// Find and delete (delink + free) an MCGRP_MGRSHP_ENTRY from the membership list
// anchored in a MCGRP_ENTRY
//v4/v6 compliant
void mcgrp_destroy_mbrshp_entry (MCGRP_CLASS  *mcgrp, 
        MCGRP_ENTRY  *grp_entry, 
        MCGRP_MBRSHP *mcgrp_mbrshp)
{
    if (!mcgrp || !mcgrp_mbrshp || !grp_entry)
        return;

    if (grp_entry->mbr_port == mcgrp_mbrshp)
        grp_entry->mbr_port = NULL;
    else
        M_AVLL_DELETE(grp_entry->mbr_ports_tree, mcgrp_mbrshp);

    grp_entry->num_mbr_ports--;

    mcgrp_destroy_source_list(mcgrp, mcgrp_mbrshp);
    //TODO: destroy PIM snooping source list as weel here
    mcgrp_destroy_tracking_list(mcgrp, &mcgrp_mbrshp->clnt_tree);

    /* Destroy PIM snooping source list as well */
    mcgrp_pims_destroy_src_list(mcgrp, mcgrp_mbrshp);
    /* Delete the timers associated with PIM snoop sources */
    if (WheelTimerSuccess == WheelTimer_IsElementEnqueued(&mcgrp_mbrshp->mbrshp_tmr.mcgrp_wte))
        WheelTimer_DelElement(mcgrp->mcgrp_wtid, &mcgrp_mbrshp->mbrshp_tmr.mcgrp_wte);

    if (WheelTimerSuccess == WheelTimer_IsElementEnqueued(&mcgrp_mbrshp->lmq_tmr.mcgrp_wte))
        WheelTimer_DelElement(mcgrp->mcgrp_wtid_lmq, &mcgrp_mbrshp->lmq_tmr.mcgrp_wte);

    mcgrp_free_mbrshp_entry(mcgrp, mcgrp_mbrshp);
}


BOOL mcgrp_src_list_empty ( MCGRP_MBRSHP      *mcgrp_mbrsh,
        MCGRP_FILTER_MODE  src_mode,
        UINT8 version)
{
    if(version == IGMP_VERSION_3)
    {
        if(mcgrp_mbrsh->src_list[src_mode])
            return FALSE;
        else
            return TRUE;
    }
    else// For igmp ver 2 operating , just return true.
    {
        return TRUE;
    }
}


// Find and delink an MCGRP_SOURCE from the mode-specific source list
// anchored in a MCGRP_MBRSHP
//v4/v6 compliant
MCGRP_SOURCE* mcgrp_delist_source (MCGRP_MBRSHP      *mcgrp_mbrshp, 
        MADDR_ST          *src_addr, 
        MCGRP_FILTER_MODE  src_mode)
{
    MCGRP_SOURCE **p_src, *mcgrp_src = NULL;

    if (mcgrp_mbrshp == NULL)
        return NULL;
    if(FILT_PIMS == src_mode)
        p_src = &mcgrp_mbrshp->pims_src_list;
    else
        p_src = &mcgrp_mbrshp->src_list[src_mode];
    while ((*p_src) &&
            (mcast_cmp_addr(&((*p_src)->src_addr), src_addr) != 0))
        p_src = & (*p_src)->next;

    if (*p_src)
    {
        mcgrp_src = *p_src;
        *p_src = mcgrp_src->next;
    }

    return mcgrp_src;
}


//v4/v6 compliant
void mcgrp_handle_intf_ver_change (MCGRP_CLASS  *mcgrp, 
        MCGRP_L3IF   *mcgrp_vport)
{
    if (mcgrp == NULL || mcgrp_vport == NULL)
        return;

    if (is_virtual_port(mcgrp_vport->vir_port_id))
    {
        mcgrp_stop_vir_port(mcgrp, mcgrp_vport);
        mcgrp_start_vir_port(mcgrp, mcgrp_vport);
    }
    else
    {
        mcgrp_stop_phy_port(mcgrp, mcgrp_vport, mcgrp_vport->phy_port_list);
        mcgrp_start_phy_port(mcgrp, mcgrp_vport, mcgrp_vport->phy_port_list);
    }
}


//Common routine to send in a query at startup
//v4/v6 compliant
void mcgrp_start_query_process (MCGRP_CLASS       *mcgrp, 
        MCGRP_PORT_ENTRY  *mcgrp_pport, 
        UINT16             vir_port_id,
        UINT32             phy_port_id)
{

    if (!mcgrp || !mcgrp_pport)
        return;
    if (!is_physical_or_lag_port(phy_port_id))
        return;
}

// This function is called periodically to refresh the static group memberships
//v4/v6 compliant
void mcgrp_refresh_static_group (MCGRP_CLASS         *mcgrp, 
        MCGRP_STATIC_ENTRY  *mcgrp_entry)
{
    if (!mcgrp || !mcgrp_entry)
        return;

    MCAST_CLASS         *multicast =  MCAST_GET_INSTANCE_FROM_VRFINDEX(MCGRP_AFI(mcgrp), mcgrp->vrf_index);
    UINT16               phy_port_id, vir_port_id;
    MCGRP_L3IF          *mcgrp_vport = NULL;
    BOOLEAN              virport = FALSE;
    MADDR_ST            *group_address;
    MADDR_ST             addr;
    UINT8                version = 0;
    UINT8                igmp_action = 0;
    UINT16               num_srcs = 0;
    UINT32              *src_list = NULL;
    sg_port_t           *sg_port;

    group_address = &mcgrp_entry->group_address;

    vir_port_id = mcgrp_entry->port_num;

    mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vir_port_id] : gMld.port_list[vir_port_id];
    if (mcgrp_vport == NULL || (! mcgrp_vport->is_up) )
    {
        if (mcgrp_vport == NULL)
        {
            L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] vport not found ", FN,LN,vir_port_id);
            return;
        }
    }

    if (is_ip_tnnl_port(vir_port_id) &&
            (mcgrp_vport->phy_port_id == PORT_INDEX_INVALID))
    {
        mcgrp_vport->phy_port_id = mcast_tnnl_get_output_port(vir_port_id);

        if (mcgrp_vport->phy_port_id != PORT_INDEX_INVALID)
            mcgrp_update_staticGroup_tnnl_portmask(mcgrp, mcgrp_vport);
    }
    else if (is_virtual_port(vir_port_id)|| (portdb_get_port_type(mld_portdb_tree, vir_port_id) == INTF_MODE_L3))
    {
        virport = TRUE;
    }
    for(sg_port = M_AVLL_FIRST(mcgrp_entry->port_tree);
            sg_port;
            sg_port = M_AVLL_NEXT(mcgrp_entry->port_tree,sg_port->node))
    {
        phy_port_id = sg_port->ifindex;
        MCGRP_PORT_ENTRY  *mcgrp_pport = NULL; 

        if (virport)
        {
            mcgrp_pport = mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
            if (mcgrp_pport == NULL || ! mcgrp_pport->is_up)
            {
                continue;
            }
        }
        else
        {
            mcgrp_pport = mcgrp_vport->phy_port_list;
        }

        // On update, the PIM/DVMRP functions get the port# from this data struct
        // Thus, it is essential to set it.
        multicast->source_port = phy_port_id;

        version = ((mcgrp_pport->oper_version >= IGMP_VERSION_2) ?
                IGMP_STATIC_VER2 : IGMP_STATIC_VER1);

        if (IS_IGMP_CLASS(mcgrp))
        {
            mcast_set_ipv4_addr(&addr, ip_get_lowest_ip_address_on_port(vir_port_id, mcgrp_vport->type));
            igmp_action = IS_EXCL ;
            if(igmp_update_ssm_parameters(mcgrp, group_address, &version, vir_port_id,
                        phy_port_id, &igmp_action, &num_srcs, &src_list) == FALSE)
                continue;
        }
        else
        {
            //MLD      
        }               

        mcgrp_update_group_address_table(mcgrp, vir_port_id, phy_port_id,
                group_address, 
                &addr,    // use intf's addr as client source
                igmp_action,
                version,
                num_srcs, (void *)src_list /* No sources */);

    }

    if (WheelTimerSuccess == WheelTimer_IsElementEnqueued(&mcgrp_entry->static_grp_tmr.mcgrp_wte))
        WheelTimer_ReTimeElement(mcgrp->mcgrp_wtid, 
                &mcgrp_entry->static_grp_tmr.mcgrp_wte, 
                (UINT32)mcgrp_vport->query_interval_time);

    else
        WheelTimer_AddElement(mcgrp->mcgrp_wtid,
                &mcgrp_entry->static_grp_tmr.mcgrp_wte, 
                (UINT32)mcgrp_vport->query_interval_time);

}
//v4/v6 compliant
BOOLEAN mcgrp_send_group_source_query (MCGRP_CLASS        *mcgrp, 
        MCGRP_MBRSHP       *mcgrp_mbrshp,
        UINT16              vir_port_id,
        UINT32              phy_port_id,
        MADDR_ST           *group_address,
        SORTED_LINKLIST   **p_src_list,
        BOOLEAN             was_excl,
        MADDR_ST           *clnt_ip_addr,
        enum BOOLEAN        is_retx)
{

    if (IS_IGMP_CLASS(mcgrp))
    {
        return igmpv3_send_group_source_query(mcgrp, mcgrp_mbrshp,
                vir_port_id, phy_port_id,
                group_address->ip.v4addr,
                (SORTED_LINKLIST**) &mcgrp_mbrshp->src_list[FILT_INCL],
                was_excl,         // 0 => was not EXCL mode
                clnt_ip_addr->ip.v4addr,
                is_retx /* not retx */);
    }
    else
    {
        //MLD
        return 0;                        
    }   
}

// This function is invoked to signal change in state of an IP interface
//v4/v6 compliant
void mcgrp_port_state_notify (UINT32        afi, 
        VRF_INDEX     vrf_index, 
        UINT16        port_id, 
        enum BOOLEAN  up)
{
    MCGRP_CLASS         *mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrf_index); 
    MCGRP_L3IF          *mcgrp_vport;
    UINT16               vir_port_id;
    if (!mcgrp || !mcgrp->enabled || ! MCGRP_IS_VALID_INTF(port_id))
    {
        return;
    }

    vir_port_id = trunk_primary_port(port_id);

    // If a trunked port just went down and the trunk is still up, ignore the event
    if (up == FALSE && is_trunk_up(trunk_id_get(port_id)))
    {
        L2MCD_LOG_INFO("%s:%d up:%d port:%d ignoring event port:%d", FN,LN,up,port_id);
        return;
    }


    mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vir_port_id] : gMld.port_list[vir_port_id];

    if (mcgrp_vport == NULL)
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] vport not found", FN,LN,vir_port_id);
        return;
    }
    unsigned char  port_type;
    port_type = portdb_get_port_type(mld_portdb_tree, vir_port_id);

    if (up)
    {
        mcgrp_vport->is_up = TRUE;

        // We run the IGMP protocol on a per-port basis. So, if is is a
        // physical port, then we would like to send out queries on this port
        // in order to learn membership information on this port.
        // So start the query proces
        if (is_virtual_port(vir_port_id) || (port_type == INTF_MODE_L3))

        {
            mcgrp_start_vir_port(mcgrp, mcgrp_vport);
        }
        else
        {
            /* Since this is a physical port, we need to make the pport state as up */
            mcgrp_start_phy_port(mcgrp, mcgrp_vport, mcgrp_vport->phy_port_list);
        }
    }
    else    // the port just went down
    {
        mcgrp_vport->is_up = FALSE;

        // Cleanup MCGRP's data structures on all ports of this interface
        if (is_virtual_port(vir_port_id) || (port_type == INTF_MODE_L3) || mcgrp_vport->is_ve)
            mcgrp_stop_vir_port(mcgrp, mcgrp_vport);
        else
        {
            mcgrp_stop_phy_port(mcgrp, mcgrp_vport, mcgrp_vport->phy_port_list);
            if (WheelTimerSuccess ==
                    WheelTimer_IsElementEnqueued(&mcgrp_vport->vport_tmr.mcgrp_wte))
                WheelTimer_DelElement(mcgrp->mcgrp_wtid,
                        &mcgrp_vport->vport_tmr.mcgrp_wte);
            // Stop/Reset the querier process and any other timers
            mcgrp_vport->querier = TRUE;
            mcgrp_vport->v1_rtr_present = FALSE;
        }
    }
}


//v4 only
int igmpv3_src_compare (void *keya, 
        void *keyb)
{
    UINT32 src_addr_a = ((MADDR_ST*) keya)->ip.v4addr;
    UINT32 src_addr_b = ((MADDR_ST*) keyb)->ip.v4addr;

    return (int) (src_addr_a - src_addr_b);
}


//v4 only
void igmpv3_src_assign (void *keya, 
        void *keyb)
{
    /*
     * The address of linked list key is being passed as the first parameter and the src address
     * is being passed as the second parameter. Since memory is not allotted, in order to assign 
     * this src_address from keyb, we subtract 4 or 8(32/64bit) bytes of memory so that the to_src is 
     * aligned with the base address of the structure, so that the src is assigned to the correct 
     * structure field
     */

    MCGRP_SOURCE* to_src = (MCGRP_SOURCE*) ((unsigned long) keya - sizeof(unsigned long));   

    mcast_set_ipv4_addr(&to_src->src_addr, ((MADDR_ST*)keyb)->ip.v4addr);
    to_src->src_timer = 0;
    to_src->retx_cnt  = 0;
    to_src->include_in_query = FALSE;
    static int clnt_addr_offset=M_AVLL_OFFSETOF(MCGRP_CLIENT, clnt_addr.ip.v4addr);
    to_src->clnt_tree= L2MCD_AVL_CREATE(l2mcd_avl_compare_u32, (void *) &clnt_addr_offset, NULL);
}


//v4 only
MCGRP_CLASS *g_igmp_destroy;

void igmpv3_src_destroy (generic_pool_struct  *pool, 
        void                 *item)
{
    MCGRP_CLASS  *igmp = g_igmp_destroy;

    if (item== NULL)
        return;

    mcgrp_free_source(igmp, (MCGRP_SOURCE*) item);
}


//v4 only
SORTED_LINKLIST_KEYINFO igmpv3_src_keyinfo =
{
    4, /* Key size - size of IPv4 address */
    igmpv3_src_compare,
    igmpv3_src_assign,
    igmpv3_src_destroy, 
    NULL,
    NULL
};


// Find and delete (delink + free) an MCGRP_CLIENT from the list of sources
// anchored in a MCGRP_MBRSHP
//v4 only
void igmpv3_destroy_client (MCGRP_CLASS   *mcgrp,
        L2MCD_AVL_TREE   *clnt_tree, 
        UINT32         clnt_addr)
{
    MCGRP_CLIENT  *mcgrp_clnt = NULL;
    MADDR_ST       clnt_address;

    mcast_init_addr(&clnt_address, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
    mcast_set_ipv4_addr(&clnt_address, clnt_addr);

    mcgrp_clnt = M_AVLL_FIND(*clnt_tree, &clnt_address);
    if (mcgrp_clnt) 
    {
        M_AVLL_DELETE(*clnt_tree, mcgrp_clnt);
        mcgrp_free_client(mcgrp, mcgrp_clnt);
    }
}

int mcgrp_port_id_cmp_cb (void *keya,
        void *keyb)
{
    return (*(UINT32 *)keya - *(UINT32 *) keyb);
}


//v4 only
void igmpv3_sorted_linklist_minus (MCGRP_CLASS              *igmp,
        generic_pool_struct      *pool,
        SORTED_LINKLIST_KEYINFO  *key_info,
        SORTED_LINKLIST         **dest_p, 
        SORTED_LINKLIST          *src)
{
    g_igmp_destroy = igmp;
    sorted_linklist_minus(pool, key_info, dest_p, src);
}


//v4 only
void igmpv3_sorted_linklist_keep_common (MCGRP_CLASS              *igmp,
        generic_pool_struct      *pool,
        SORTED_LINKLIST_KEYINFO  *key_info,
        SORTED_LINKLIST         **dest_p, 
        SORTED_LINKLIST          *src)
{
    g_igmp_destroy = igmp;
    sorted_linklist_keep_common(pool, key_info, dest_p, src);
}


//v4 only
void igmpv3_sorted_linklist_free_list (MCGRP_CLASS              *igmp,
        generic_pool_struct      *pool,
        SORTED_LINKLIST_KEYINFO  *key_info,
        SORTED_LINKLIST          *src)
{
    g_igmp_destroy = igmp;
    sorted_linklist_free_list(pool, key_info, src);
}


//v4 only
int igmpv3_encode_src_list (IGMPV3_MESSAGE  *igmpv3_msg, 
        MCGRP_SOURCE    *p_src,
        BOOLEAN          all_srcs,
        BOOLEAN          is_retx)
{
    UINT32  *p_dst = igmpv3_msg->source_ary;
    int      num_srcs = 0;

    for (; p_src; p_src = p_src->next)
    {
        if (all_srcs || p_src->include_in_query)
        {
            // Include source if this a retransmit or if source is not already scheduled
            if (is_retx || p_src->retx_cnt == 0)
            {
                *p_dst++ = htonl(p_src->src_addr.ip.v4addr);
                num_srcs++;

                // send at most one packet size.
                if (num_srcs >= 365)
                    break;
            }
        }
    }

    // We may have broken out because we exceeded our MTU
    // If so, make sure we reset the include_in_query flag for the remaining sources
    for (; p_src; p_src = p_src->next)
    {
        p_src->include_in_query = FALSE;
        p_src->retx_cnt = 0;
    }

    return num_srcs;
}

void mcgrp_process_wte_event (void *wte_param)
{
    MCGRP_TIMER_ELEM  *wte_elem = (MCGRP_TIMER_ELEM *)wte_param;

    if (!wte_elem)
        return; //RD: Need to print the error

    L2MCD_LOG_DEBUG("%s(%d) Timer Type: %d afi:%d", FN, LN, wte_elem->timer_type,wte_elem->mcgrp->afi);

    switch (wte_elem->timer_type)
    {
        case MCGRP_WTE_STATIC:
            mcgrp_refresh_static_group(wte_elem->mcgrp, wte_elem->wte.static_grp);
            break;

        case MCGRP_WTE_QUERIER:
            mcgrp_age_query_timers(wte_elem->mcgrp, wte_elem->wte.vport.mcgrp_vport);
            break;

        case MCGRP_WTE_MBRSHP:
            mcgrp_age_group_mbrshp(wte_elem->mcgrp, wte_elem->wte.mbrshp.vport, 
                    wte_elem->wte.mbrshp.grp_entry, 
                    wte_elem->wte.mbrshp.mcgrp_mbrshp);
            break;

        case MCGRP_WTE_LMQI:
            mcgrp_age_group_mbrshp_and_lmq (wte_elem->mcgrp, wte_elem->wte.mbrshp.vport, 
                    wte_elem->wte.mbrshp.grp_entry, 
                    wte_elem->wte.mbrshp.mcgrp_mbrshp);
            break;

        case MCGRP_WTE_CLIENT:
            mcgrp_age_clnt_timers(wte_elem->mcgrp, wte_elem->wte.clnt.clnt_tree, 
                    wte_elem->wte.clnt.mcgrp_clnt);
            break;
        case MCGRP_WTE_MCT_LEAVE_SYNC_MAX_RESP_TMR:
            break;

        case MCGRP_WTE_L2_STATIC:
            mcgrp_refresh_l2_static_group(wte_elem->mcgrp, wte_elem->wte.l2_static_grp);
            break;

        case MCGRP_WTE_MROUTER:
            mcgrp_delete_router_port(wte_elem->mcgrp, wte_elem->wte.mrtr_port.mcgrp_vport, wte_elem->wte.mrtr_port.phy_port_id);
            break;

        case MCGRP_WTE_SRC_MBRSHP:
            mcgrp_pims_age_src_mbrshp(wte_elem->mcgrp, wte_elem->wte.mbrshp.vport,
                    wte_elem->wte.mbrshp.grp_entry,
                    wte_elem->wte.mbrshp.mcgrp_mbrshp,
                    wte_elem->wte.mbrshp.pims_src_entry);
            break;
    }
}

enum BOOLEAN
is_physical_or_lag_port(int port)
{
	return TRUE;
}


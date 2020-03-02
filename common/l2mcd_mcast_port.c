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

IP_PORT_INFO gPortInfo;
uint32_t mld_only_code;
VE_GLOBAL        ve_global;

extern MCGRP_GLOBAL_CLASS    gMld, *pgMld;
extern MCGRP_GLOBAL_CLASS    gIgmp, *pgIgmp;

#define MCGRP_INITIAL_GROUPS 256
#define MCGRP_INITIAL_FWD_ENTRY 256
/*-----------------------------------------------------------------------------------------**
**                                                                                         **
** This function allocate and initialize the memory required for the MCGRP ADDRESS         **
** TABLE. Memory is taken  from this pool to create a new entry, and returned to pool when **
** entry is deleted.                                                                       **
**-----------------------------------------------------------------------------------------*/
//v4/v6 compliant 
BOOLEAN mcgrp_global_pools_init (UINT32  afi)
{
    UINT32               initial_groups = MCGRP_INITIAL_GROUPS;
    int                  res;

    MCGRP_GLOBAL_CLASS  *mcgrp_glb = ((IP_IPV4_AFI == afi) ? &gIgmp : &gMld);

    // Alloc pool for the group entries
    mcgrp_glb->group_pool = (generic_pool_struct*)dy_malloc_zero(sizeof(generic_pool_struct));

    res = init_generic_pool(mcgrp_glb->group_pool, initial_groups,
                sizeof(MCGRP_ENTRY), GENERIC_POOL_MEMCHK_ON);
    if(!res)
        return FALSE;

    set_generic_pool_upper_limit(mcgrp_glb->group_pool, 0);


    // Alloc pool for the group membership entries
    mcgrp_glb->grp_mbrshp_pool =
        (generic_pool_struct*)dy_malloc_zero(sizeof(generic_pool_struct));

    res = init_generic_pool(mcgrp_glb->grp_mbrshp_pool, initial_groups,
                            sizeof(MCGRP_MBRSHP), GENERIC_POOL_MEMCHK_ON);
    if(!res)
        return FALSE;

    set_generic_pool_upper_limit(mcgrp_glb->grp_mbrshp_pool, 0);

    // Alloc pool for the source entries
    mcgrp_glb->src_specific_pool =
                   (generic_pool_struct*) dy_malloc_zero(sizeof(generic_pool_struct));

    res = init_generic_pool(mcgrp_glb->src_specific_pool, MCGRP_INITIAL_FWD_ENTRY,
                            sizeof(MCGRP_SOURCE), GENERIC_POOL_MEMCHK_ON);
    if(!res)
        return FALSE;

    set_generic_pool_upper_limit(mcgrp_glb->src_specific_pool, 0);

    // Alloc pool for the Client entries
    mcgrp_glb->src_specific_client_pool =
                   (generic_pool_struct*) dy_malloc_zero(sizeof(generic_pool_struct));

    res = init_generic_pool(mcgrp_glb->src_specific_client_pool, MCGRP_INITIAL_FWD_ENTRY,
                            sizeof(MCGRP_CLIENT), GENERIC_POOL_MEMCHK_ON);
    if(!res)
        return FALSE;

    set_generic_pool_upper_limit(mcgrp_glb->src_specific_client_pool, 0);

    if (IP_IPV4_AFI == afi)
    {
    }
    return TRUE;
}

//This function is called for every 100msecs
void mcgrp_service_wheel_timer_ms (UINT32 afi)
{
    MCGRP_CLASS *mcgrp;

    mcgrp = (afi == IP_IPV4_AFI) ? gIgmp.instances_list : gMld.instances_list;

    while (mcgrp)
    {
        if (mcgrp->enabled)
            WheelTimer_UpdateTic(mcgrp->mcgrp_wtid_lmq, 0, 1);

        mcgrp = mcgrp->inst_fwd;
    }
}

TRUNK_STATE trunk_port_state(PORT_ID port)
{
    return 0;
}

void mcgrp_service_wheel_timer (UINT32 afi)
{
    MCGRP_CLASS *mcgrp;

    mcgrp = (afi == IP_IPV4_AFI) ? gIgmp.instances_list : gMld.instances_list;

    while (mcgrp)
    {
        if (mcgrp->enabled)
            WheelTimer_UpdateTic(mcgrp->mcgrp_wtid, 0, 1);

        mcgrp = mcgrp->inst_fwd;
    }
}

int mcgrp_addr_cmp_cb_param (const void *keya, const void *keyb, void *param)
{
    MADDR_ST addr_a = *(MADDR_ST*) keya;
    MADDR_ST addr_b = *(MADDR_ST*) keyb;
    if (addr_a.ip.v4addr > addr_b.ip.v4addr) return 1;
    if (addr_a.ip.v4addr < addr_b.ip.v4addr) return -1;
    return 0;
}
void set_mask_bit(PORT_MASK *mask, int port)
{
	if (!mld_only_code)
        return;

	MLD_PORT_MASK *tmp_mask = (MLD_PORT_MASK *) mask;
	int tmp_port_num = mld_get_port_num(port);
	SET_BIT_BMP(tmp_mask, tmp_port_num);
}

void clear_mask_bit(PORT_MASK *mask, int port)
{
	if(!mld_only_code)
		return;

    MLD_PORT_MASK *tmp_mask = (MLD_PORT_MASK *) mask;
    int tmp_port_num = mld_get_port_num(port);
    RESET_BIT_BMP(tmp_mask, tmp_port_num);
}

//v4/v6 compliant
void mcgrp_free_source (MCGRP_CLASS   *mcgrp, MCGRP_SOURCE  *mcgrp_src)
{
    MCGRP_CLIENT        *mcgrp_clnt, *next_clnt;

    if (!mcgrp_src)
        return;

    mcgrp_clnt = M_AVLL_FIRST(mcgrp_src->clnt_tree);
    while (mcgrp_clnt)
    {
        next_clnt = M_AVLL_NEXT(mcgrp_src->clnt_tree, mcgrp_clnt->node);
        M_AVLL_DELETE(mcgrp_src->clnt_tree, mcgrp_clnt);
        mcgrp_free_client(mcgrp, mcgrp_clnt);
        mcgrp_clnt = next_clnt;
    }

    generic_free_mem_to_pool((IS_IGMP_CLASS(mcgrp) ? gIgmp.src_specific_pool :
                                                     gMld.src_specific_pool),
                              mcgrp_src);
}

void mcgrp_free_client (MCGRP_CLASS   *mcgrp, MCGRP_CLIENT  *mcgrp_clnt)
{
    MCGRP_GLOBAL_CLASS  *mcgrp_glb = (IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld);

    if (mcgrp_clnt)
    {
        if (WheelTimerSuccess ==
                          WheelTimer_IsElementEnqueued(&mcgrp_clnt->clnt_tmr.mcgrp_wte))
        {
            WheelTimer_DelElement(mcgrp->mcgrp_wtid,
                                  &mcgrp_clnt->clnt_tmr.mcgrp_wte);
        }
        generic_free_mem_to_pool(mcgrp_glb->src_specific_client_pool, mcgrp_clnt);
    }
}

TRUNK_ID trunk_id_get(PORT_ID port )
{
    return 0;
}

UINT32 mcgrp_get_remaining_time(WheelTimerId timer_id, WheelTimerElement *timer_elem)
{
     WheelTimerTics time = 0;
     if(WheelTimer_GetTimeToExpire(timer_id, timer_elem, (WheelTimerTics *)&time) != WheelTimerSuccess)
     {
        //log error
     }
	return time;
}

static USHORT end_around_carry (ULONG sum)              /* Carries in high order 16 bits */
{
    USHORT csum;
    USHORT return_value;

    csum = (USHORT) (sum >> 16);

    while (csum != 0x0000)
    {
        sum = csum + (sum & 0xffffL);

        csum = (USHORT) (sum >> 16);
    }
    
    /* Chops to 16 bits */
    
    return_value = (USHORT) (sum & 0x0000ffffL);
        
    return (return_value);
}       

static USHORT calculate_word_checksum (USHORT *usptr_short, USHORT length)
{
    ULONG sum;
    USHORT result;

    sum = 0x00000000L;

    while (length != 0x0000)
    {   
        --length;
        
        sum += *usptr_short;
    
        ++usptr_short;
    }
    
    result = end_around_carry (sum);

    return (result);
}   

/****************************************************************************/
/* the data order is assumed to be network order. */

USHORT calculate_ip_checksum (PSEUDO_IP_PARAMETERS *sptr_pseudo_header, BYTE *bptr_start_from, USHORT length)
{
    USHORT word_checksum;
    ULONG sum;
    ULONG checksum;
    USHORT return_value; 

    sum = 0x00000000L;

    if (sptr_pseudo_header != NULL)
    {
        word_checksum = calculate_word_checksum ((USHORT *) sptr_pseudo_header, (USHORT) (sizeof (PSEUDO_IP_PARAMETERS)) >> 1);
    
        sum = word_checksum;
    }
    
    checksum = 0x00000000L;
    
    if (length > 1)
    {
        /* ptr_start_from must be on short word boundary */

        word_checksum = calculate_word_checksum ((USHORT *) bptr_start_from, (USHORT) (length >> 1));

        checksum += word_checksum;
    }
     
    /* Handle odd trailing byte */
        
    if (length & 1)
    {
#ifndef BIG_ENDIAN
        checksum += (unsigned char) (bptr_start_from[--length]);
#else
        checksum += (USHORT) (((unsigned char) (bptr_start_from[--length])) << 8);
#endif
    }

    sum += checksum;

    /* Do final end-around carry, complement and return */

    return_value = (USHORT) (~end_around_carry (sum) & 0xffff);

    return (return_value);
}

BOOLEAN is_trunk_up( TRUNK_ID trunk_id )
{
    return  FALSE;
}


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
#include "l2mcd_portdb.h"
#include "mld_vlan_db.h"

#define ALL_PIM_ROUTERS_SSM_PRECEDENCE 2 

extern L2MCD_AVL_TREE *mld_portdb_tree;

int linklist_delete_pointer(LINKLIST_TYPE **head, LINKLIST_TYPE *item)
{
    LINKLIST_TYPE *prev, *p;

    if(*head == NULL)
        return 0;
    p = *head;
    if(p == item) // It is the first one, must change head
    {
        *head = p->next;
        return 1;
    }
    prev = p;
    p = p->next;
    while(p)
    {
        if(p == item)
        {   // match
            prev->next = p->next;
            return 1;
        }
        prev = p;
        p = p->next;
    }
    return 0; // not found
}

int32_t mld_get_port_num(uint16_t port)
{
    uint32_t phy_ports = ip_get_number_of_phy_ports();
	uint32_t ifindex = mld_get_port_ifindex(port);
	int local_tunnel_id = 0; 

    if (port < phy_ports)
        return port;
    else if(l2mcd_ifindex_is_trunk(ifindex))
    {
		return (l3_get_port_from_ifindex(ifindex));
    }
	else if(l2mcd_ifindex_is_tunnel(ifindex))
	{
		if (-1 == local_tunnel_id)
		{
			L2MCD_LOG_INFO("%s:%d, error occurred in allocating tunnel-id", __FUNCTION__,__LINE__);
			return -1;
		}
	}
	return -1;
}

uint16_t mld_l3_get_port_from_ifindex(uint32_t ifindex, uint8_t type)
{
 
	if(type == MLD_BD) {
  		return( l3_get_port_from_bd_id(ifindex));
	} else {
		return(l3_get_port_from_ifindex(ifindex));   
	}
}

uint32_t mld_get_port_ifindex(uint16_t port_id)
{
    return(portdb_get_port_ifindex(mld_portdb_tree, port_id));
}

uint32_t mld_get_vlan_id(uint16_t vir_port_id)
{
	uint32_t ifindex = 0;
	ifindex = portdb_get_port_ifindex(mld_portdb_tree, vir_port_id);
	//L2MCD_LOG_INFO ("%s(%d) : virport id= %d ifindex  0x%x ", 
	//		__FUNCTION__, __LINE__, vir_port_id, ifindex);

	if(l2mcd_ifindex_is_physical(ifindex))
    {
		return ifindex;
	}
	else if((l2mcd_ifindex_is_trunk(ifindex)))
    {
		L2MCD_LOG_INFO("%s(%d) ifindex:0x%x is trunk ", FN, LN, ifindex);	
		return(mld_portdb_get_ivid_from_gvid(ifindex, MLD_ROUTE_PORT));
	}
	else if(l2mcd_ifindex_is_svi(ifindex)){
		//L2MCD_LOG_INFO("%s(%d) vlan_id:%d ", __FUNCTION__, __LINE__, l2mcd_ifindex_get_svi_vid(ifindex));
		return(l2mcd_ifindex_get_svi_vid(ifindex));
	} else {
		return ifindex;
    }
}

uint32_t mld_get_ivid_vport(uint16_t vir_port_id, uint8_t afi) 
{
	MCGRP_L3IF			*mcgrp_vport	= NULL;
    uint32_t vid;

	if (afi == MCAST_IPV4_AFI)
		mcgrp_vport = gIgmp.port_list[vir_port_id];
	else
		mcgrp_vport = gMld.port_list[vir_port_id];
    if(mcgrp_vport == NULL)
    	return 0;
    vid  = mld_get_vlan_id(vir_port_id); 
	return(mld_portdb_get_ivid_from_gvid(vid,mcgrp_vport->type));
}

uint8_t  mld_get_vlan_type(uint16_t ivid)
{
   	if(ivid > 0 && ivid< 4096 ) {   
   		return(MLD_VLAN);
  	}
	return(MLD_ROUTE_PORT);
}

char * mld_get_if_name_from_ifindex(uint32_t ifindex)
{
    return (portdb_get_ifname_from_portindex(ifindex));
}

int l3_get_max_ports(void)
{
    return MAX_L3_PORTS;
}

void mld_get_ifname(char *if_name, int if_type, char *comp_if_name)
{
     memcpy(comp_if_name, if_name,INTERFACE_NAMSIZ);
    return;
}

uint32_t mld_get_lif_ifindex_from_ifname(char *ifname, uint32_t gvid, uint8_t vlan_type) 
{


    int port=0;
    port = portdb_get_portindex_from_ifname(ifname); 
    L2MCD_VLAN_LOG_INFO(gvid,"%s:%d:[vlan:%d], get port for ifname:%s port%d", FN,LN, gvid, ifname, port);
    return port;
}

int mld_get_port_bitmap_size()
{
    return 0;
}

PORT_ID mcast_tnnl_get_output_port (PORT_ID tnnl_ifid)
{
    return 0;
}

int ip_get_number_of_phy_ports(void)
{
    return 0;
}

uint32_t  mld_mcast_tnnl_get_output_ifindex(uint16_t vir_port_id)
{
    return(pim_get_ifindex_from_port(mld_mcast_tnnl_get_output_port(vir_port_id)));
}

uint32_t  mld_mcast_tnnl_get_output_port(uint32_t ifindex) 
{
 uint16_t port_id;

 port_id = l3_get_port_from_ifindex(ifindex);
 return (mcast_tnnl_get_output_port(port_id));
}

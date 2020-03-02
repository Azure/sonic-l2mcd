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
#include "mld_vlan_db.h"
#include "l2mcd.h"
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <errno.h>


extern int l3_get_port_from_ifindex(int ifindex);
extern L2MCD_AVL_TREE *ve_mld_portdb_tree;
extern uint32_t hsl_sock_fd[MCAST_AFI_MAX];
#define HSL_ETHER_TYPE_IP                  0x0800
#define HSL_ETHER_TYPE_IPV6                0x86DD
#define AF_IGMP_SNOOP 51
#define AF_MLD_SNOOP 59

extern MCGRP_ROUTER_ENTRY* mcgrp_find_rtr_port_entry (MCGRP_CLASS  *mcgrp,
                                             MCGRP_L3IF   *mcgrp_vport,
                                             UINT32        phy_port_id);

extern L2MCD_AVL_TREE *mld_portdb_tree;

int mld_ok_to_send_over_edge_port(ifindex_t source, ifindex_t destination)
{
	if(source == destination)
		return FALSE;
    else 
		return TRUE;
}

/* 	This function will prepare a IGMP report and send it over mrouter port. This is needed because
	we want to send the static IGMP report over mrouter ports.
	Parameters:
		grp_addr 	: Static group Ip address
		mld 		: instance class
		mld_vport	: Vlan Instance in IGMP
		rx_phy_port	: Port-Id of the port where static group is configured
		joinflag	: Boolean flag, TRUE: Join, FALSE: Leave
	Note: Currently, this function supports only IPV4.
*/
void mld_tx_static_report_leave_on_mrtr_port(MCGRP_CLASS  *mld, MADDR_ST *grp_addr, MCGRP_L3IF *mld_vport, 
											 uint32_t rx_phy_port, uint8_t joinflag)
{
	uint8_t 			afi 						= MCAST_IPV4_AFI;
	ifindex_t 			source;
	port_link_list_t 	*sptr_addr_entry 			= NULL;
	uint32_t 			gvid 						= 0;
	uint32_t			src_addr 					= 0;
	int 				port_id 					= 0;
	mld_vlan_node_t 	*vlan_node 					= NULL;

	if (mld_vport == NULL) {
		L2MCD_LOG_INFO("%s(%d) mld_vport is NULL. ", FN, LN);	
		return;
	}

	/*
	 * Note : Here tx_port_number is based out of vlan_id ifindex.
	 * If vlan has a Ve associated then, retrieve the Ve_port_id and
	 * see whether there is any IP address associated with this ve_port_id
	 * in mld_portdb_tree/ve_mld_portdb_tree.
	 * This is needed when Vlan and VE ID are different.
	 * When Vlan and VE are same id then, tx_port_number will be same.
	 */
	gvid = mld_get_vlan_id(mld_vport->vir_port_id);
	vlan_node = mld_vdb_vlan_get(gvid, mld_vport->type);
	if (vlan_node && vlan_node->ve_ifindex) 
	{
		if(l2mcd_ifindex_is_svi(vlan_node->ve_ifindex)) 
		{
			port_id = l3_get_port_from_ifindex(vlan_node->ve_ifindex);
			sptr_addr_entry = (port_link_list_t *)(portdb_get_port_lowest_ipv4_addr_from_list(ve_mld_portdb_tree, port_id));
			MLD_LOG(MLD_LOGLEVEL7,MLD_IP_IPV4_AFI, "%s(%d) rx_phy_port:0x%x ifindex:0x%x ve_ifindex:0x%x ", 
					FN, LN, rx_phy_port, vlan_node->ifindex, vlan_node->ve_ifindex);
		}
		else {
			//Router Port IP address
			port_id = mld_vport->vir_port_id;
			sptr_addr_entry = (port_link_list_t *)(portdb_get_port_lowest_ipv4_addr_from_list(mld_portdb_tree, port_id));
			MLD_LOG(MLD_LOGLEVEL7,MLD_IP_IPV4_AFI, "%s(%d) rx_phy_port:0x%x Router ifindex:0x%x ", 
					FN, LN, rx_phy_port, vlan_node->ifindex);
		}
	}

	// TODO: Note that sptr_addr_entry is a list. Not sure what is "list of lowest ip addresses".
	if (sptr_addr_entry) 
	{
		src_addr = sptr_addr_entry->value.ipaddress;
	}
	source = rx_phy_port;
	if(is_mld_snooping_enabled(mld_vport, afi)) 
	{
		/* This function should take care of sending to all mrouter ports
		 */
		igmp_send_igmp_message(mld, mld_vport->vir_port_id,
					source, //mcgrp_rport->phy_port_id,
					joinflag ? IGMP_V2_MEMBERSHIP_REPORT_TYPE : IGMP_V2_LEAVE_GROUP_TYPE,
					(UINT8) mld_vport->oper_version,
					grp_addr->ip.v4addr,   // Group Address
					src_addr, // Source Address of the packet 
					0, // 0 means use default response time
					NULL, FALSE,       // no srcs
					FALSE); // not retx
	}
}

void mld_tx_reports_leave_rcvd_on_edge_port(void *req, MADDR_ST *grp_addr, MCGRP_CLASS  *mld, MCGRP_L3IF *mld_vport)
{
	MCGRP_ROUTER_ENTRY* mcgrp_rport = NULL;
	MADDR_ST dest_addr;
	union mld_in6_cmsg  *pkt_cmsg;
	uint8_t afi;
	MCGRP_GLOBAL_CLASS *mcgrp_glb = (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
	ifindex_t source,destination;
	uint32_t rx_phy_port;
	MCGRP_PORT_ENTRY* mcgrp_pport;


	if (mld_vport == NULL) 
	{
		L2MCD_LOG_INFO("%s(%d) mld_vport is NULL. ", FN, LN);	
		return;
    }

	if(!IS_IGMP_CLASS(mld)) {
	    afi = MCAST_IPV6_AFI;
        pkt_cmsg = (union mld_in6_cmsg *)((IP6_RX_PKT_MSG *)req)->header.msg_instance_id;
	    mcast_set_ipv6_addr(&dest_addr, &grp_addr->ip.v6addr);
		rx_phy_port = ((IP6_RX_PKT_MSG *)req)->ip_param.rx_physical_port_number;
		
	}
    else {
	    afi = MCAST_IPV4_AFI;
        pkt_cmsg = (union mld_in6_cmsg *)((IP_RX_PKT_MSG *)req)->header.msg_instance_id;
	    mcast_set_ipv4_addr(&dest_addr, grp_addr->ip.v4addr);
		//For Non-bcast case use source as rx_phy_port_numder, 
		//vaddr.port contains ifindex for bcast case
		rx_phy_port = ((IP_RX_PKT_MSG *)req)->ip_param.rx_phy_port_number;
	}
	source = rx_phy_port;

	if (is_mld_snooping_enabled(mld_vport, afi)) {
		mcgrp_rport = mld_vport->rtr_port_list;
		
		while (mcgrp_rport) {
			L2MCD_VLAN_LOG_DEBUG(mld_vport->vir_port_id, "%s:%d:[vlan:%d] vaddr.port:%0x  port_ifindex:0x%x", 
				__FUNCTION__, __LINE__, mld_vport->vir_port_id, pkt_cmsg->vaddr.port, mcgrp_rport->phy_port_id);
			
			/* This is for stopping looping the joins, received on vlag , sending them to again on the
 			** the same vlag */ 
			//destination = mld_get_port_ifindex(mcgrp_rport->phy_port_id);
			destination = mcgrp_rport->phy_port_id;
			L2MCD_LOG_INFO("%s(%d) src_port:0x%x (%s) dst_port:0x%x", FN, LN, 
				source, mld_get_if_name_from_ifindex(rx_phy_port), destination);
			if (mld_ok_to_send_over_edge_port(source, destination)) {
				L2MCD_VLAN_LOG_DEBUG(mld_vport->vir_port_id,"%s:%d:[vlan:%d] %s:mcgrp_rport %s vlan_id %s %s",
							FN, LN, mld_vport->vir_port_id, afi == MLD_IP_IPV4_AFI ? "IGMP":"MLD", 
							mld_get_if_name_from_ifindex(mcgrp_rport->phy_port_id), 
							mld_get_if_name_from_port(mld_vport->vir_port_id), mcast_print_addr(grp_addr));
				l2mcd_send_pkt(req, mcgrp_rport->phy_port_id, mld_vport->vir_port_id, &dest_addr, mld, mcgrp_glb, TRUE, FALSE);

			}
			mcgrp_rport = mcgrp_rport->next;
		}
		/* Now scan through the edge ports and whichever matches tunnel, forward it.
		   We will exclude mrouter ports since we already forwarded over mrouter ports. */	
		mcgrp_pport = mld_vport->phy_port_list;
		while (mcgrp_pport)
		{ 	
			destination = mcgrp_pport->phy_port_id;
			if(l2mcd_ifindex_is_tunnel(destination)
				  && mld_ok_to_send_over_edge_port(source, destination)
				  && !mcgrp_find_rtr_port_entry(mld, mld_vport, mcgrp_pport->phy_port_id))	
			{
				L2MCD_VLAN_LOG_DEBUG(mld_vport->vir_port_id, "%s:%d:[vlan:%d] mcgrp_pport %s vlan_id %s %s",
					  __FUNCTION__, LN,mld_vport->vir_port_id, mld_get_if_name_from_ifindex(mcgrp_pport->phy_port_id), 
					  mld_get_if_name_from_port(mld_vport->vir_port_id), mcast_print_addr(grp_addr));
				l2mcd_send_pkt(req, mcgrp_pport->phy_port_id, mld_vport->vir_port_id, &dest_addr, mld, mcgrp_glb,TRUE, FALSE);
			}
			mcgrp_pport = mcgrp_pport->next;
		}
	}
}



int l2mcd_send_pkt(void *itc_msg, ifindex_t phy_port_id, uint16_t ivid, 
					MADDR_ST *grp_addr, 
					MCGRP_CLASS *mld, 
					MCGRP_GLOBAL_CLASS  *mcgrp_glb, 
					bool_t is_forwarded, bool_t is_bcast)
{
    int					ret = 0;
    struct ethhdr *eth_hdr;
    char				*ip_pkt = NULL;	
    int                 eth_hdr_size=0;
    union				mld_in6_cmsg *pkt_cmsg;
    uint8_t vlan_type=0;
    char *pkt=NULL, *send_pkt=NULL;
    IGMP_PACKET  *igmp_pkt = NULL; 
    int pkt_len=0;
    char  ifname[L2MCD_IFNAME_SIZE];
    struct sockaddr_ll sa;
    l2mcd_if_tree_t *l2mcd_if_tree;

	int	send_pkt_size = 0;
    int	ip_pkt_total_len = 0;

    eth_hdr_size = 14;

    if (!IS_IGMP_CLASS(mld)) 
    {
       ip_pkt = ((IP6_RX_PKT_MSG *)itc_msg)->pkt_data;
       ip_pkt_total_len = 	((IP6_RX_PKT_MSG *)itc_msg)->pkt_size;
	   pkt_cmsg = (union mld_in6_cmsg *)((IP6_RX_PKT_MSG *)itc_msg)->header.msg_instance_id;
    } else {
        ip_pkt = ((IP_RX_PKT_MSG *)itc_msg)->ip_param.data;
        ip_pkt_total_len = ((IP_RX_PKT_MSG *)itc_msg)->ip_param.total_length;
		pkt_cmsg = (union mld_in6_cmsg *)((IP_RX_PKT_MSG *)itc_msg)->header.msg_instance_id;
    }

	send_pkt = calloc(1, eth_hdr_size  + ip_pkt_total_len);
    memset(send_pkt, 0, send_pkt_size);
	memcpy(((char *)send_pkt +  eth_hdr_size) , (char *)ip_pkt , ip_pkt_total_len);

    //Fill Ethernet Header	
    eth_hdr = (struct ethhdr *)send_pkt;
    if (is_forwarded)
    {
        //Use original pkt mac
        memcpy(eth_hdr->h_source, pkt_cmsg->vaddr.src_mac, ETHER_ADDR_LEN);	
    } else {
        //Orinate packet mac use own mac
        memcpy(eth_hdr->h_source, mcgrp_glb->mac, ETHER_ADDR_LEN);
    }
    //Fill Destination MAC
    if(grp_addr->afi == IP_IPV6_AFI) 
    {
        MLD_CONVERT_IPV6MCADDR_TO_MAC ((char *)&grp_addr->ip.v6addr, eth_hdr->h_dest);
        //Fill v6 Ether type.
        eth_hdr->h_proto = htons(HSL_ETHER_TYPE_IPV6); 
    } else {
        uint32_t ipv4 = (grp_addr->ip.v4addr);
        MLD_CONVERT_IPV4MCADDR_TO_MAC ((char *)&(ipv4), eth_hdr->h_dest);
        eth_hdr->h_proto = htons(HSL_ETHER_TYPE_IP); 
    }

    if (is_bcast)
    {
        snprintf(ifname, L2MCD_IFNAME_SIZE,"Vlan%d",ivid);
        sa.sll_ifindex = if_nametoindex(ifname);
    } else  {
        vlan_type = mld_get_vlan_type(ivid);
        if (vlan_type == MLD_VLAN) 
		{
            l2mcd_if_tree = M_AVLL_FIND(g_l2mcd_if_to_kif_tree, &phy_port_id);
            if (l2mcd_if_tree)
            {
                memcpy(ifname, l2mcd_if_tree->iname, L2MCD_IFNAME_SIZE);
                sa.sll_ifindex = l2mcd_if_tree->kif;
            }
        }
		else 
		{
			L2MCD_LOG_INFO("Invalid type %s:%d is_bcast:%d vlan_type:%d phy:%d", __FUNCTION__, __LINE__, is_bcast, vlan_type, phy_port_id);
			L2MCD_VLAN_LOG_ERR(ivid, "Invalid type %s:%d is_bcast:%d vlan_type:%d phy:%d", __FUNCTION__, __LINE__, is_bcast, vlan_type, phy_port_id);
            
        }
    }

    pkt = (char *)eth_hdr;
    igmp_pkt=(IGMP_PACKET*)((char *) pkt + eth_hdr_size);
    pkt_len= eth_hdr_size + ip_pkt_total_len;
    char dmac[20];
    char smac[20];

    snprintf(smac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x",
            eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2], eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
    snprintf(dmac, sizeof(dmac), "%02x:%02x:%02x:%02x:%02x:%02x",
            eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2], eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);

    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, eth_hdr->h_dest, ETHER_ADDR_LEN);
    L2MCD_PKT_PRINT(ivid,
            "IGMP_TX Packet %s  ETH DA:%s,SA:%s,etype:0x%x  IP: v:0x%x ihl:0x%x len:0x%x tttl:0x%x prot:0x%x csum:0x%x sip:0x%x dip:0x%x option:0x%x option:length:%d, IGMP:type:0x%x mrt:0x%x csum:0x%x ga:0x%x outif:0x%x is_bcast:%d vlan_type:%d",
            ifname, dmac,smac,eth_hdr->h_proto,
            igmp_pkt->ip_header.version_header_length.version, igmp_pkt->ip_header.version_header_length.header_length,igmp_pkt->ip_header.total_length,
            igmp_pkt->ip_header.time_to_live,igmp_pkt->ip_header.protocol,igmp_pkt->ip_header.header_checksum,igmp_pkt->ip_header.source_ip_address, 
            igmp_pkt->ip_header.destination_ip_address,igmp_pkt->ip_options.code.option_number,igmp_pkt->ip_options.length,
            igmp_pkt->igmp_message.type, igmp_pkt->igmp_message.maximum_response_time, igmp_pkt->igmp_message.checksum, 
            igmp_pkt->igmp_message.group_address,sa.sll_ifindex, is_bcast, vlan_type);
    if (sendto(g_l2mcd_igmp_tx_handle, pkt, pkt_len, 0, (struct sockaddr*)&sa,sizeof(sa)) == -1)
    {
        L2MCD_PKT_PRINT(ivid, "IGMP_TX Err is_bcast:%d vlan_type:%d  port:%d ret:%s\n", is_bcast, vlan_type,  phy_port_id, strerror(errno));
        L2MCD_LOG_NOTICE("sock send  handle ivid:%d  %d pklen:%d port:%d ret: %s",g_l2mcd_igmp_tx_handle,pkt_len, phy_port_id, ivid, strerror(errno));
		ret=-1;
    }

	free(send_pkt);
    return (ret);
}



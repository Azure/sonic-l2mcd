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
#ifndef __L2MCD_PORTDB__
#define __L2MCD_PORTDB__

#include "l2mcd_data_struct.h"
#include "hash_grow_generic.h"
#include "l2mcd_mld_port.h"
#include "l2mcd.h"
#include "l2mcd_mcast_co.h"

#define MAC_ADDR_LEN 6
#define PORTDB_DEFAULT_PORT_MTU     1500
#define PORTDB_DEFAULT_PORT_TYPE    1



typedef struct PORTDB_IP6_ADDRESS_ENTRY_S {
    struct PORTDB_IP6_ADDRESS_ENTRY_S   *sptr_forward_link;
    IP6_IPV6_ADDRESS                    address; 
    IP6_IPV6_ADDRESS                    prefix; 
    UINT8                               prefix_length;
    UINT8                               flags;
} PORTDB_IP6_ADDRESS_ENTRY;

typedef struct PORTDB_IP6_S {
    /* ip6_enabled is enabled if address is configured or  ip6_protocol_enabled is set. */
    UINT16             ip6_protocol_enabled:1; /* enable ipv6 interface, even if address is not configured */
    UINT16             spare:15; 
    UINT8              number_of_ip6_addresses;
    PORTDB_IP6_ADDRESS_ENTRY *sptr_ip6_link_local_address; //Link Local Address
    PORTDB_IP6_ADDRESS_ENTRY *sptr_ip6_address_list; //Global Address
} PORTDB_IP6;



typedef struct portdb_entry_s {
    L2MCD_AVL_NODE         node;
    unsigned int        port_index;
    unsigned long       ifindex;
    VRF_INDEX           vrf_id;
    unsigned int        mtu;
    unsigned int        ipv6_mtu;
    unsigned long       ivid;
    unsigned long       gvid;        
    float               bandwidth;
    float               bw_configured; /* Configured bw value; (when not configured) overloaded with full trunk bw irrespective of active portlist */
	UINT8               hwAddr[6];
    UINT16              port_state:1;
    UINT16              ip6_enabled:1; /* Current Enabled/Disabled state for processing IP6 packet */
    UINT16              ip4_enabled:1; /* Current Enabled/Disabled state for processing IP4 packet */
    UINT16              type:3;        /* interface type : NSM_INTF_MODE_UNK/NSM_INTF_MODE_L2/NSM_INTF_MODE_L3 */
                                       /* this follows nsm_intf_type_new_s
                                        * ENUM which will take upto a value of
                                        * '4'; hence 3 bits are needed.*/
    UINT16              netdev_state:1; /* Indicates the interface got netdevice is created or not */
    UINT16              admin_state:1;
    UINT16              unnumbered:1;  /* Indicates if the interface is unnumbered interface*/
    UINT16              neighbor_up:1; /* Indicates if neighbor is discovered on the unnumbered interface */
    UINT16              spare:6; 

    PORTDB_IP6          *ip6;
    struct list			*ip4;
	// Fusion ISIS: Store MAC for easier SYNC to standby
	u_char              mac_addr[MAC_ADDR_LEN];
    void                *opaque_data; 
} portdb_entry_t;

typedef struct PORTDB_IP4_S {
    L2MCD_AVL_NODE     node;
    UINT32          ipaddress;
    VRF_INDEX       vrf_index;
    UINT8           prefix_length;
    UINT32          flags;
    UINT32          port_index;
    UINT8           mac[6];
} PORTDB_IP4;

typedef struct port_link_list_s
{
    struct  port_link_list_s *next;
    PORTDB_IP4 value;
}port_link_list_t;


typedef struct PORTDB_VRF_S {
    char            *vrf_name;
    unsigned char   afi;
} portdb_vrf_t;


char *portdb_get_ifname_from_portindex(unsigned long port_index);
unsigned int portdb_get_portindex_from_ifname(char *ifname);
int portdb_add_ifname(char *ifname, int name_len, unsigned int port_index);
void portdb_init();
int portdb_ifname_hash_init(void);
unsigned int portdb_get_port_vrf_index(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index);
int portdb_portindex_key_compare(unsigned long key1, unsigned long key2);
UINT32 portdb_portindex_hash_function(unsigned long key);
int portdb_gvid_hash_init(void);
int portdb_vrf_hash_init(void);
portdb_entry_t *portdb_find_port_entry(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index);
unsigned char portdb_get_port_type(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index);
int portdb_set_port_state(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index, unsigned char port_state);
port_link_list_t *
portdb_get_port_lowest_ipv4_addr_from_list(L2MCD_AVL_TREE *portdb_tree, UINT32 port_index);
unsigned char portdb_get_port_state(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index);
int portdb_delete_ifname(char *ifname);
int portdb_remove_port_entry_from_tree(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index);
int portdb_add_port_entry_to_tree(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index, 
            VRF_INDEX vrf_id, unsigned long ifindex);
int portdb_remove_addr_ipv4_list(L2MCD_AVL_TREE *portdb_tree, UINT32 port_index,
                            UINT32 ipaddress);
unsigned long portdb_get_port_ifindex(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index);
#endif //__L2MCD_PORTDB__

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


#define PORTDB_IFNAME_HASH_INIT_SIZE  L2MCD_PORTDB_HASH_SIZE

char *portdb_get_ifname_from_portindex(unsigned long port_index)
{
    return NULL; //Could not find port_index in portdb;
}

unsigned int portdb_get_portindex_from_ifname(char *ifname)
{
}

int portdb_add_ifname(char *ifname, int name_len, unsigned int port_index)
{
    return 0;    
}

void portdb_init()
{
    portdb_ifname_hash_init();    
    portdb_gvid_hash_init();
    portdb_vrf_hash_init();
}

int portdb_ifname_hash_init(void)
{
    return 0;        
}

unsigned int portdb_get_port_vrf_index(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{

}

int portdb_portindex_key_compare(unsigned long key1, unsigned long key2)
{

}

UINT32 portdb_portindex_hash_function(unsigned long key)
{
 }


#define PORTDB_GVID_HASH_INIT_SIZE 100

int portdb_gvid_key_compare(unsigned long key1, unsigned long key2)
{

}

UINT32 portdb_gvid_hash_function(unsigned long key)
{
    return ( (UINT32) key); //gvid is unique for each port
}


int portdb_gvid_hash_init(void)
{
    return 0;        
}   

#define PORTDB_VRFNAME_HASH_INIT_SIZE 100

int portdb_vrfid_key_compare(unsigned long key1, unsigned long key2)
{

}

UINT32 portdb_vrfid_hash_function(unsigned long key)
{
    return key; //vrfid is unique for each vrf name
}

int portdb_add_vrfname(char *vrfname, int name_len, VRF_INDEX vrfid, unsigned char afi)
{
 
}


int portdb_vrf_hash_init(void)
{
     
}

portdb_entry_t *portdb_find_port_entry(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{

}

unsigned long portdb_get_port_ifindex(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{

}

unsigned char portdb_is_port_index_valid(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{

}

unsigned char portdb_get_port_type(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{

}

int portdb_set_port_state(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index, unsigned char port_state)
{
    return 0;
}

port_link_list_t *
portdb_get_port_lowest_ipv4_addr_from_list(L2MCD_AVL_TREE *portdb_tree, UINT32 port_index)
{

}

unsigned char portdb_get_port_state(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{

}

int portdb_delete_ifname(char *ifname)
{
    return 0;
}

int portdb_remove_port_entry_from_tree(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{
    return 0;
}

int portdb_add_port_entry_to_tree(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index, 
            VRF_INDEX vrf_id, unsigned long ifindex)
{
    return 0;
}

void
portdb_insert_addr_ipv4_list(L2MCD_AVL_TREE *portdb_tree, UINT32 port_index,
                            UINT32 ipaddress, UINT8 prefix_length, VRF_INDEX vrf_index, UINT32 flags)
{
}

int 
portdb_remove_addr_ipv4_list(L2MCD_AVL_TREE *portdb_tree, UINT32 port_index, UINT32 ipaddress)
{
}


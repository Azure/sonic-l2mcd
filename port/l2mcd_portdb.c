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

/*Interface name to port index mapping*/
//Hash table to search interface name
static hashGrowGeneric *portdb_ifname_to_portindex_hash = NULL;
static hashGrowGeneric *portdb_portindex_to_ifname_hash = NULL;
#define PORTDB_IFNAME_HASH_INIT_SIZE  L2MCD_PORTDB_HASH_SIZE

char *portdb_get_ifname_from_portindex(unsigned long port_index)
{
    int ret;
    unsigned long ifname_ptr;

    ret = hashGrowGenericGet(portdb_portindex_to_ifname_hash, port_index, (unsigned long *)&ifname_ptr);

    if(ret) {
        return (char *)ifname_ptr;
    }

    return NULL; //Could not find port_index in portdb;
}

unsigned int portdb_get_portindex_from_ifname(char *ifname)
{
    int ret;
    unsigned long port_index;
    ret = hashGrowGenericGet(portdb_ifname_to_portindex_hash, (unsigned long)ifname, (unsigned long *)&port_index);

    if(ret) {
        return port_index;
    }

    return NO_SUCH_PORT; //invalid port_index;
}

int portdb_add_ifname(char *ifname, int name_len, unsigned int port_index)
{
    int ret;
    char *interface_name; 
    if( !(interface_name = (char *)malloc(name_len + 1)) )
        return -1;

    strcpy(interface_name, ifname);

    ret = hashGrowGenericInsert(portdb_portindex_to_ifname_hash, port_index, (unsigned long)interface_name);
    if(!ret)
    {
        L2MCD_LOG_NOTICE("%s index:%d to portname:%s ret:%d", __FUNCTION__, port_index, interface_name, ret);
        return -1; //Failed to add interface name to hash table;
    }

    ret = hashGrowGenericInsert(portdb_ifname_to_portindex_hash, (unsigned long)interface_name, port_index);
    if(!ret)
    {
        L2MCD_LOG_NOTICE("%s index:%d from portname:%s ret:%d", __FUNCTION__, port_index, interface_name,ret);
        return -1; //Failed to add interface name to hash table;
    }

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
    portdb_ifname_to_portindex_hash = hashGrowGenericCreate(PORTDB_IFNAME_HASH_INIT_SIZE,
            HASH_GROW_DO_NOT_SHRINK, string_key_compare,
            string_key_hash_function, NULL);
    if (!portdb_ifname_to_portindex_hash)
    {
        L2MCD_LOG_ERR("%s portdb_ifname_to_portindex_hash alloc Fail",__FUNCTION__);
        L2MCD_INIT_LOG("%s portdb_ifname_to_portindex_hash alloc Fail",__FUNCTION__);
    }

    portdb_portindex_to_ifname_hash = hashGrowGenericCreate(PORTDB_IFNAME_HASH_INIT_SIZE,
            HASH_GROW_DO_NOT_SHRINK, portdb_portindex_key_compare,
            portdb_portindex_hash_function, NULL);
    if (!portdb_portindex_to_ifname_hash)
    {
        L2MCD_LOG_ERR("%s portdb_portindex_to_ifname_hash alloc Fail",__FUNCTION__);
        L2MCD_INIT_LOG("%s portdb_portindex_to_ifname_hash alloc Fail",__FUNCTION__);
    }
    L2MCD_INIT_LOG("%s portdb_hash size idxtoname:%d nametoidx:%d", __FUNCTION__, PORTDB_IFNAME_HASH_INIT_SIZE, PORTDB_IFNAME_HASH_INIT_SIZE);
    return 0;        
}

unsigned int portdb_get_port_vrf_index(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{
    portdb_entry_t *port_entry;

    port_entry = portdb_find_port_entry(portdb_tree, port_index);
    if (!port_entry) {
        return IPVRF_INVALID_VRF_IDX; //this indicates invalid vrf index
    }

    return port_entry->vrf_id;
}

int portdb_portindex_key_compare(unsigned long key1, unsigned long key2)
{
    if(key1 < key2)
        return -1;
    else if(key1 > key2)
        return 1;
    
    return 0;
}

UINT32 portdb_portindex_hash_function(unsigned long key)
{
    return ( (UINT32) key); //portindex is unique for each port
}

/*Gvid to ivid mapping*/
static hashGrowGeneric *portdb_gvid_to_ivid_hash = NULL;
#define PORTDB_GVID_HASH_INIT_SIZE 100

int portdb_gvid_key_compare(unsigned long key1, unsigned long key2)
{
    if(key1 < key2)
        return -1;
    else if(key1 > key2)
        return 1;
    
    return 0;
}

UINT32 portdb_gvid_hash_function(unsigned long key)
{
    return ( (UINT32) key); //gvid is unique for each port
}


int portdb_gvid_hash_init(void)
{
    portdb_gvid_to_ivid_hash = hashGrowGenericCreate(PORTDB_IFNAME_HASH_INIT_SIZE,
            HASH_GROW_DO_NOT_SHRINK, portdb_gvid_key_compare,
            portdb_gvid_hash_function, NULL);

    return 0;        
}   

/*Vrf name to vrfId mapping*/
//Hash table to search vrf name
static hashGrowGeneric *portdb_vrfname_to_vrfid_hash = NULL;
static hashGrowGeneric *portdb_vrfid_to_vrfname_hash = NULL;
#define PORTDB_VRFNAME_HASH_INIT_SIZE 100

int portdb_vrfid_key_compare(unsigned long key1, unsigned long key2)
{
    if(key1 < key2)
        return -1;
    else if(key1 > key2)
        return 1;
    
    return 0;
}

UINT32 portdb_vrfid_hash_function(unsigned long key)
{
    return key; //vrfid is unique for each vrf name
}

int portdb_add_vrfname(char *vrfname, int name_len, VRF_INDEX vrfid, unsigned char afi)
{
    int ret;
    portdb_vrf_t *vrf;

    if( !(vrf = (portdb_vrf_t *)calloc(1, sizeof(portdb_vrf_t))) )
        return -1;

    if( !(vrf->vrf_name = (char *)malloc(name_len + 1)) ) {
        free(vrf);
        return -1;
    }    
    strncpy(vrf->vrf_name, vrfname, name_len);
	vrf->vrf_name[name_len]= '\0';
    vrf->afi = afi;
    ret = hashGrowGenericInsert(portdb_vrfid_to_vrfname_hash, vrfid, (unsigned long)vrf);
    if(!ret)
        return -1; //Failed to add vrf name to hash table;

    ret = hashGrowGenericInsert(portdb_vrfname_to_vrfid_hash, (unsigned long)vrf->vrf_name, vrfid);
    if(!ret)
        return -1; //Failed to add vrf name to hash table;

    return 0;    
}


int portdb_vrf_hash_init(void)
{
    portdb_vrfname_to_vrfid_hash = hashGrowGenericCreate(PORTDB_VRFNAME_HASH_INIT_SIZE,
            HASH_GROW_DO_NOT_SHRINK, string_key_compare,
            string_key_hash_function, NULL);

    portdb_vrfid_to_vrfname_hash = hashGrowGenericCreate(PORTDB_VRFNAME_HASH_INIT_SIZE,
            HASH_GROW_DO_NOT_SHRINK, portdb_vrfid_key_compare,
            portdb_vrfid_hash_function, NULL);

    //Add default vrf to hash table
    portdb_add_vrfname(DEFAULT_VRF_NAME, strlen(DEFAULT_VRF_NAME), DEFAULT_VRF_ID, 0);

    return 0;        
}

portdb_entry_t *portdb_find_port_entry(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{
    return(M_AVLL_FIND(*portdb_tree, (void *)&port_index));
}

unsigned long portdb_get_port_ifindex(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{
    portdb_entry_t *port_entry;

    port_entry = portdb_find_port_entry(portdb_tree, port_index);
    if (!port_entry) {
        L2MCD_LOG_INFO("%s port_index %d not found",__FUNCTION__, port_index);
        return 0; //this indicates port is down
    }

    return port_entry->ifindex;
}

unsigned char portdb_is_port_index_valid(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{
    portdb_entry_t *port_entry;

    port_entry = portdb_find_port_entry(portdb_tree, port_index);
    if (!port_entry) {
        return 0; //this indicates invalid port or port not yet added to portdb
    }
    
    return 1;
}

unsigned char portdb_get_port_type(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{
    portdb_entry_t *port_entry;

    port_entry = portdb_find_port_entry(portdb_tree, port_index);
    if (!port_entry) {
        return 1; 
    }

    return port_entry->type;
}

int portdb_set_port_state(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index, unsigned char port_state)
{
    portdb_entry_t *port_entry;

    port_entry = portdb_find_port_entry(portdb_tree, port_index);
    if (!port_entry) {
        return -1;
    }

    port_entry->port_state = port_state;

    return 0;
}

port_link_list_t *
portdb_get_port_lowest_ipv4_addr_from_list(L2MCD_AVL_TREE *portdb_tree, UINT32 port_index)
{
    //UINT32 retcode;
    portdb_entry_t *port_entry;

    port_entry  = portdb_find_port_entry(portdb_tree, port_index);
    if(port_entry) {
        if(port_entry->opaque_data)
            return port_entry->opaque_data; 
    }

	return (0);
}

unsigned char portdb_get_port_state(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{
    portdb_entry_t *port_entry;

    port_entry = portdb_find_port_entry(portdb_tree, port_index);
    if (!port_entry) {
        return 0; //this indicates port is down
    }

    return port_entry->port_state;
}

int portdb_delete_ifname(char *ifname)
{
    int ret = 0;
    unsigned long port_index = 0;
    unsigned long ifname_ptr = 0;

    ret = hashGrowGenericGetAndDelete(portdb_ifname_to_portindex_hash, (unsigned long)ifname, &port_index, NULL);
    if(ret != 1)
        return -1; //interface name not found

    //printf("%s: Deleted %d\n", __FUNCTION__, port_index);
    ret = hashGrowGenericGetAndDelete(portdb_portindex_to_ifname_hash, port_index, &ifname_ptr, NULL);
    if(ret != 1)
        return -1; //interface name not found
    //printf("%s: Deleted %s\n", __FUNCTION__, (char *)ifname_ptr);
    free((char *)ifname_ptr);

    return 0;
}

int portdb_remove_port_entry_from_tree(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index)
{
    portdb_entry_t *port_entry;

    port_entry = portdb_find_port_entry(portdb_tree, port_index);
    if (!port_entry || port_entry->opaque_data) {
        return -1;
    }

    //Cleanup ip4 related info
    if(port_entry->ip4) {
        // free(port_entry->ip4); 
        // this is a list now
        list_delete (port_entry->ip4); 
        port_entry->ip4 = NULL;			
    }

    //Cleanup ip6 related info
    if(port_entry->ip6) {
        free(port_entry->ip6);
    }

    M_AVLL_DELETE(*portdb_tree, port_entry);
    L2MCD_LOG_INFO("Deleted port_index:%d (ifindex:0x%x) from AVL tree", port_index, port_entry->port_index);
    free(port_entry);
    port_entry=NULL;

    return 0;
}

int portdb_add_port_entry_to_tree(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index, 
            VRF_INDEX vrf_id, unsigned long ifindex)
{
    portdb_entry_t *port_entry;

    //Note: If port entry exists, then update the data or ignore ??
    port_entry = portdb_find_port_entry(portdb_tree, port_index);
    if (port_entry)
    {
        L2MCD_LOG_NOTICE("%s port_index:%d entry exists", __FUNCTION__, port_index);
        return 0;
    }
    port_entry = (portdb_entry_t*)calloc(1, sizeof(portdb_entry_t));

    if (!port_entry) {
        return -1;
    }

    port_entry->vrf_id = vrf_id;
    port_entry->ifindex = ifindex;
    port_entry->port_index = port_index;
    port_entry->mtu = PORTDB_DEFAULT_PORT_MTU;
    port_entry->ipv6_mtu = PORTDB_DEFAULT_PORT_MTU;
    port_entry->type = PORTDB_DEFAULT_PORT_TYPE; /* Unknown by default */ 

    M_AVLL_INIT_NODE(port_entry->node);
    if (!M_AVLL_INSERT(*portdb_tree, port_entry))
    {
        L2MCD_LOG_INFO("Err Added port_index:%d to AVL tree", port_index);
        free(port_entry);
        return -1;
    }
    L2MCD_LOG_INFO("Added port_index:%d to AVL tree", port_index);

    return 0;
}

void
portdb_insert_addr_ipv4_list(L2MCD_AVL_TREE *portdb_tree, UINT32 port_index,
                            UINT32 ipaddress, UINT8 prefix_length, VRF_INDEX vrf_index, UINT32 flags)
{

    PORTDB_IP4  *ipv4_entry;
    portdb_entry_t *port_entry;
    port_link_list_t *head, *prev = NULL, *temp_entry, *temp;

    port_entry  = portdb_find_port_entry(portdb_tree, port_index);
    if(!port_entry)
    {
        L2MCD_LOG_INFO("%s Port entry not found for %d", __FUNCTION__, port_index);
        return;
    }
    //FIXME: If ipv4 entry exists, then update the data or ignore ??

    temp_entry = (port_link_list_t *)calloc(1, sizeof(port_link_list_t));
    if (!temp_entry) {
        L2MCD_LOG_ERR("calloc failed %s", __FUNCTION__);
        return ;
    }
    ipv4_entry = &temp_entry->value;
    ipv4_entry->port_index = port_index;
    ipv4_entry->ipaddress = ipaddress;
    ipv4_entry->prefix_length = prefix_length;
    ipv4_entry->vrf_index = vrf_index;
    ipv4_entry->flags = flags;

    head = (port_link_list_t *)port_entry->opaque_data;

    while(head && head->value.ipaddress < ipaddress)
    {
        prev = head;
        head = head->next;
    }

    if(prev) {
        temp_entry->next = prev->next;
        prev->next = temp_entry;
    } else {
        temp = port_entry->opaque_data;
        temp_entry->next = temp;
        port_entry->opaque_data = temp_entry;
    }
}

int 
portdb_remove_addr_ipv4_list(L2MCD_AVL_TREE *portdb_tree, UINT32 port_index, UINT32 ipaddress)
{
    portdb_entry_t *port_entry;
    port_link_list_t *head, *prev = NULL;

    port_entry  = portdb_find_port_entry(portdb_tree, port_index);
    if(!port_entry)
        return 1;

    head = (port_link_list_t *)port_entry->opaque_data;

    while(head && head->value.ipaddress != ipaddress)
    {
        prev = head;
        head = head->next;
    }

    if(head && head->value.ipaddress == ipaddress) {
        if(prev) {
            prev->next = head->next;
        } else
            port_entry->opaque_data = head->next;
        free(head);
        head=NULL;
    }
    if (!port_entry->opaque_data) return 0;
    return 1;
}


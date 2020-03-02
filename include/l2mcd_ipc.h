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
#ifndef __L2MCD_IPC_H__
#define __L2MCD_IPC_H__

#include <netinet/ether.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

#define L2MCD_IPC_SOCK_NAME "/var/run/l2mcd_ipc.sock"

#define L2MCD_IFNAME_SIZE       20
#define L2MCD_IP_ADDR_STR_SIZE  16
#define L2MCD_IPC_MAX_PORTS         100
#define L2MCD_OP_ENABLE             1
#define L2MCD_OP_DISABLE            0

typedef enum L2MCD_MSG_TYPE {
    L2MCD_INVALID_MSG,
    L2MCD_SNOOP_CONFIG_MSG,
    L2MCD_SNOOP_STATIC_CONFIG_MSG,
    L2MCD_SNOOP_MROUTER_CONFIG_MSG,
    L2MCD_SNOOP_MROUTER_REMOTE_CONFIG_MSG,
    L2MCD_SNOOP_REMOTE_CONFIG_MSG,
    L2MCD_SNOOP_PORT_LIST_MSG,
    L2MCD_CONFIG_PARAMS_MSG,
    L2MCD_VLAN_MEM_TABLE_UPDATE,
    L2MCD_INTERFACE_TABLE_UPDATE,
    L2MCD_LAG_MEM_TABLE_UPDATE,
    L2MCD_SNOOP_CTL_MSG,
    L2MCD_IGMP_PKT_MSG,
    L2MCD_MAX_MSG
} L2MCD_MSG_TYPE;

typedef struct PORT_ATTR_ {
    char       pnames[L2MCD_IFNAME_SIZE];
    int        oper_state;
    int        stp_state; 
} PORT_ATTR;

typedef struct L2MCD_CONFIG_MSG {
    uint8_t     op_code;  
    uint8_t     enabled;
    uint8_t     querier;
    uint8_t     fast_leave;
    int         cmd_code;
    int         version;
    int         query_interval;
    int         last_member_query_interval;
    int         query_max_response_time;
    int         vlan_id;
    uint32_t    count;
    int         prefix_length;
    uint8_t     mac_addr[ETHER_ADDR_LEN];
    char        gaddr[L2MCD_IP_ADDR_STR_SIZE];
    char        saddr[L2MCD_IP_ADDR_STR_SIZE];
    PORT_ATTR   ports[L2MCD_IPC_MAX_PORTS];
} L2MCD_CONFIG_MSG;

typedef struct L2MCD_IPC_MSG {
    int             msg_type;
    unsigned int    msg_len;
    char            data[0];
} L2MCD_IPC_MSG;
#endif

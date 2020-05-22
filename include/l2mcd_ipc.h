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

typedef struct L2MCD_IPC_MSG {
    int             msg_type;
    unsigned int    msg_len;
    char            data[0];
} L2MCD_IPC_MSG;
#endif

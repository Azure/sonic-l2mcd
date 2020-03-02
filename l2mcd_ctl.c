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

/*
 * Diagnostic test Commands 
 */
#include <stdio.h>
#include "l2mcd.h"
#include "l2mcd_ipc.h"
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> 


#define L2MCD_CTL_SOCK_NAME "/var/run/l2mcd_dbg.sock"
int l2mcd_ctl_fd;
int pk_sock_fd;

int l2mcd_ctl_ipc_init()
{
    int ret;
	struct sockaddr_un addr;


    unlink(L2MCD_CTL_SOCK_NAME);
    // create socket
    l2mcd_ctl_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (!l2mcd_ctl_fd) {
		printf("socket error %s", strerror(errno));
		return 0;
    }

    // setup socket address structure
    bzero(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, L2MCD_CTL_SOCK_NAME, sizeof(addr.sun_path)-1);

    ret = (int)bind(l2mcd_ctl_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (ret == -1)
    {
		printf("ipc bind error %s", strerror(errno));
        close(l2mcd_ctl_fd);
        return 0;
    }

    pk_sock_fd= socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (!pk_sock_fd)
    {
        printf("pk_sock_fd socket error %s\n", strerror(errno));
    }
    return 1;
}

int l2mcd_ctl_send(int msgType, uint32_t msgLen, void *data)
{

    size_t len = 0;
    struct sockaddr_un addr;
    int rc=0;

    L2MCD_IPC_MSG *tx_msg;
    len = msgLen + (offsetof(struct L2MCD_IPC_MSG, data));
    //printf("tx_msg len %d msglen %d\n", (int)len, msgLen);

    tx_msg = (L2MCD_IPC_MSG *)calloc(1, len);
    if (tx_msg == NULL)
    {
		printf("tx_msg mem alloc error\n");
        return -1;
    }
    tx_msg->msg_type = msgType;
    tx_msg->msg_len  = msgLen;
    memcpy(tx_msg->data, data, msgLen);

    bzero(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, L2MCD_IPC_SOCK_NAME, sizeof(addr.sun_path)-1);

    rc = (int)sendto(l2mcd_ctl_fd, (void*)tx_msg, len, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == -1)
    {
		printf("tx_msg send error %s\n",strerror(errno));
    }   
    free(tx_msg);
    return rc;
}

char g_l2mcd_test_buf1[2000];
uint8_t g_l2mcd_test_buf2[2000];

void l2mcd_ctl_send_pkt(char *buf, char *ifname)
{
    struct sockaddr_ll sa;
    FILE *pkt_fp=NULL;
    int pkt_len=0;
    int i=0, j=0;
    char str[20];
  
    pkt_fp =  fopen(buf,"r");
    if (!pkt_fp) {printf("failed to open %s",buf); return;}
 
    sa.sll_halen = 6; 
    sa.sll_ifindex = if_nametoindex(ifname);
    sa.sll_addr[5]= 0x55; 
    while(!feof(pkt_fp))
    {
        g_l2mcd_test_buf1[i++] = fgetc(pkt_fp);
        if (i>2000) break;
    }
    for (j=0;j<i;j+=2)
    {
            sprintf(str,"0x%c%c", g_l2mcd_test_buf1[j],g_l2mcd_test_buf1[j+1]);   
            g_l2mcd_test_buf2[j/2]= strtol(str, NULL, 0);
    }
    g_l2mcd_test_buf2[i]='\0';
    fclose(pkt_fp);
    pkt_len=i;
    printf("iname:%s ifindex:%d pkt_len:%d sock_fd:%d sending..\n", ifname,sa.sll_ifindex,pkt_len,pk_sock_fd);
    if (sendto(pk_sock_fd, g_l2mcd_test_buf2, pkt_len, 0, (struct sockaddr*)&sa,sizeof(sa)) == -1)
    {
        printf("sock send  %s\n",strerror(errno));
    }
 }

void print_usage()
{
    printf("Usage:\n");
    printf("\tl2mcd_ctl -d <log_level>\n");
    printf("\tl2mcd_ctl [-s <cmd_op_file>]  (-v <vlan> | -a <dump_all>) \n");
    printf("\tl2mcd_ctl (-v <vlan:1-4095 | 0:disable all>) (-p <pkt_log_file>) [-d <bit_mask| 0:disable for vlan>]\n");
    printf("\tl2mcd_ctl [-s <cmd_op_file>] (-c <1-10>)\n"); 
    printf("\tl2mcd_ctl -r <vlanid> <srcip> <grpip>  <port_name> <is_add>\n ");
    printf("\tl2mcd_ctl (-s <ip_pkt_hex_file>) (-v <vlan>) (-i <port_if>)\n"); 
    printf("\tl2mcd_ctl -L <ip_pkt_hex_file> <port_name> \n"); 
    return;
}

int main(int argc, char **argv)
{
    int opt,dbg_Level;
    L2MCD_CTL_MSG msg;
    L2MCD_CONFIG_MSG cfg_msg;
    memset(&msg, 0, sizeof(L2MCD_CTL_MSG));

    if (!l2mcd_ctl_ipc_init())
    {
        printf("sockinit failed\n");
        exit(1);
    }
    if (argc==1)
    {
        print_usage();
        exit(0);

    }
    snprintf(msg.fname, 100, "/dev/pts/1");

    while ((opt = getopt(argc, argv, "r:d:v:s:p:a:c:i:L")) != -1) 
    {
        switch (opt) 
        {
        case 'r':
           cfg_msg.vlan_id = atoi(argv[optind-1]);
           memcpy(cfg_msg.saddr,argv[optind], L2MCD_IP_ADDR_STR_SIZE);
           memcpy(cfg_msg.gaddr,argv[optind+1], L2MCD_IP_ADDR_STR_SIZE);
           memcpy(cfg_msg.ports[0].pnames, argv[optind+2], L2MCD_IFNAME_SIZE);
           cfg_msg.op_code = atoi(argv[optind+3]);
           printf("Test Group : vlan:%d %s %s %s %d\n",cfg_msg.vlan_id,cfg_msg.saddr,cfg_msg.gaddr,cfg_msg.ports[0].pnames,cfg_msg.op_code);
           l2mcd_ctl_send(L2MCD_SNOOP_REMOTE_CONFIG_MSG, sizeof(cfg_msg), (void *)&cfg_msg);
           goto l2mcd_ctl_end;
           break;
        case 'd':
           dbg_Level=atoi(optarg);
           msg.cmd |=L2MCD_CTL_CMD_DB_LEVEL;
           msg.dbgLevel=dbg_Level;
           break;
        case 'v':
           msg.cmd |=L2MCD_CTL_CMD_SESS_VID;
           msg.vid = atoi(optarg);
           if (!msg.vid || (msg.vid>4095))
           {
               msg.vid=0;
           }
           break;
       case 's':
           memcpy(msg.fname, optarg, 100);
           msg.cmd|=L2MCD_CTL_CMD_SESS_NAME;
           break;
       case 'p':
           memcpy(msg.fname, optarg, 100);
           msg.cmd|=L2MCD_CTL_CMD_PLOG_NAME;
           break;
        case 'a':
           msg.cmd |=L2MCD_CTL_CMD_DUMP_ALL;
           break;
        case 'c':
           msg.cmd |=L2MCD_CTL_CMD_CUSTOM;
           msg.cmd_id = atoi(optarg);
           break;
        case 'i':
           msg.cmd |= L2MCD_CTL_CMD_PKT;
           msg.cmd_id = atoi(optarg);
           break;
        case 'L':
           l2mcd_ctl_send_pkt(argv[optind], argv[optind+1]);
           return 0;
        default: /*?*/
           print_usage();
           exit(0);
           break;
        }

    }

    if ((msg.cmd&L2MCD_CTL_CMD_SESS_NAME) && (msg.cmd &L2MCD_CTL_CMD_PLOG_NAME))
    {
        printf("command error\n");
        return 0;
    }
    else if(msg.cmd & L2MCD_CTL_CMD_PKT)
    {
        msg.cmd = L2MCD_CTL_CMD_PKT;
    }
    else if (msg.cmd & L2MCD_CTL_CMD_PLOG_NAME)
    {
        if (msg.cmd&L2MCD_CTL_CMD_DB_LEVEL) printf("logmask:%d",msg.dbgLevel);
        if (!msg.vid) printf("Trace Log Disabled for all Vlans\n");
        else printf("Trace log enabled for vlan:%d handle:%s \n", msg.vid, msg.fname);
    }
    else if (msg.cmd&L2MCD_CTL_CMD_DB_LEVEL)
    {
        printf("setting loglevel to %d\n", msg.dbgLevel);
    }
    else
    {
        if (msg.cmd & L2MCD_CTL_CMD_DUMP_ALL)
        {
            printf("L2MCD Dump All \n");
        }
        if (msg.cmd & L2MCD_CTL_CMD_SESS_VID)
        {
            printf("VDB Dump vlan:%d ses:%s\n", msg.vid,msg.fname);
        }
        else if (msg.cmd & L2MCD_CTL_CMD_CUSTOM)
        {
            printf("Custom command %s\n",msg.fname);
        }
    }

    l2mcd_ctl_send(L2MCD_SNOOP_CTL_MSG, sizeof(msg), &msg);
  
l2mcd_ctl_end:
    return 0;
  
}



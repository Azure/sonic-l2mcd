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

#define _GNU_SOURCE 
#include <sys/socket.h>
#include <sys/types.h>
#include "l2mcd.h"
#include <linux/filter.h>
#include <linux/rtnetlink.h>
#include "mld_vlan_db.h"
#include "l2mcd_mld_utils.h"
#include "l2mcd_mld_port.h"
#include "l2mcd_mcast_co.h"
#include <sys/ioctl.h>

L2MCD_CONTEXT l2mcd_context;

/*
 * l2mcd_process_ipc_msg 
 *
 * Processing of L2MCd socket messages
 */
static void l2mcd_process_ipc_msg(L2MCD_IPC_MSG *msg, int len, struct sockaddr_un client_addr)
{
    
}
 
void l2mcd_100ms_timer(evutil_socket_t fd, short what, void *arg)
{

}

void l2mcd_libevent_destroy(struct event *ev)
{
    event_del(ev);
}

/*
 * l2mcd_libevent_create
 *
 * Create a libevent to register a callback for a socket
 */
struct event *l2mcd_libevent_create(struct event_base *base, 
        evutil_socket_t sock,
        short flags,
        void *cb_fn,
        void *arg, 
        const struct timeval *tv,
        int ev_prio)
{
    struct event *ev = 0;
    int prio;

    if (-1 == sock) //100ms timer
    {
        prio = L2MCD_LIBEV_HIGH_PRI_Q;
    }
    else
    {
        prio = L2MCD_LIBEV_LOW_PRI_Q;
        evutil_make_socket_nonblocking(sock);
    }
    if (ev_prio != -1) prio= ev_prio;

    ev = event_new(base, sock, flags, cb_fn, arg);
    if (ev)
    {
        if(-1 == event_priority_set(ev, prio))
        {
            L2MCD_LOG_ERR("event_priority_set failed");
            return NULL;
        }

        if (-1 != event_add(ev, tv))
        {
            g_l2mcd_stats_libev_no_of_sockets++;
            L2MCD_LOG_INFO("Event Added : ev:%p, arg : %s", ev, (char *)arg);
            L2MCD_LOG_INFO("base : %p, sock : %d, flags : %x, cb_fn : %p", base, sock, flags, cb_fn);
            if (tv)
                L2MCD_LOG_INFO("tv.sec : %u, tv.usec : %u", tv->tv_sec, tv->tv_usec);

            return ev;
        }
    }
    return NULL;
}

/* 
 * l2mcd_recv_client_msg
 *
 * Process messages from client sockets
 */
void l2mcd_recv_client_msg(evutil_socket_t fd, short what, void *arg)
{
    char buffer[4096];
    socklen_t len;
    struct sockaddr_un client_sock;

    g_l2mcd_stats_libev_ipc++;

    len = sizeof(struct sockaddr_un);
    len = recvfrom(fd, (void *) buffer, 4096, 0, (struct sockaddr *) &client_sock, &len);
    if (len == -1)
    {
        L2MCD_LOG_INFO("recv  message error %s", strerror(errno));
    }
    else
    {
        L2MCD_LOG_DEBUG("%s Rcvd message len %d", __FUNCTION__, len);
        l2mcd_process_ipc_msg((L2MCD_IPC_MSG *)buffer, len, client_sock);
    }
}

/*
 * l2mcd igmp_tx socket 
 *
 * Create RAW socket for sending IGMP packets
 */
int l2mcd_igmptx_sock_init()
{
    g_l2mcd_igmp_tx_handle = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);


    if (g_l2mcd_igmp_tx_handle<0)
    {
      L2MCD_LOG_ERR("Failed to create TX socket for IGMP Snooping");  
      g_l2mcd_igmp_tx_handle=0;
      return -1;
    }
    L2MCD_INIT_LOG("Created IGMP TX socket fd:%d", g_l2mcd_igmp_tx_handle);
    return 0;
}

void l2mcd_parseRtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {  
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta; 
        }
        rta = RTA_NEXT(rta,len);  
    }
}

/*
 * l2mcd_nl_msg - Netlink Message handler 
 */
void l2mcd_nl_msg(evutil_socket_t fd, short what, void *arg)
{
    struct sockaddr_nl  nl_sa; 
    struct iovec iov; 
    uint8_t buf[8192];
    struct msghdr msg;  
            
    struct nlmsghdr *h;
    struct ifinfomsg *ifi; 
    struct rtattr *tb[IFLA_MAX + 1];
    int if_up=0;
    int if_run=0;
    char *ifName=NULL;
    ssize_t status=0;

    memset(&nl_sa, 0, sizeof(nl_sa));
    iov.iov_base = buf; 
    iov.iov_len = sizeof(buf);
    msg.msg_name = &nl_sa;               
    msg.msg_namelen = sizeof(nl_sa);       
    msg.msg_iov = &iov;                    
    msg.msg_iovlen = 1;    

    status = recvmsg(fd, &msg, 0);
    if (status <0) 
    {
        L2MCD_VLAN_LOG_INFO(4095, "%s:%d  event Received status %li invalid", __FUNCTION__, __LINE__, status);
        return;
    }
    for (h = (struct nlmsghdr*)buf; status >= (ssize_t)sizeof(*h); ) 
    {
        L2MCD_VLAN_LOG_DEBUG(4095, "NL event Received %d", h->nlmsg_type);
        if (h->nlmsg_type == RTM_NEWLINK)
        {
            if (h->nlmsg_len<0) 
            {
                L2MCD_LOG_NOTICE("NL sock msg_len:%d  len:%d",h->nlmsg_len, status);
                continue;
            } 
            ifi = (struct ifinfomsg*) NLMSG_DATA(h);
            l2mcd_parseRtattr(tb, IFLA_MAX, IFLA_RTA(ifi), h->nlmsg_len);

            if (tb[IFLA_IFNAME]) ifName = (char*)RTA_DATA(tb[IFLA_IFNAME]); 
            if_up = (ifi->ifi_flags & IFF_UP)? 1:0;
            if_run= (ifi->ifi_flags & IFF_RUNNING)? 1:0;
            L2MCD_LOG_DEBUG("IF Event: %s up:%d if_run:%d index:%d", ifName, if_up, if_run, ifi->ifi_index);  
            if (g_port_init_done && (strstr((char*)ifName, "PortChannel") || strstr((char*)ifName, "Ethernet")))
            {
                l2mcd_portstate_update(ifi->ifi_index, if_run, ifName);
            }
        }
        status -= NLMSG_ALIGN(h->nlmsg_len);
        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(h->nlmsg_len));
    }
    return; 
}


/*
 * l2mcd_recv_igmp_msg
 * 
 * IGMP Packet RX handler
 */
void l2mcd_recv_igmp_msg(evutil_socket_t fd, short what, void *arg)
{
}

int l2mcd_igmprx_sock_close(char *pname, int fd, struct event *igmp_rx_event)
{
    return 0;

}

/*
 * l2mcd igmp_rx socket 
 *
 * Create RAW socket for recieving IGMP packets
 */
struct event *l2mcd_igmprx_sock_init(int *fd, char *iname)
{

}


/*
 * l2mcd_ipc_init
 *
 * Socket communication to l2mcd config manager
 */
int l2mcd_ipc_init()
{
    struct sockaddr_un sa;
    int ret;
    struct event *ipc_event = NULL; 


    unlink(L2MCD_IPC_SOCK_NAME);
    g_l2mcd_ipc_handle = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (!g_l2mcd_ipc_handle)
    {
        L2MCD_INIT_LOG("sock create fail %s %s", L2MCD_IPC_SOCK_NAME, strerror(errno));
        return -1;
    }
    L2MCD_INIT_LOG("Created socket %s fd:%d", L2MCD_IPC_SOCK_NAME, g_l2mcd_ipc_handle);
    // setup socket address structure
    memset(&sa, 0, sizeof(struct sockaddr_un));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, L2MCD_IPC_SOCK_NAME, sizeof(sa.sun_path) - 1);

    ret = bind(g_l2mcd_ipc_handle, (struct sockaddr *)&sa, sizeof(struct sockaddr_un));
    if (ret == -1)
    {
        L2MCD_LOG_ERR("ipc bind error %s", strerror(errno));
        L2MCD_INIT_LOG("ipc bind error %s", strerror(errno));
        close(g_l2mcd_ipc_handle);
        return -1;
    }

    //Add ipc socket to libevent list
    ipc_event = l2mcd_libevent_create(g_l2mcd_evbase, g_l2mcd_ipc_handle,
            EV_READ|EV_PERSIST, l2mcd_recv_client_msg, (char *)"L2MCD_IPC", NULL, -1);
    if (!ipc_event)
    {
        L2MCD_LOG_ERR("ipc_event Create failed");
        L2MCD_INIT_LOG("ipc_event Create failed");
        return -1;
    }
    L2MCD_INIT_LOG("LibEvent Register for sock fd:%d name:%s",g_l2mcd_ipc_handle,L2MCD_IPC_SOCK_NAME);
    return 0;
}

int l2mcd_unix_sock_create(uint32_t *sock, char *sock_name, int levent)
{
	struct sockaddr_un addr;
    struct event *ipc_event = NULL; 
    int fd;

    // create socket
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd<0) {
        L2MCD_LOG_ERR("%s  Sock %s create error", __FUNCTION__,sock_name);
        L2MCD_INIT_LOG("%s Sock %s create error %s", __FUNCTION__,sock_name,strerror(errno));
		return -1;
    }
    unlink(sock_name);
    bzero(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_name, sizeof(addr.sun_path)-1);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un))<0)
    {
        L2MCD_LOG_ERR("%s  Sock %s bind error", __FUNCTION__,sock_name);
        L2MCD_INIT_LOG("%s Sock %s bind error %s", __FUNCTION__,sock_name,strerror(errno));
        close(fd);
        return -1;
    }
    *sock = fd;
    L2MCD_INIT_LOG("Created socket %s  fd:%d",sock_name,*sock);
    if (!levent)
    {
        return 0;
    }
    ipc_event = l2mcd_libevent_create(g_l2mcd_evbase, fd,
            EV_READ|EV_PERSIST, l2mcd_recv_client_msg, (char *)"IPC", NULL, -1);
    if (!ipc_event)
    {
        L2MCD_LOG_ERR("ipc_event Create failed");
        L2MCD_INIT_LOG("ipc_event Create failed");
        return -1;
    }
    L2MCD_INIT_LOG("LibEvent Register for sock fd:%d name:%s",*sock,sock_name);
    return 0;
}


int port_ifname_db_init()
{
    int i=0, rc=0;
    char ifname[20];
    for (i=0;i<L2MCD_PORTDB_PHYIF_MAX_IDX;i++)
    {
        snprintf(ifname, 20, "Ethernet%d",i);
        rc= portdb_add_ifname(ifname, strlen(ifname) + 1, i+L2MCD_PORTDB_PHYIF_START_IDX);
    }
    L2MCD_INIT_LOG_INFO("%s Done", __FUNCTION__);
    return rc;
}

int l2mcd_nl_init()
{
      struct sockaddr_nl nl_sa = {
        .nl_family = AF_NETLINK,
        .nl_pad    = 0,
        .nl_pid    = 0,
        .nl_groups = RTMGRP_LINK
    };
    struct event *ipc_event = NULL; 
    g_l2mcd_nl_fd =  socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE); 
    if (g_l2mcd_nl_fd<0) 
    {
        L2MCD_INIT_LOG("NetLink socket Init Failed");
        L2MCD_LOG_ERR("NetLink socket Init Failed");
        return -1;
    }
    if (bind(g_l2mcd_nl_fd, (struct sockaddr*)&nl_sa, sizeof(nl_sa)) < 0) 
    {    // bind socket
        L2MCD_INIT_LOG("Failed to bind netlink socket: %s\n", (char*)strerror(errno));
        close(g_l2mcd_nl_fd);
        return -1;
    }   
    //Add ipc socket to libevent list
    ipc_event = l2mcd_libevent_create(g_l2mcd_evbase, g_l2mcd_nl_fd,
                EV_READ|EV_PERSIST, l2mcd_nl_msg, (char *)"L2MCD NL", NULL,-1);
    if (!ipc_event)
    {
        L2MCD_LOG_ERR("ipc_event Create failed");
        L2MCD_INIT_LOG("ipc_event Create failed");
        return -1;
    }
    L2MCD_INIT_LOG("LibEvent Register for NL sock fd:%d ",g_l2mcd_nl_fd);
    return 0;
}


void mcast_global_init(UINT32 afi)
{
    L2MCD_INIT_LOG_INFO("Entering %s afi:%d", __FUNCTION__, afi);
    return;
}

int mcast_igmp_init()
{
	return (0);
}

/*
 * l2mcd_system_init
 *
 * L2MC Daemon Starting Point
 */
int l2mcd_system_init(int flag)
{
    struct event_config *cfg  = NULL;
    struct timeval l2mcd_ipc_msec_50 = { 0, 1*1000 };
    struct timeval l2mcd_100ms_tv = {0, L2MCD_100MS_TIMEOUT};
    struct event   *l2mcd_evtimer_100ms = 0;
    int rc=0;
    char *l2mcd_msg_sock= L2MCD_MSG_SOCK_NAME;

    signal(SIGPIPE, SIG_IGN);
    cfg = event_config_new();
    if (!cfg)
    {
        L2MCD_LOG_INFO("%s event_config_new failed", __FUNCTION__);
        L2MCD_INIT_LOG("%s event_config_new failed", __FUNCTION__);
        return -1;
    }
    L2MCD_LOG_INFO("LIBEVENT VER : 0x%x", event_get_version_number());
    L2MCD_INIT_LOG("LIBEVENT VER : 0x%x", event_get_version_number());
    event_config_set_max_dispatch_interval(cfg, &l2mcd_ipc_msec_50/*max_interval*/, -1/*max_callbacks*/, 1/*min-prio*/);

    /* Create event base to attach a event */
    g_l2mcd_evbase = event_base_new_with_config(cfg);
    if (g_l2mcd_evbase == NULL)
    {
        L2MCD_LOG_ERR("event base creation failed");
        L2MCD_INIT_LOG("event base creation failed");
        return -1;
    }
    event_base_priority_init(g_l2mcd_evbase, L2MCD_LIBEV_PRIO_QUEUES);

    /*IGMP Control Packet Transmit Socket*/
    rc = l2mcd_igmptx_sock_init();
    if (rc < 0)
    {
        L2MCD_LOG_ERR("l2mcd IGMNP TX sock init failed %d", rc);
        L2MCD_INIT_LOG("l2mcd IGMP TX sock init failed %d", rc);
        return -1;
    }
    L2MCD_INIT_LOG_INFO("TX Sock Initialized");
    /*Create a Timer Libevent*/
    l2mcd_evtimer_100ms= l2mcd_libevent_create(g_l2mcd_evbase, -1,
            EV_PERSIST, l2mcd_100ms_timer, (char *)"L2MCD 100MS Timer", &l2mcd_100ms_tv, -1);
    if (!l2mcd_evtimer_100ms)
    {
        L2MCD_LOG_ERR("l2mcd_evtimer_100ms create Failed");
        L2MCD_INIT_LOG("l2mcd_evtimer_100ms create Failed");
        return -1;
    }

    if (l2mcd_unix_sock_create(&g_l2mcd_igmp_msg_handle, l2mcd_msg_sock, 0)<0)
    {
        L2MCD_INIT_LOG("igmp_msg_handle sock create failed");
        return -1;
    }
    L2MCD_INIT_LOG("igmp_msg_handle:%d sock:%s created ",g_l2mcd_igmp_msg_handle, l2mcd_msg_sock);

    /*IPC Messaging Socket with L2MC Config Manager*/
    rc = l2mcd_ipc_init();
    if (rc <0)
    {
        L2MCD_LOG_ERR("l2mc ipc init failed :%d", rc);
        L2MCD_INIT_LOG("l2mc ipc init failed :%d", rc);
        return -1;
    }
    l2mcd_nl_init();
    L2MCD_INIT_LOG("system init done");
    event_base_dispatch(g_l2mcd_evbase);
    return 0;
}

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
#ifndef __MCAST_ADDR_H__
#define __MCAST_ADDR_H__

#include "l2mcd_data_struct.h"

// Structure and type definitions

typedef union MCAST_AF_ADDR
{
	UINT32        v4addr;
	IPV6_ADDRESS  v6addr;
} MCAST_AF_ADDR;

typedef struct MADDR_ST
{
	MCAST_AF_ADDR     ip;	
	
#if defined (CONFIG_X86) || defined (x86)
			UINT32					  reserved:16;
			UINT32			  plen:8;
			UINT32			  afi:8;
#else
			UINT32			  afi:8;
			UINT32			  plen:8;
			UINT32					  reserved:16;
#endif

} MADDR_ST;

#define IP6_OPT_RTALERT_MLD	0	/* Datagram contains an MLD message */
#define	IP6_ICMPV6			58		/* ICMP6 */
#define IP6_OPT_RTALERT		0x05	/* 00 0 00101 */
#define IP6_OPT_PAD1		0x00	/* 00 0 00000 */
#define IP6_HOP_BY_HOP_EH	0
/* Address Mask */
#define IP6_ADDRESS_MASK0	{{{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }}}
#define IP6_ADDRESS_MASK32	{{{ 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, \
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}
#define IP6_ADDRESS_MASK64	{{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}
#define IP6_ADDRESS_MASK96	{{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }}}
#define IP6_ADDRESS_MASK128	{{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}}

#define IP6_COPY_ADDRESS(a, b)	\
	{(a).address.address32[0] = (b).address.address32[0];	\
	 (a).address.address32[1] = (b).address.address32[1];	\
	 (a).address.address32[2] = (b).address.address32[2];	\
	 (a).address.address32[3] = (b).address.address32[3]; }

#define IP6_IS_ADDRESS_UNSPECIFIED(a)	\
	(((a).address32[0] == 0) &&	\
	 ((a).address32[1] == 0) &&	\
	 ((a).address32[2] == 0) &&	\
	 ((a).address32[3] == 0))
/*
 * IPv4 compatible
 */
#define IP6_IS_ADDRESS_V4COMPAT(a)		\
	(((a).address32[0] == 0) &&	\
	 ((a).address32[1] == 0) &&	\
	 ((a).address32[2] == 0) &&	\
	 ((a).address32[3] != 0) &&	\
	 ((a).address32[3] != net_to_host_long(1)))
/*
 * Mapped
 */
#define IP6_IS_ADDRESS_V4MAPPED(a)		      \
	(((a).address32[0] == 0) &&	\
	 ((a).address32[1] == 0) &&	\
	 ((a).address32[2] == net_to_host_long(0x0000ffff)))

#define IP6_IS_ADDRESS_NOT_NULL(a)	\
	(((a).address32[0] != 0) ||	\
	 ((a).address32[1] != 0) ||	\
	 ((a).address32[2] != 0) ||	\
	 ((a).address32[3] != 0))



#define IP6_ARE_ADDRESSES_SAME(a ,b)	\
	(((a).address32[0] == (b).address32[0] ) \
	 && ((a).address32[1] == (b).address32[1] ) \
	 && ((a).address32[2] == (b).address32[2] ) \
	 && ((a).address32[3] == (b).address32[3] ) )

#define IP6_IS_ADDRESS_MULTICAST(a)	((a).address8[0] == 0xff)
#define IP6_ADDRESS_MC_SCOPE(a)		((a).address8[1] & 0x0f)
#define IP6_IS_MC_ADDRESS_FWDABLE(a) \
	(IP6_IS_ADDRESS_MULTICAST(a) &&	\
	 	(IP6_ADDRESS_MC_SCOPE(a) > 3))
#define IP6_IS_ADDRESS_MC_SITELOCAL(a)	\
	(IP6_IS_ADDRESS_MULTICAST(a) && 	\
	 (IP6_ADDRESS_MC_SCOPE(a) == IP6_ADDRESS_SCOPE_SITELOCAL))
#define IP6_IS_ADDRESS_MC_GLOBAL(a)	\
	(IP6_IS_ADDRESS_MULTICAST(a) &&	\
	 (IP6_ADDRESS_MC_SCOPE(a) == IP6_ADDRESS_SCOPE_GLOBAL))



#define IP6_ARE_ADDRESS_EQUAL	IP6_ARE_ADDRESSES_SAME
#define IP6_IS_ADDRESS_EQUAL	IP6_ARE_ADDRESSES_SAME
#define IP6_IS_ADDRESS_LESS(a, b)	\
	( ((a).address8[0]  <  (b).address8[0])  || \
	( ((a).address8[0]  == (b).address8[0])  && \
	( ((a).address8[1]  <  (b).address8[1])  || \
	( ((a).address8[1]  == (b).address8[1])  && \
	( ((a).address8[2]  <  (b).address8[2])  || \
	( ((a).address8[2]  == (b).address8[2])  && \
	( ((a).address8[3]  <  (b).address8[3])  || \
	( ((a).address8[3]  == (b).address8[3])  && \
	( ((a).address8[4]  <  (b).address8[4])  || \
	( ((a).address8[4]  == (b).address8[4])  && \
	( ((a).address8[5]  <  (b).address8[5])  || \
	( ((a).address8[5]  == (b).address8[5])  && \
	( ((a).address8[6]  <  (b).address8[6])  || \
	( ((a).address8[6]  == (b).address8[6])  && \
	( ((a).address8[7]  <  (b).address8[7])  || \
	( ((a).address8[7]  == (b).address8[7])  && \
	( ((a).address8[8]  <  (b).address8[8])  || \
	( ((a).address8[8]  == (b).address8[8])  && \
	( ((a).address8[9]  <  (b).address8[9])  || \
	( ((a).address8[9]  == (b).address8[9])  && \
	( ((a).address8[10] <  (b).address8[10]) || \
	( ((a).address8[10] == (b).address8[10]) && \
	( ((a).address8[11] <  (b).address8[11]) || \
	( ((a).address8[11] == (b).address8[11]) && \
	( ((a).address8[12] <  (b).address8[12]) || \
	( ((a).address8[12] == (b).address8[12]) && \
	( ((a).address8[13] <  (b).address8[13]) || \
	( ((a).address8[13] == (b).address8[13]) && \
	( ((a).address8[14] <  (b).address8[14]) || \
	( ((a).address8[14] == (b).address8[14]) && \
	( ((a).address8[15] <  (b).address8[15]) \
	))))))))))))))))))))))))))))))) 
#define IP6_IS_ADDRESS_LARGE(a, b)	\
	( ((a).address8[0]  >  (b).address8[0])  || \
	( ((a).address8[0]  == (b).address8[0])  && \
	( ((a).address8[1]  >  (b).address8[1])  || \
	( ((a).address8[1]  == (b).address8[1])  && \
	( ((a).address8[2]  >  (b).address8[2])  || \
	( ((a).address8[2]  == (b).address8[2])  && \
	( ((a).address8[3]  >  (b).address8[3])  || \
	( ((a).address8[3]  == (b).address8[3])  && \
	( ((a).address8[4]  >  (b).address8[4])  || \
	( ((a).address8[4]  == (b).address8[4])  && \
	( ((a).address8[5]  >  (b).address8[5])  || \
	( ((a).address8[5]  == (b).address8[5])  && \
	( ((a).address8[6]  >  (b).address8[6])  || \
	( ((a).address8[6]  == (b).address8[6])  && \
	( ((a).address8[7]  >  (b).address8[7])  || \
	( ((a).address8[7]  == (b).address8[7])  && \
	( ((a).address8[8]  >  (b).address8[8])  || \
	( ((a).address8[8]  == (b).address8[8])  && \
	( ((a).address8[9]  >  (b).address8[9])  || \
	( ((a).address8[9]  == (b).address8[9])  && \
	( ((a).address8[10] >  (b).address8[10]) || \
	( ((a).address8[10] == (b).address8[10]) && \
	( ((a).address8[11] >  (b).address8[11]) || \
	( ((a).address8[11] == (b).address8[11]) && \
	( ((a).address8[12] >  (b).address8[12]) || \
	( ((a).address8[12] == (b).address8[12]) && \
	( ((a).address8[13] >  (b).address8[13]) || \
	( ((a).address8[13] == (b).address8[13]) && \
	( ((a).address8[14] >  (b).address8[14]) || \
	( ((a).address8[14] == (b).address8[14]) && \
	( ((a).address8[15] >  (b).address8[15]) \
	))))))))))))))))))))))))))))))) 


/*
 * Definition of some useful macros to handle IP6 addresses
 */
#define IP6_ADDRESS_UNSPECIFIED_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}
#define IP6_ADDRESS_LOOPBACK_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IP6_ADDRESS_NODELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IP6_ADDRESS_LINKLOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IP6_ADDRESS_LINKLOCAL_ALLROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }}}
#define IP6_ADDRESS_ANYCAST_SOLICITED_NODE_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00 }}}
#define IP6_ADDRESS_LINKLOCAL_ALL_RIPNG_ROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09 }}}

#define IP6_ADDRESS_LINKLOCAL_ALL_DHCP6_AGENT_ROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02 }}}

#define IP6_ADDRESS_SITE_ALL_DHCP6_ROUTERS_INIT \
	{{{ 0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03 }}}

#define MADDR_IS_V4_AFI(p_maddr)     ((p_maddr)->afi == IP_IPV4_AFI)
#define MADDR_IS_V6_AFI(p_maddr)     ((p_maddr)->afi == IP_IPV6_AFI)

#define MADDR_GET_FULL_PLEN(afi) 	 ((afi) == IP_IPV4_AFI ? 32 : 128)


// Functions
void mcast_init_addr(MADDR_ST * addr, UINT32 afi, UINT32 plen);
void mcast_addr_get_mac_addr(MADDR_ST* addr, MAC_ADDRESS *mac_addr);
void mcast_set_addr (MADDR_ST *to_addr, MADDR_ST *from_addr);
void mcast_set_plen_from_netmask (UINT8 *plen, MADDR_ST *network);
void mcast_set_netmask_from_plen (MADDR_ST *netmask, UINT8 plen);
void mcast_set_ipv4_addr (MADDR_ST *to_addr, UINT32 v4_addr);
void mcast_set_ipv6_addr (MADDR_ST *to_addr, IPV6_ADDRESS *v6_addr);
void mcast_set_addr_any (MADDR_ST *addr);
void mcast_set_addr_default (MADDR_ST *addr, UINT32 afi);
void mcast_set_addr_max_value (MADDR_ST *addr);
void mcast_get_ipv4_addr (UINT32 *v4_addr, MADDR_ST *addr);
void mcast_get_ipv6_addr (IPV6_ADDRESS *v6_addr, MADDR_ST *addr);
BOOLEAN mcast_is_valid_grpaddr(MADDR_ST * addr);
BOOLEAN mcast_is_valid_unicast (MADDR_ST * addr);
BOOLEAN mcast_addr_any (MADDR_ST *addr);
BOOLEAN mcast_addr_group_wc (MADDR_ST *addr);
BOOLEAN mcast_addr_is_class_d (MADDR_ST *addr);
BOOLEAN mcast_addr_is_emb_rp (MADDR_ST *addr);
BOOLEAN mcast_addr_invalid (MADDR_ST *addr);
BOOLEAN mcast_addrs_share_mac (MADDR_ST *addr, MADDR_ST* addrb);
UINT32 mcast_addr_get_mac_suffix(MADDR_ST* addr);
BOOLEAN mcast_is_valid_mask_len (UINT8      mask_len,
                                 MADDR_ST  *addr);
char *mcast_print_addr (MADDR_ST *addr);
char *mcast_print_afi (UINT32 afi);
char *ipaddr_print_str(MADDR_ST *addr);
int mcast_cmp_addr (MADDR_ST *addr1, MADDR_ST *addr2);
BOOLEAN mcast_same_addr (MADDR_ST *addr1, MADDR_ST *addr2);

BOOLEAN mcast_addr_contain(MADDR_ST *subset_address , MADDR_ST *superset_address);
void mcast_addr_init (UINT32 afi);

#endif /* __MCAST_ADDR_H__ */
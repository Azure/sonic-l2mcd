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
#include "mcast_addr.h"
#include "l2mcd_mcast_co.h"

#define MCAST_PRINT_BUF_MAX  10
#define MCAST_PRINT_BUF_SIZE 64
#define MCAST_PRINT_AFI_BUF_SIZE 5
char mcast_addr_buff[MCAST_PRINT_BUF_MAX][MCAST_PRINT_BUF_SIZE];

IP6_IPV6_ADDRESS ip6_unspecified_address = IP6_ADDRESS_UNSPECIFIED_INIT;

void mcast_set_addr (MADDR_ST *to_addr, MADDR_ST *from_addr)
{
	to_addr->afi = from_addr->afi;
	to_addr->plen = from_addr->plen;

	if (from_addr->afi == IP_IPV4_AFI)
	{
		to_addr->ip.v4addr = from_addr->ip.v4addr;
	}
	else
	{
		to_addr->ip.v6addr = from_addr->ip.v6addr;
	}
}

/*
 * Compare addr func returns
 * -1 if addr1 < add2
 *  0 if addr is same
 *  1 if addr1 > addr2
 */
int mcast_cmp_addr (MADDR_ST *addr1, MADDR_ST *addr2)
{
	if (addr1->afi != addr2->afi) 
	{
		//AFI mismatch
		return (-1);
	} 

	if (addr1->afi == IP_IPV4_AFI)
	{              
		if (addr1->ip.v4addr == addr2->ip.v4addr)
		{
			if (addr1->plen == addr2->plen)return (0);
			if (addr1->plen  < addr2->plen) return (-1);
			if (addr1->plen  > addr2->plen) return (1);
		}
		if (addr1->ip.v4addr < addr2->ip.v4addr) return (-1);
		if (addr1->ip.v4addr > addr2->ip.v4addr) return (1);
	} 
	else if (addr1->afi == IP_IPV6_AFI)
	{
		if (IP6_IS_ADDRESS_EQUAL(addr1->ip.v6addr.address, addr2->ip.v6addr.address))
		{
			if (addr1->plen == addr2->plen)                return (0);
			if (addr1->plen  < addr2->plen) return (-1);
			if (addr1->plen  > addr2->plen) return (1);
		}
		if (IP6_IS_ADDRESS_LESS(addr1->ip.v6addr.address, addr2->ip.v6addr.address))
		{
			return (-1);
		}
		if (IP6_IS_ADDRESS_LARGE(addr1->ip.v6addr.address, addr2->ip.v6addr.address)) 
		{
			return (1);
		}
	}

	return (-1);
}

BOOLEAN mcast_is_valid_unicast (MADDR_ST *addr)
{

	if (mcast_addr_is_class_d(addr))
		return (FALSE);

	if (addr->afi == IP_IPV4_AFI)
	{
		return (!IN_BADCLASS(addr->ip.v4addr));
	}
	else
	{
		return (!IP6_IS_ADDRESS_UNSPECIFIED(addr->ip.v6addr.address));
	}
    return (FALSE);
}

char *mcast_print_addr (MADDR_ST *addr)
{
	static int bidx = 0;

	bidx = (bidx + 1) % MCAST_PRINT_BUF_MAX;

	memset(mcast_addr_buff[bidx], 0, MCAST_PRINT_BUF_SIZE);

    if (!addr)
	{
        return("");
	}

	if (mcast_addr_any(addr))
	{
		snprintf(mcast_addr_buff[bidx], MCAST_PRINT_BUF_SIZE, "*");
	}
	else
	{
		switch (addr->afi)
		{	
			case IP_IPV4_AFI:			
				if ((addr->plen == MADDR_GET_FULL_PLEN(addr->afi)) || (addr->plen == 0))
				{
					snprintf(mcast_addr_buff[bidx], MCAST_PRINT_BUF_SIZE, "0x%x", addr->ip.v4addr);
				}
				else
				{
					snprintf(mcast_addr_buff[bidx], MCAST_PRINT_BUF_SIZE, "0x%x/%d", addr->ip.v4addr, addr->plen);					
				}
				break;

			case IP_IPV6_AFI:
                break;

			default:
				snprintf(mcast_addr_buff[bidx], MCAST_PRINT_BUF_SIZE, "-");
				break;
		}			
	}

	return (mcast_addr_buff[bidx]);

}


static char paddrbuf[MCAST_PRINT_BUF_SIZE][MCAST_PRINT_BUF_MAX];
static int idx = 0;
char *ipaddr_print_str(MADDR_ST *addr)
{
    struct sockaddr_in sa;
   	idx = (idx + 1) % MCAST_PRINT_BUF_MAX;
	memset(paddrbuf[idx], 0, MCAST_PRINT_BUF_SIZE);
    sa.sin_addr.s_addr = htonl(addr->ip.v4addr);
    inet_ntop(AF_INET, &(sa.sin_addr), paddrbuf[idx], INET_ADDRSTRLEN);
    return paddrbuf[idx];
}


void mcast_set_addr_any (MADDR_ST *addr)
{
	addr->plen = MADDR_GET_FULL_PLEN(addr->afi);
	
	if (addr->afi == IP_IPV4_AFI) 
	{
		addr->ip.v4addr = 0;
	}
	else if (addr->afi == IP_IPV6_AFI)
	{
		addr->ip.v6addr = ip6_unspecified_address;
	}
	else 
	{	
		//invalid AFI
	}
}

BOOLEAN mcast_addr_any (MADDR_ST *addr)
{
	if (addr->afi == IP_IPV4_AFI)
	{
		return (addr->ip.v4addr == 0);
	}
	else if (addr->afi == IP_IPV6_AFI)
	{
		return (IP6_IS_ADDRESS_UNSPECIFIED(addr->ip.v6addr.address));
	}
	else 
	{
		//invalid AFI
	}

	return (TRUE);
}

void mcast_set_ipv6_addr (MADDR_ST *to_addr, IPV6_ADDRESS *v6_addr)
{
	to_addr->afi = IP_IPV6_AFI;
	to_addr->ip.v6addr = *v6_addr;
	to_addr->plen = MADDR_GET_FULL_PLEN(IP_IPV6_AFI);
}

BOOLEAN mcast_addr_is_class_d (MADDR_ST *addr)
{
	if (addr->afi == IP_IPV4_AFI)
	{
		return (((addr->ip.v4addr >> 28) == 0xe) && ((addr->ip.v4addr & 0x0fffffff) != 0));
	}
	else if (addr->afi == IP_IPV6_AFI)
	{
		return (addr->ip.v6addr.address.address8[0] == 0xff);
	}
	else 
	{
		//invalid AFI
	}

	return (FALSE);
}

void mcast_set_ipv4_addr (MADDR_ST *to_addr, UINT32 v4_addr)
{
	to_addr->afi = IP_IPV4_AFI;
	to_addr->ip.v4addr = v4_addr;	
	to_addr->plen = MADDR_GET_FULL_PLEN(IP_IPV4_AFI);
}

void mcast_init_addr (MADDR_ST *addr, UINT32 afi, UINT32 plen)
{
	addr->afi = afi;
	addr->plen = plen;
}

BOOLEAN mcast_is_valid_grpaddr(MADDR_ST *addr)
{
	if (addr->afi == IP_IPV4_AFI)
	{
		return ((addr->ip.v4addr >= 0xe0000100) && (addr->ip.v4addr <= 0xefffffff));
	}
	else
	{
		return (IP6_IS_MC_ADDRESS_FWDABLE(addr->ip.v6addr.address));
	}
    return (FALSE);
}

void mcast_set_addr_default (MADDR_ST *addr, UINT32 afi)
{
	addr->afi = afi;
	addr->plen = 0;

	if (addr->afi == IP_IPV4_AFI) 
	{
		addr->ip.v4addr = 0;
	}
	else if (addr->afi == IP_IPV6_AFI)
	{
		addr->ip.v6addr = ip6_unspecified_address;
	}
	else 
	{	
		//invalid AFI
	}
}

BOOLEAN mcast_same_addr (MADDR_ST *addr1, MADDR_ST *addr2) 
{
	return (mcast_cmp_addr(addr1, addr2) == 0);
}



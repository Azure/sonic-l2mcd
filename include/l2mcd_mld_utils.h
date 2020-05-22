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
#ifndef __L2MCD_MLD_UTILS__
#define __L2MCD_MLD_UTILS__

#include <netinet/in.h>
#include "l2mcd.h"
#include "l2mcd_data_struct.h"
#include "l2mcd_mcast_co.h"

#define MLD_OK 0
#define MLD_ERROR (-1)
#define MLD_VLAN 0x1
#define MLD_BD 0x3
#define MLD_ROUTE_PORT 0x4
#define MLD_IP_IPV4_AFI 1
#define MLD_IP_IPV6_AFI 2
#define MLD_DEFAULT_VRF_ID    L2MCD_DEFAULT_VRF_IDX
#define MCAST_AFI_MAX L2MCD_AFI_MAX
#define MLD_MAX_VLANS	(8192*2)
#define MLD_CALLOC	calloc
#define MLD_FREE(_param_)  {free(_param_); _param_ = NULL;}
#define MLD_IVID_GVID_MAP_NOT_FOUND -1
#define IGMP_MAX_VLAN_SUPPORT_REACHED 4094
#define MLD_MAX_VLAN_SUPPORT_REACHED 4094
#define MLD_FAIL -1
#define MLD_MAX_VLAN_REACHED -2
#define MLD_VLAN_SNOOP_DISABLED -3
#define MLD_VLAN_FWD_REF -4
#define MLD_SNOOP_DISABLED -5
#define PIMS_ERR_SNOOP_DISABLED -6
#define MLD_PROTO_MROUTER 1
#define MLD_PIM_MROUTER  2

#endif //__L2MCD_MLD_UTILS__

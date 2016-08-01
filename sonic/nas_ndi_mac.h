
/*
 * Copyright (c) 2016 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *  LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */


/*
 * filename: nas_ndi_mac.h
 */

#ifndef NAS_NDI_MAC_H_
#define NAS_NDI_MAC_H_

#include "std_error_codes.h"
#include "ds_common_types.h"
#include "nas_ndi_common.h"
#include "dell-base-l2-mac.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup NDI API - MAC Functionality
 *
 *  \{
 */

/*
 * Attribute flags for mac entry related info
 *
 * Contains different attribute flags
 *
 */
typedef enum {
    NDI_MAC_ENTRY_ATTR_TYPE        = 1,     /* static/dynamic */
    NDI_MAC_ENTRY_ATTR_PORT_ID,             /* port id */
    NDI_MAC_ENTRY_ATTR_PKT_ACTION,          /* packet action */
    NDI_MAC_ENTRY_ATTR_MAX
} ndi_mac_attr_flags;

/*
 * L2 MAC entry
 *
 * Contains details of signle mac entry
 *
 */

typedef struct ndi_mac_entry_s {
    npu_id_t                    npu_id;     /* NPU ID */
    hal_vlan_id_t               vlan_id;    /* VLAN ID */
    ndi_port_t                  port_info;  /* NDI port (npu/local port) */
    hal_mac_addr_t              mac_addr;   /* MAC address */
    bool                        is_static;  /* Flag to determine static/dynamic */
    BASE_MAC_PACKET_ACTION_t    action;     /* Packet action */
    ndi_mac_attr_flags          attr_flag;  /* Attribute flag */
    uint64_t                    ndi_lag_id; /* In case of lag, ndi lag id is used by mac
                                             * to decode the ifindex */
} ndi_mac_entry_t;

/*
 * Attribute flag for MAC entry delete
 *
 * Contains various types of MAC entry delete
 *
 */
typedef enum {
    NDI_MAC_DEL_SINGLE_ENTRY    = 1,    /* Delete single entry */
    NDI_MAC_DEL_BY_PORT,                /* Delete all the entries by port */
    NDI_MAC_DEL_BY_VLAN,                /* Delete all the entries by vlan */
    NDI_MAC_DEL_BY_PORT_VLAN,           /* Delete all the entries by port/vlan combination */
    NDI_MAC_DEL_ALL_ENTRIES,            /* Delete all the entries */
    NDI_MAC_DEL_INVALID_TYPE
} ndi_mac_delete_type_t;

/*
 * Attribute flag for MAC entry change event
 *
 * Contains MAC entry change event details, depending on this uppper layer
 * will update the cache
 *
 */
typedef enum {
    NDI_MAC_EVENT_LEARNED   = 1,    /* New MAC entry learned */
    NDI_MAC_EVENT_AGED,             /* MAC entry aged */
    NDI_MAC_EVENT_FLUSHED,          /* MAC entry removed */
    NDI_MAC_EVENT_INVALID
} ndi_mac_event_type_t;

/**
 * @brief Add a MAC entry into the MAC Table
 *
 * @param entry - MAC entry to be configured
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_create_mac_entry(ndi_mac_entry_t *entry);
t_std_error ndi_update_mac_entry(ndi_mac_entry_t *p_mac_entry, ndi_mac_attr_flags attr_changed);

/**
 * @brief Delete MAC entry/entries from the MAC Table based on delete_type flag
 *
 * @param entry - entry to be deleted. delete_flag will determine which
 *                elements of this structure to be considered
 *                e.g.
 *                for SINGLE_ENTRY, all the fields within entry should be considered.
 *                for ALL_ENTRIES, this param is ignored.
 *
 * @param delete_type - flag to indicate the type (single/port/port-vlan/vlan/all)
 *
 * @param type_set - flag to indicate whether all entries needs to be flushed under the type.
 *                   If this is not set all entries(static/dynamic) should be flushed.
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_delete_mac_entry(ndi_mac_entry_t *entry, ndi_mac_delete_type_t delete_type, bool type_set);

/**
 * @brief   MAC event notification callback function type
 * @param   npu_id NPU ID
 * @param   ndi_mac_event_type_t event type
 * @param   ndi_mac_entry_t mac entry details
 * @return  None
 */
typedef void (*ndi_mac_event_notification_fn) (npu_id_t npu_id, ndi_mac_event_type_t mac_event, ndi_mac_entry_t *mac_entry, bool is_lag_index);

/**
 * @brief This function is used to register the callback function for MAC event notification with NDI
 *
 * @param reg_fn - Callback function for MAC event notification
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_mac_event_notify_register(ndi_mac_event_notification_fn reg_fn);

/**
 * @brief Retrieve the MAC entry
 *
 * @param mac_entry - Caller to fill up the mandatory fields into this entry
 *                    i.e. npu_id, vlan_id, mac_addr
 *                    This entry will be filled up with further details after successful execution
 *                    i.e. port_id, action, is_static
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_get_mac_entry_attr(ndi_mac_entry_t *mac_entry);


/**
 * @brief Set MAC entry
 *
 * @param mac_entry - entry to be set
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_set_mac_entry_attr(ndi_mac_entry_t *mac_entry);

/**
 *  \}
 */
#ifdef __cplusplus
}
#endif
#endif /* NAS_NDI_MAC_H_ */

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
#include <string.h>
#include <errno.h>
#include <system_error>
#include <sys/socket.h>
//#include <linux/if.h>
#include <chrono>
#include <string>
#include "dbconnector.h"
#include "producerstatetable.h"
#include "l2mcd.h"
#include "l2mcd_sync.h"
#include <algorithm> 
#include "debugframework.h"
#include "notificationproducer.h"

#define STATE_L2MC_MROUTER_TABLE_NAME   "L2MC_STATE_MROUTER_TABLE"

using namespace std;
using namespace swss;

void l2mcd_debugCLI(std::string s, KeyOpFieldsValuesTuple t);
string g_L2McdCompstring = "l2mcd_debug";

L2mcSync::L2mcSync(DBConnector *db, DBConnector *cfgDb, DBConnector *stateDb) :
    m_l2mcdAppVlanTable(db, APP_L2MC_VLAN_TABLE_NAME),
    m_l2mcdEntryTable(db,  APP_L2MC_MEMBER_TABLE_NAME),
    m_l2mcdMrouterTable(db, APP_L2MC_MROUTER_TABLE_NAME),
    m_statel2mcdLocalMemberTable(stateDb, STATE_L2MC_MEMBER_TABLE_NAME),
    m_statel2mcdLocalMrouterTable(stateDb, STATE_L2MC_MROUTER_TABLE_NAME)
{
    SWSS_LOG_NOTICE("L2MCD: sync object");
    l2mc_entry_notifications = new swss::NotificationProducer(db, "L2MC_NOTIFICATIONS");
    l2mc_mrouter_notifications = new swss::NotificationProducer(db, "L2MC_MROUTER_NOTIFICATIONS");
    m_mclagTable = std::unique_ptr<Table>(new Table(cfgDb, CFG_MCLAG_TABLE_NAME ));


}

DBConnector db(APPL_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);
DBConnector cfgDb(CONFIG_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);
DBConnector stateDb(STATE_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);
L2mcSync l2mcsync(&db, &cfgDb, &stateDb);
extern "C" void l2mcd_dump_vdb_brief(int id);
extern "C" void l2mcd_dump_vdb_stats(int id);
extern "C" void l2mcd_dump_portdb(void);
extern "C" void l2mcd_dump_groups(int id, int flag);
extern "C" void l2mcd_print_vars(void);
extern "C" void l2mcd_set_loglevel_w(int level);
extern "C" void l2mcd_dump_vdb_ports(int vid);
extern "C" void l2mcd_dump_ve_portdb_tree(void);
extern "C" void l2mcd_dump_port_vlan_bm(void);
extern "C" int l2mcd_is_peerlink(char *portname);

extern "C" {

    void l2mcsync_init_debug_framework()
    {
        l2mcsync.initDebugFrameWork();
    }
    void l2mcsync_add_vlan_entry(uint16_t vlan_id)
    {
        l2mcsync.addL2mcVlanEntry(vlan_id);
    }
    int l2mcdsync_get_l2mcmgr_debug_prio()
    {
        return l2mcsync.getL2mcMgrDebugPrio();
    }  
    void l2mcsync_del_vlan_entry(uint16_t vlan_id)
    {
        l2mcsync.delL2mcVlanEntry(vlan_id);
    }
    void l2mcsync_add_l2mc_entry(L2MCD_APP_TABLE_ENTRY *msg)
    {
        l2mcsync.addL2mcTableEntry(msg);
    }
    void l2mcsync_del_l2mc_entry(L2MCD_APP_TABLE_ENTRY *msg)
    {
        l2mcsync.delL2mcTableEntry(msg);
    }
    void l2mcsync_process_mrouterentry(L2MCD_APP_TABLE_ENTRY *msg)
    {
        l2mcsync.processL2mcMrouterTableEntry(msg);
    }
    void l2mcsync_debug_print(const char *fmt, ...)
    {
        char dump_str[200];
        va_list args;
        va_start(args,fmt);
        vsnprintf(dump_str, 200, fmt, args);
        va_end(args);
        SWSS_DEBUG_PRINT(g_L2McdCompstring,"%s", dump_str );
    }
    int l2mcd_is_peerlink(char *portname)
    {
        return l2mcsync.isPortPeerLink(portname);
    }
}

int L2mcSync::getL2mcMgrDebugPrio(void)
{
    return (swss::Logger::getInstance().getMinPrio());
}
void L2mcSync::addL2mcVlanEntry(uint16_t vlan_id)
{
    std::vector<FieldValueTuple> fvVector;
    string vlan;

    vlan = VLAN_PREFIX + to_string(vlan_id);
    FieldValueTuple s("id", to_string(vlan_id));
    fvVector.push_back(s);
    m_l2mcdAppVlanTable.set(vlan, fvVector);
    SWSS_LOG_NOTICE("APP_L2MC_VLAN_TABLE Add %s to L2MC ", vlan.c_str());
}

void L2mcSync::delL2mcVlanEntry(uint16_t vlan_id)
{
    string vlan;

    vlan = VLAN_PREFIX + to_string(vlan_id);
    m_l2mcdAppVlanTable.del(vlan);

    SWSS_LOG_NOTICE("APP_L2MC_VLAN_TABLE Delete %s from L2MC ", vlan.c_str());
}
void L2mcSync::addL2mcTableEntry(L2MCD_APP_TABLE_ENTRY *msg)
{
    string key;
    string stateKey;
    string type = "dynamic";
    std::vector<FieldValueTuple> fvVector;
    std::vector<FieldValueTuple> fvVector1;
    std::vector<swss::FieldValueTuple> entry;

    key = VLAN_PREFIX + to_string(msg->vlan_id)+L2MCD_DEFAULT_KEY_SEPARATOR;
    key.append(msg->saddr);
    key.append(L2MCD_DEFAULT_KEY_SEPARATOR);
    key.append(msg->gaddr);
    key.append(L2MCD_DEFAULT_KEY_SEPARATOR);
    key.append(msg->ports[0].pnames);
    stateKey = VLAN_PREFIX + to_string(msg->vlan_id)+L2MCD_STATE_KEY_SEPARATOR;
    stateKey.append(msg->saddr);
    stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
    stateKey.append(msg->gaddr);
    stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
    stateKey.append(msg->ports[0].pnames);

    if(msg->is_static) type.assign("static");
    if(msg->is_remote) type.assign("remote");
    FieldValueTuple s("type", type.c_str());
    fvVector.push_back(s);
    if (!msg->op_code)
    {
        SWSS_LOG_NOTICE("APP_L2MC_ENTRY_TABLE Group-DEL key:%s vid:%d G:%s sa:%s port %s static:%d is_remote:%d ", key.c_str(), msg->vlan_id, msg->gaddr, msg->saddr, msg->ports[0].pnames, msg->is_static,msg->is_remote);
        m_l2mcdEntryTable.del(key);
        if (!m_statel2mcdLocalMemberTable.get(stateKey, fvVector1))
        {
            SWSS_LOG_NOTICE("STATE_L2MC_ENTRY_TABLE Group-DEL key:%s vid:%d G:%s sa:%s port %s static:%d Not Exists ", key.c_str(), msg->vlan_id, msg->gaddr, msg->saddr, msg->ports[0].pnames, msg->is_static);
            return;
        }
        m_statel2mcdLocalMemberTable.del(stateKey);

        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->is_static)
            stateKey.append("static");
        else
            stateKey.append("dynamic");
        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->port_oper)
            stateKey.append("LEAVE");
        l2mc_entry_notifications->send("DEL", stateKey, entry);
    }
    else
    {
        SWSS_LOG_NOTICE("APP_L2MC_ENTRY_TABLE Group-ADD key:%s vid:%d G:%s sa:%s port %s static:%d,is_remote:%d  ", key.c_str(), msg->vlan_id, msg->gaddr, msg->saddr, msg->ports[0].pnames, msg->is_static, msg->is_remote);
        m_l2mcdEntryTable.set(key,fvVector);
        if (m_statel2mcdLocalMemberTable.get(stateKey, fvVector1))
        {
            SWSS_LOG_NOTICE("STATE_L2MC_ENTRY_TABLE Group-ADD key:%s vid:%d G:%s sa:%s port %s static:%d Exists ", key.c_str(), msg->vlan_id, msg->gaddr, msg->saddr, msg->ports[0].pnames, msg->is_static);
            return;
        }
        m_statel2mcdLocalMemberTable.set(stateKey, fvVector);

        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->is_static)
            stateKey.append("static");
        else
            stateKey.append("dynamic");
        l2mc_entry_notifications->send("SET", stateKey, entry);
    }

}

void L2mcSync::delL2mcTableEntry(L2MCD_APP_TABLE_ENTRY *msg)
{
    string key;
    key = VLAN_PREFIX + to_string(msg->vlan_id) +  L2MCD_DEFAULT_KEY_SEPARATOR + "*"+L2MCD_DEFAULT_KEY_SEPARATOR;
    key +=msg->gaddr;
    SWSS_LOG_NOTICE("APP_L2MC_ENTRY_TABLE Group delete vid:%d G:%s ", msg->vlan_id, msg->gaddr);
    m_l2mcdEntryTable.del(key);

}

void L2mcSync::processL2mcMrouterTableEntry(L2MCD_APP_TABLE_ENTRY *msg)
{
    string key;
    string stateKey;
    string type = "dynamic";
    std::vector<FieldValueTuple> fvVector;
    std::vector<FieldValueTuple> fvVector1;
    std::vector<swss::FieldValueTuple> entry;

    key = VLAN_PREFIX + to_string(msg->vlan_id)+L2MCD_DEFAULT_KEY_SEPARATOR;
    key.append(msg->ports[0].pnames);

    stateKey = VLAN_PREFIX + to_string(msg->vlan_id)+L2MCD_STATE_KEY_SEPARATOR;
    stateKey.append(msg->ports[0].pnames);
    
    if(msg->is_static) type.assign("static");
    FieldValueTuple s("type", type.c_str());
    fvVector.push_back(s);

    if (msg->op_code)
    {
        SWSS_LOG_NOTICE("APP_L2MC_MROUTER_TABLE:Key:%s stateKey:%s Vlan%d:%s mrouter add",key.c_str(), stateKey.c_str(),
                msg->vlan_id, msg->ports[0].pnames);
        m_l2mcdMrouterTable.set(key,fvVector);
        if (m_statel2mcdLocalMrouterTable.get(stateKey, fvVector1))
        {
            SWSS_LOG_NOTICE("STATE_L2MC_MROUTER_TABLE Mroute port Add key:%s vid:%d port %s static:%d Exists ", stateKey.c_str(), 
                    msg->vlan_id, msg->ports[0].pnames, msg->is_static);
            return;
        }
        m_statel2mcdLocalMrouterTable.set(stateKey, fvVector);
        
        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->is_static)
            stateKey.append("static");
        else
            stateKey.append("dynamic");
        l2mc_mrouter_notifications->send("SET", stateKey, entry);
    }
    else
    {
        m_l2mcdMrouterTable.del(key);
        SWSS_LOG_NOTICE("APP_L2MC_MROUTER_TABLE:Key:%s stateKey:%s Vlan%d:%s mrouter entry deleted", key.c_str(),
                stateKey.c_str(), msg->vlan_id, msg->ports[0].pnames);

        if (!m_statel2mcdLocalMrouterTable.get(stateKey, fvVector1))
        {
            SWSS_LOG_NOTICE("STATE_L2MC_MROUTER_TABLE Mroute port DEL key:%s vid:%d port %s static:%d Not Exists ", stateKey.c_str(), 
                    msg->vlan_id, msg->ports[0].pnames, msg->is_static);
            return;
        }
        m_statel2mcdLocalMrouterTable.del(stateKey);

        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->is_static)
            stateKey.append("static");
        else
            stateKey.append("dynamic");
        
        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->port_oper)
            stateKey.append("LEAVE");
        l2mc_mrouter_notifications->send("DEL", stateKey, entry);
    }
}

void L2mcSync::initDebugFrameWork(void)
{
    Debugframework::linkWithFramework(g_L2McdCompstring, l2mcd_debugCLI);
    SWSS_LOG_NOTICE("Initialized Debug Frame work for L2MCD");    

}

void l2mcd_debugCLI(std::string s, KeyOpFieldsValuesTuple t)
{
     string group = "dumpall";
     string keywd = kfvKey(t);
     string vid;
     string levelString;
     int vlan_id=0,level=0;
     int i=0;
     SWSS_LOG_NOTICE("L2MCD: Debug CLI key-%s",keywd.c_str());
    
     if (keywd != g_L2McdCompstring)
     {
         SWSS_LOG_NOTICE("Keywd wrong %s", keywd.c_str());
         return;
     }
    g_l2mcd_fwk_dbg_mode = 1;
    SWSS_DEBUG_PRINT_BEGIN(g_L2McdCompstring);

    for (auto i : kfvFieldsValues(t))
     {
         if (fvField(i) == "group")
         {
            group = fvValue(i);
         }
         else if (fvField(i) == "vid")
         {
            vid = fvValue(i);
            vlan_id = stoi(vid.c_str());
         }
         else if (fvField(i) == "level")
         {
            levelString = fvValue(i);
            level = stoi(levelString.c_str());
         }
         else
         {
            string field = fvField(i);
            string value = fvValue(i);
            SWSS_DEBUG_PRINT(g_L2McdCompstring, "L2MCD: Rcvd field %s, Value %s", field.c_str(),value.c_str());
         }
     
     }

     if (group =="vdb")
     {
         l2mcd_dump_vdb_brief(vlan_id);
     }
     else if (group =="vdb_stats")
     {
         l2mcd_dump_vdb_stats(vlan_id);
     }
     else if (group =="igmp_groups")
     {
         l2mcd_dump_groups(vlan_id, 0);
     }
     else if (group == "ports")
     {
         l2mcd_dump_portdb();
     }
     else if (group == "global")
     {
         l2mcd_print_vars();
     }
     else if (group == "dumpall")
     {
         l2mcd_print_vars();
         l2mcd_dump_portdb();
         l2mcd_dump_vdb_brief(0);
         l2mcd_dump_vdb_stats(0);
         l2mcd_dump_groups(0,1);
         l2mcd_dump_vdb_ports(0);
         l2mcd_dump_ve_portdb_tree();
         l2mcd_dump_port_vlan_bm();
     }
     else if (group == "vlanLog")
     {
        g_l2mcd_vlan_dbg_to_sys_log=TRUE;
        if (level)
        {
            g_l2mcd_vlan_log_mask=level;
        }
        if (!vlan_id) 
        {
            memset(&g_l2mcd_pkt_log[0], 0, L2MCD_VLAN_MAX);
            g_l2mcd_vlan_dbg_to_sys_log = FALSE;
            L2MCD_CLI_PRINT("Disable Vlan sys logging for all tags global_level_mask:%x",g_l2mcd_vlan_log_mask);
        }
        else if (vlan_id==L2MCD_VLAN_MAX)
        {
            memset(&g_l2mcd_pkt_log[0],1, L2MCD_VLAN_MAX);
            L2MCD_CLI_PRINT("Enable Vlan sys logging for all tags global_level_maskk:%x",g_l2mcd_vlan_log_mask);
            g_l2mcd_dbg_vlan_log_all=TRUE;
        }
        else 
        {
            g_l2mcd_pkt_log[vlan_id&0xFFF]= level?1:0;
            L2MCD_CLI_PRINT("vlan logging %s for vid:%d global_level_mask:0x%x",level?"Enabled":"Disabled",vlan_id,g_l2mcd_vlan_log_mask);
        }
        g_l2mcd_dbg_vlan_log_all=TRUE;
        for (i=0;i<L2MCD_VLAN_MAX;i++) g_l2mcd_dbg_vlan_log_all &= g_l2mcd_pkt_log[i];
     }
     else if (group == "dbgLevel")
     {
        l2mcd_set_loglevel_w(level);

     }
     SWSS_LOG_NOTICE(" l2mcd debug command:  group:%s vid %s(%d) global_level_mask:%d, g_l2mcd_dbg_vlan_log_all:%d", group.c_str(), vid.c_str(), vlan_id,g_l2mcd_vlan_log_mask,g_l2mcd_dbg_vlan_log_all);
     SWSS_DEBUG_PRINT_END(g_L2McdCompstring);
     g_l2mcd_fwk_dbg_mode=0;
}

bool L2mcSync::isPortPeerLink(std::string portname)
{
    std::vector<std::string> keys;
    std::string peerlink;

    m_mclagTable->getKeys(keys);    
    if (keys.empty()) {
        return 0;
    }
    for (auto &k : keys) {
        m_mclagTable->hget(k, "peer_link", peerlink);
        if (portname == peerlink)
            return 1;
    }
    return 0;
}

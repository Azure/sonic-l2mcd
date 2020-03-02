INCLUDES = -I $(top_srcdir) -I $(top_srcdir)/include -I ./include

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = l2mcd
bin_PROGRAMS +=l2mcd_ctl
SUBDIRS=include
#if DEBUG
#DBGFLAGS = -ggdb -DDEBUG
#else
#DBGFLAGS = -g
#endif

AC_PROG_CC = gcc

AM_CFLAGS = -DDEBUG -DBRCD_DCE_L3_PORT -DBRCD_DCE_L3_PIM_PORT -DBRCD_DCE_L36_PIM -DBRCD_DCE_IPV6 -DBRCD_LIB_MLD_DCE_PORT -DBRCD_DCE_SHARED_RIB -DBRCD_DCE_NEW_RIB -DSR_SWITCH_ROUTER -D__NO_IPSEC__ -D__MP__ -D__IPV6__ -DBRCD_DCE_L3V6_PORT -DBRCD_DCE_MLD_PORT -D__FOUNDRY_BGP__ -D__PIM__ 

l2mcd_SOURCES = \
                 l2mcd_main.cpp \
                 l2mcd_sync.cpp \
                 common/applog.c \
                 common/malloc_stubs.c \
                 common/hash_grow_generic.c \
                 common/wheel_timer.c \
                 common/avl.c \
                 common/timer_api.c \
                 common/linklist_api.c \
                 common/l2mcd_mcast_port.c \
                 common/l2mcd_data_struct.c \
                 common/l2mcd_mcast_addr.c \
                 port/main.c \
                 port/l2mcd_cli.c \
                 port/l2mcd_system.c \
                 port/l2mcd_utils.c \
                 port/l2mcd_portdb.c \
                 port/l2mcd_mld_mcast.c \
                 port/mld_pkt.c \
                 port/l2mcd_mld_pim_snoop.c \
                 port/mld_vdb.c \
                 port/l2mcd_mld_port.c \
                 port/l2mcd_mld_utils.c \
                 src/igmp.c \
                 src/igmp_cu.c \
                 src/igmp_fsm.c \
                 src/igmp_io.c \
                 src/mld_main.c

l2mcd_CFLAGS = $(DBGFLAGS) $(AM_CFLAGS) $(CFLAGS_COMMON) 
l2mcd_CPPFLAGS = $(DBGFLAGS) $(AM_CFLAGS) $(CFLAGS_COMMON) $(COV_CFLAGS) $(ASAN_CFLAGS)
l2mcd_LDADD = -lhiredis /usr/lib/x86_64-linux-gnu/libevent.a -lswsscommon  $(COV_LDFLAGS) $(ASAN_LDFLAGS)


l2mcd_ctl_SOURCES = \
                l2mcd_ctl.c

l2mcd_ctl_CFLAGS = $(DBGFLAGS) $(AM_CFLAGS) $(CFLAGS_COMMON)
l2mcd_ctl_CPPFLAGS = $(DBGFLAGS) $(AM_CFLAGS) $(CFLAGS_COMMON) $(COV_CFLAGS) $(ASAN_CFLAGS)
l2mcd_ctl_LDADD = -lhiredis /usr/lib/x86_64-linux-gnu/libevent.a -lswsscommon $(COV_LDFLAGS) $(ASAN_LDFLAGS)

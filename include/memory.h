/* Memory management routine
   Copyright (C) 1998 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _ZEBRA_MEMORY_H
#define _ZEBRA_MEMORY_H
#include <stddef.h>

#define array_size(ar) (sizeof(ar) / sizeof(ar[0]))

/* For pretty printing of memory allocate information. */
struct memory_list
{
  int index;
  const char *format;
};

struct mlist {
  struct memory_list *list;
  const char *name;
};
 
enum
{
  MTYPE_LINK_LIST=4,
  MTYPE_LINK_NODE=5,
  MTYPE_MAX,
};


extern struct mlist mlists[];
#define XMALLOC(mtype, size)       zmalloc ((mtype), (size))
#define XCALLOC(mtype, size)       zcalloc ((mtype), (size))
#define XREALLOC(mtype, ptr, size) zrealloc ((mtype), (ptr), (size))
#define XFREE(mtype, ptr)          do { \
                                     zfree ((mtype), (ptr)); \
                                     ptr = NULL; } \
                                   while (0)
#define XSTRDUP(mtype, str)        zstrdup ((mtype), (str))


/* Prototypes of memory function. */
extern void *zmalloc (int type, size_t size);
extern void *zcalloc (int type, size_t size);
extern void *zrealloc (int type, void *ptr, size_t size);
extern void  zfree (int type, void *ptr);
extern char *zstrdup (int type, const char *str);

extern void *mtype_zmalloc (const char *file, int line, int type, size_t size);

extern void *mtype_zcalloc (const char *file, int line, int type, size_t size);

extern void *mtype_zrealloc (const char *file, int line, int type, void *ptr,
		             size_t size);

extern void mtype_zfree (const char *file, int line, int type,
		         void *ptr);

extern char *mtype_zstrdup (const char *file, int line, int type,
		            const char *str);
extern void memory_init (void);
extern void log_memstats_stderr (const char *);

/* return number of allocations outstanding for the type */
extern unsigned long mtype_stats_alloc (int);

/* Human friendly string for given byte count */
#define MTYPE_MEMSTR_LEN 20
extern const char *mtype_memstr (char *, size_t, unsigned long);
#endif /* _ZEBRA_MEMORY_H */

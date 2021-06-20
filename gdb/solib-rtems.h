/* Handle shared libraries for GDB, the GNU Debugger.

   Copyright (C) 2021 Hesham Almatary.
   Copyright (C) 2000-2019 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef SOLIB_RTEMS_H
#define SOLIB_RTEMS_H

#include "solist.h"

struct objfile;
struct target_so_ops;

extern struct target_so_ops rtems_so_ops;

/* Link map info to include in an allocated so_list entry.  */

/* Critical offsets and sizes which describe struct r_debug and
   struct link_map on RTEMS targets.  All offsets and sizes are
   in bytes unless otherwise specified.  */

struct link_map_offsets
  {
    /* Offset and size of r_debug.r_version.  */
    int r_version_offset, r_version_size;
    int r_map_offset;
    int link_map_size;
    int l_type_offset;
    int l_name_offset;
    int l_sec_num_offset;
    int l_sec_detail_offset;
    int l_base_sec_addr_offset;
    int l_rpathlen_offset;
    int l_rpath_offset;
    int l_next_offset;
    int l_prev_offset;
    int sec_map_size;
    int s_name_offset;
    int s_addr_offset;
    int s_size_offset;
    int s_rap_id_offset;
  };

/* set_solib_rtems_fetch_link_map_offsets() is intended to be called by
   a <arch>_gdbarch_init() function.  It is used to establish an
   architecture specific link_map_offsets fetcher for the architecture
   being defined.  */

extern void set_solib_rtems_fetch_link_map_offsets
  (struct gdbarch *gdbarch, struct link_map_offsets *(*func) (void));

/* This function is called by thread_db.c.  Return the address of the
   link map for the given objfile.  */
extern CORE_ADDR rtems_fetch_objfile_link_map (struct objfile *objfile);

/* Fetch (and possibly build) an appropriate `struct link_map_offsets'
   for ILP32, LP64, and CHERI 64/128 RTEMS systems.  */
extern struct link_map_offsets *rtems_ilp32_fetch_link_map_offsets (void);
extern struct link_map_offsets *rtems_lp64_fetch_link_map_offsets (void);
extern struct link_map_offsets *rtems_c64_fetch_link_map_offsets (void);
extern struct link_map_offsets *rtems_c128_fetch_link_map_offsets (void);

#endif /* solib-rtems.h */

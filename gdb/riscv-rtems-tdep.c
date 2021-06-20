/* Target-dependent code for GNU/Linux SPARC.

   Copyright (C) 2021 Hesham Almatary.
   Copyright (C) 2003-2013 Free Software Foundation, Inc.

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

#include "defs.h"
#include "dwarf2-frame.h"
#include "frame.h"
#include "frame-unwind.h"
#include "gdbtypes.h"
#include "regset.h"
#include "gdbarch.h"
#include "gdbcore.h"
#include "osabi.h"
#include "regcache.h"
#include "solib-rtems.h"
#include "symtab.h"
#include "trad-frame.h"
#include "tramp-frame.h"
#include "xml-syscall.h"
#include "linux-tdep.h"

/* The syscall's XML filename for riscv.  */
#define XML_SYSCALL_FILENAME_SPARC32 "syscalls/riscv-linux.xml"

#include "riscv-tdep.h"

static void
riscv_rtems_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  set_solib_rtems_fetch_link_map_offsets
    (gdbarch, (riscv_abi_clen (gdbarch) == 16
           ? rtems_c128_fetch_link_map_offsets
           : (riscv_abi_clen (gdbarch) == 8
             ? rtems_c64_fetch_link_map_offsets
             : (riscv_isa_xlen (gdbarch) == 4
               ? rtems_ilp32_fetch_link_map_offsets
               : rtems_lp64_fetch_link_map_offsets))));

  set_solib_rtems_fetch_link_map_offsets
    (gdbarch, rtems_c128_fetch_link_map_offsets);
}

/* Provide a prototype to silence -Wmissing-prototypes.  */
extern void _initialize_riscv_rtems_tdep (void);

void
_initialize_riscv_rtems_tdep (void)
{
  gdbarch_register_osabi (bfd_arch_riscv, 0, GDB_OSABI_RTEMS,
                          riscv_rtems_init_abi);
}

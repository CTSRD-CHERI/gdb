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

/* Implement the "init" method of struct tramp_frame.  */
static void
riscv_cherifreertos_tramp_init (const struct tramp_frame *self,
              struct frame_info *this_frame,
              struct trad_frame_cache *this_cache,
              CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR frame_sp = get_frame_sp (this_frame);
  int clen = riscv_abi_clen (gdbarch);

  CORE_ADDR mcontext_addr
    = (frame_sp + clen * 13);

  trad_frame_set_reg_addr(this_cache, RISCV_CFP_REGNUM, mcontext_addr);
  trad_frame_set_reg_value (this_cache, RISCV_CSP_REGNUM, frame_sp + clen * 15);
  trad_frame_set_reg_addr(this_cache, RISCV_PCC_REGNUM, mcontext_addr + 1 * clen);

  trad_frame_set_id (this_cache, frame_id_build (frame_sp, func));
}

static const struct tramp_frame riscv_cherifreertos_intercompartment_tramp  =
{
  NORMAL_FRAME,
  2,
  {
    { 0x9302, ULONGEST_MAX },
    { 0x7e73, ULONGEST_MAX },
    { 0x3004, ULONGEST_MAX },
    { 0x035b, ULONGEST_MAX },
    { 0x03e0, ULONGEST_MAX },
    {TRAMP_SENTINEL_INSN, ULONGEST_MAX}
  },
  riscv_cherifreertos_tramp_init
};

static const struct tramp_frame riscv_cherifreertos_intracompartment_tramp =
{
  NORMAL_FRAME,
  4,
  {
    { 0xfec300db, ULONGEST_MAX },
    { 0x0d01240f, ULONGEST_MAX },
    {TRAMP_SENTINEL_INSN, ULONGEST_MAX}
  },
  riscv_cherifreertos_tramp_init
};

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

  if (riscv_abi_clen (gdbarch) == 16) {
    tramp_frame_prepend_unwinder (gdbarch, &riscv_cherifreertos_intercompartment_tramp);
    //tramp_frame_prepend_unwinder (gdbarch, &riscv_cherifreertos_intracompartment_tramp);
  } else if (riscv_abi_clen (gdbarch) == 8) {
    tramp_frame_prepend_unwinder (gdbarch, &riscv_cherifreertos_intercompartment_tramp);
  } else if (riscv_isa_xlen (gdbarch) == 4) {
    // TODO
  } else {
    // TODO
  }
}

/* Provide a prototype to silence -Wmissing-prototypes.  */
extern void _initialize_riscv_rtems_tdep (void);

void
_initialize_riscv_rtems_tdep (void)
{
  gdbarch_register_osabi (bfd_arch_riscv, 0, GDB_OSABI_RTEMS,
                          riscv_rtems_init_abi);
}

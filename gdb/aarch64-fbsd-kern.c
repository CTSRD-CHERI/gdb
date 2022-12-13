/*-
 * Copyright (c) 2017 John Baldwin <jhb@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Target-dependent code for FreeBSD/aarch64 kernels.  */

#include "defs.h"

#include "aarch64-tdep.h"
#include "frame-unwind.h"
#include "gdbarch.h"
#include "gdbcore.h"
#include "osabi.h"
#include "regcache.h"
#include "regset.h"
#include "solib.h"
#include "target.h"
#include "trad-frame.h"

#include "kgdb.h"

struct aarch64_fbsd_kern_info
{
  LONGEST osreldate = 0;
};

/* Per-program-space data key.  */
static const registry<program_space>::key<aarch64_fbsd_kern_info>
aarch64_fbsd_kern_pspace_data;

/* Get the current aarch64_fbsd_kern data.  If none is found yet, add it
   now.  This function always returns a valid object.  */

static struct aarch64_fbsd_kern_info *
get_aarch64_fbsd_kern_info (void)
{
  struct aarch64_fbsd_kern_info *info;

  info = aarch64_fbsd_kern_pspace_data.get (current_program_space);
  if (info != nullptr)
    return info;

  info = aarch64_fbsd_kern_pspace_data.emplace (current_program_space);
  info->osreldate = parse_and_eval_long ("osreldate");
  return info;
}

static const struct regcache_map_entry aarch64_fbsd_pcbmap[] =
  {
    { 11, AARCH64_X0_REGNUM + 19, 8 }, /* x19 ... x29 */
    { 1, AARCH64_PC_REGNUM, 8 },
    { 1, AARCH64_SP_REGNUM, 8 },
    { 0 }
  };

static const struct regset aarch64_fbsd_pcbregset =
  {
    aarch64_fbsd_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static const struct regcache_map_entry aarch64_fbsd_pcbmap_cheri[] =
  {
    { 11, AARCH64_C0_REGNUM(0) + 19, 16 }, /* c19 ... c29 */
    { 1, AARCH64_PCC_REGNUM(0), 16 },
    { 1, AARCH64_CSP_REGNUM(0), 16 },
    { 0 }
  };

static const struct regset aarch64_fbsd_pcbregset_cheri =
  {
    aarch64_fbsd_pcbmap_cheri,
    regcache_supply_regset, regcache_collect_regset
  };

static const struct regcache_map_entry aarch64_fbsd_pcbmap_cheri_alias[] =
  {
    { 11, AARCH64_X0_REGNUM + 19, 16 }, /* x19 ... x29 */
    { 1, AARCH64_PC_REGNUM, 16 },
    { 1, AARCH64_SP_REGNUM, 16 },
    { 0 }
  };

static const struct regset aarch64_fbsd_pcbregset_cheri_alias =
  {
    aarch64_fbsd_pcbmap_cheri_alias,
    regcache_supply_regset, regcache_collect_regset
  };

/* In kernels prior to __FreeBSD_version 1400084, struct pcb used an
   alternate layout.  */

static const struct regcache_map_entry aarch64_fbsd13_pcbmap[] =
  {
    { 30, AARCH64_X0_REGNUM, 8 }, /* x0 ... x29 */
    { 1, AARCH64_PC_REGNUM, 8 },
    { 1, REGCACHE_MAP_SKIP, 8 },
    { 1, AARCH64_SP_REGNUM, 8 },
    { 0 }
  };

static const struct regset aarch64_fbsd13_pcbregset =
  {
    aarch64_fbsd13_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static const struct regcache_map_entry aarch64_fbsd13_pcbmap_cheri[] =
  {
    { 30, AARCH64_C0_REGNUM(0), 16 }, /* c0 ... c29 */
    { 1, AARCH64_PCC_REGNUM(0), 16 },
    { 1, REGCACHE_MAP_SKIP, 16 },
    { 1, AARCH64_CSP_REGNUM(0), 16 },
    { 0 }
  };

static const struct regset aarch64_fbsd13_pcbregset_cheri =
  {
    aarch64_fbsd13_pcbmap_cheri,
    regcache_supply_regset, regcache_collect_regset
  };

static const struct regcache_map_entry aarch64_fbsd13_pcbmap_cheri_alias[] =
  {
    { 30, AARCH64_X0_REGNUM, 16 }, /* x0 ... x29 */
    { 1, AARCH64_PC_REGNUM, 16 },
    { 1, REGCACHE_MAP_SKIP, 16 },
    { 1, AARCH64_SP_REGNUM, 16 },
    { 0 }
  };

static const struct regset aarch64_fbsd13_pcbregset_cheri_alias =
  {
    aarch64_fbsd13_pcbmap_cheri_alias,
    regcache_supply_regset, regcache_collect_regset
  };

static void
aarch64_fbsd_supply_pcb(struct regcache *regcache, CORE_ADDR pcb_addr)
{
  const struct regset *pcbregset;
  struct aarch64_fbsd_kern_info *info = get_aarch64_fbsd_kern_info();
  gdb_byte buf[8 * 33];

  if (info->osreldate >= 1400084)
    pcbregset = &aarch64_fbsd_pcbregset;
  else
    pcbregset = &aarch64_fbsd13_pcbregset;
  if (target_read_memory (pcb_addr, buf, sizeof buf) == 0)
    regcache_supply_regset (pcbregset, regcache, -1, buf,
			    sizeof (buf));
}

static void
aarch64_fbsd_supply_cheriabi_pcb(struct regcache *regcache, CORE_ADDR pcb_addr)
{
  aarch64_gdbarch_tdep *tdep
    = gdbarch_tdep<aarch64_gdbarch_tdep> (regcache->arch ());
  const struct regset *pcbregset_cheri, *pcbregset_cheri_alias;
  struct aarch64_fbsd_kern_info *info = get_aarch64_fbsd_kern_info();
  size_t len;

  if (info->osreldate >= 1400084)
    {
      pcbregset_cheri = &aarch64_fbsd_pcbregset_cheri;
      pcbregset_cheri_alias = &aarch64_fbsd_pcbregset_cheri_alias;
      len = regcache_map_entry_size (aarch64_fbsd_pcbmap_cheri);
    }
  else
    {
      pcbregset_cheri = &aarch64_fbsd13_pcbregset_cheri;
      pcbregset_cheri_alias = &aarch64_fbsd13_pcbregset_cheri_alias;
      len = regcache_map_entry_size (aarch64_fbsd13_pcbmap_cheri);
    }
  regcache->supply_regset (pcbregset_cheri, tdep->cap_reg_base, -1, pcb_addr,
			   len);
  regcache->supply_regset (pcbregset_cheri_alias, -1, pcb_addr, len);
}

static bool
is_cheri_kernel()
{
  return lookup_minimal_symbol ("userspace_root_cap", (const char *) NULL,
				(struct objfile *) NULL).minsym != NULL;
}

static const struct target_desc *
aarch64_fbsd_read_description()
{
  aarch64_features features;

  features.tls = true;
  features.capability = is_cheri_kernel ();

  return aarch64_read_description (features);
}

static const struct regcache_map_entry aarch64_fbsd_trapframe_map[] =
  {
    { 1, AARCH64_SP_REGNUM, 8 },
    { 1, AARCH64_LR_REGNUM, 8 },
    { 1, AARCH64_PC_REGNUM, 8 },
    { 1, AARCH64_CPSR_REGNUM, 8 },
    { 1, REGCACHE_MAP_SKIP, 8 },	/* esr */
    { 1, REGCACHE_MAP_SKIP, 8 },	/* far */
    { 30, AARCH64_X0_REGNUM, 8 }, /* x0 ... x29 */
    { 0 }
  };

static const struct regcache_map_entry aarch64_fbsd_trapframe_map_cheri[] =
  {
    { 1, AARCH64_CSP_REGNUM (0), 16 },
    { 1, AARCH64_CLR_REGNUM (0), 16 },
    { 1, AARCH64_PCC_REGNUM (0), 16 },
    { 1, AARCH64_DDC_REGNUM (0), 16 },
    { 1, REGCACHE_MAP_SKIP, 8 },	/* cpsr */
    { 1, REGCACHE_MAP_SKIP, 8 },	/* esr */
    { 1, REGCACHE_MAP_SKIP, 8 },	/* far */
    { 1, REGCACHE_MAP_SKIP, 8 },	/* pad */
    { 30, AARCH64_C0_REGNUM (0), 16 }, /* c0 ... c29 */
    { 0 }
  };

static const struct regcache_map_entry aarch64_fbsd_trapframe_map_cheri_alias[] =
  {
    { 1, AARCH64_SP_REGNUM, 16 },
    { 1, AARCH64_LR_REGNUM, 16 },
    { 1, AARCH64_PC_REGNUM, 16 },
    { 1, REGCACHE_MAP_SKIP, 16 },	/* ddc */
    { 1, AARCH64_CPSR_REGNUM, 8 },
    { 1, REGCACHE_MAP_SKIP, 8 },	/* esr */
    { 1, REGCACHE_MAP_SKIP, 8 },	/* far */
    { 1, REGCACHE_MAP_SKIP, 8 },	/* pad */
    { 30, AARCH64_X0_REGNUM, 16 }, /* x0 ... x29 */
    { 0 }
  };

/* In kernels prior to __FreeBSD_version 1400084, struct trapframe
   used an alternate layout.  */

static const struct regcache_map_entry aarch64_fbsd13_trapframe_map[] =
  {
    { 1, AARCH64_SP_REGNUM, 8 },
    { 1, AARCH64_LR_REGNUM, 8 },
    { 1, AARCH64_PC_REGNUM, 8 },
    { 1, AARCH64_CPSR_REGNUM, 4 },
    { 1, REGCACHE_MAP_SKIP, 4 },	/* esr */
    { 30, AARCH64_X0_REGNUM, 8 }, /* x0 ... x29 */
    { 0 }
  };

static const struct regcache_map_entry aarch64_fbsd13_trapframe_map_cheri[] =
  {
    { 1, AARCH64_CSP_REGNUM (0), 16 },
    { 1, AARCH64_CLR_REGNUM (0), 16 },
    { 1, AARCH64_PCC_REGNUM (0), 16 },
    { 1, AARCH64_DDC_REGNUM (0), 16 },
    { 1, REGCACHE_MAP_SKIP, 4 },	/* cpsr */
    { 1, REGCACHE_MAP_SKIP, 4 },	/* esr */
    { 1, REGCACHE_MAP_SKIP, 8 },	/* pad */
    { 30, AARCH64_C0_REGNUM (0), 16 }, /* c0 ... c29 */
    { 0 }
  };

static const struct regcache_map_entry aarch64_fbsd13_trapframe_map_cheri_alias[] =
  {
    { 1, AARCH64_SP_REGNUM, 16 },
    { 1, AARCH64_LR_REGNUM, 16 },
    { 1, AARCH64_PC_REGNUM, 16 },
    { 1, REGCACHE_MAP_SKIP, 16 },	/* ddc */
    { 1, AARCH64_CPSR_REGNUM, 4 },
    { 1, REGCACHE_MAP_SKIP, 4 },	/* esr */
    { 1, REGCACHE_MAP_SKIP, 8 },	/* pad */
    { 30, AARCH64_X0_REGNUM, 16 }, /* x0 ... x29 */
    { 0 }
  };

static struct trad_frame_cache *
aarch64_fbsd_trapframe_cache (frame_info_ptr this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct aarch64_fbsd_kern_info *info = get_aarch64_fbsd_kern_info();
  struct trad_frame_cache *cache;
  CORE_ADDR func, offset, pc, sp;
  const char *name;
  int i, tf_size;

  if (*this_cache != NULL)
    return ((struct trad_frame_cache *)*this_cache);

  const struct regcache_map_entry *trapframe_map;
  const struct regcache_map_entry *trapframe_map_cheri;
  const struct regcache_map_entry *trapframe_map_cheri_alias;
  if (info->osreldate >= 1400084)
    {
      trapframe_map = aarch64_fbsd_trapframe_map;
      trapframe_map_cheri = aarch64_fbsd_trapframe_map_cheri;
      trapframe_map_cheri_alias = aarch64_fbsd_trapframe_map_cheri_alias;
    }
  else
    {
      trapframe_map = aarch64_fbsd13_trapframe_map;
      trapframe_map_cheri = aarch64_fbsd13_trapframe_map_cheri;
      trapframe_map_cheri_alias = aarch64_fbsd13_trapframe_map_cheri_alias;
    }

  cache = trad_frame_cache_zalloc (this_frame);
  *this_cache = cache;

  if (tdep->abi == AARCH64_ABI_AAPCS64_CAP)
    sp = get_frame_register_unsigned (this_frame,
				      AARCH64_CSP_REGNUM (tdep->cap_reg_base));
  else
    sp = get_frame_register_unsigned (this_frame, AARCH64_SP_REGNUM);

  if (tdep->has_capability ())
    {
      tf_size = regcache_map_entry_size (trapframe_map_cheri);
      trad_frame_set_reg_regmap (cache, trapframe_map_cheri, sp,
				 tf_size, tdep->cap_reg_base);
      trad_frame_set_reg_regmap (cache, trapframe_map_cheri_alias,
				 sp, tf_size);
    }
  else
    {
      tf_size = regcache_map_entry_size (trapframe_map);
      trad_frame_set_reg_regmap (cache, trapframe_map, sp,
				 tf_size);
    }

  /* Read $PC from trap frame.  */
  func = get_frame_func (this_frame);
  find_pc_partial_function (func, &name, NULL, NULL);
  if (tdep->has_capability ())
    offset = regcache_map_offset (trapframe_map, AARCH64_PCC_REGNUM(0),
				  gdbarch);
  else
    offset = regcache_map_offset (trapframe_map, AARCH64_PC_REGNUM, gdbarch);
  pc = read_memory_unsigned_integer (sp + offset, 8, byte_order);

  if (pc == 0 && strcmp(name, "fork_trampoline") == 0)
    {
      /* Initial frame of a kthread; terminate backtrace.  */
      trad_frame_set_id (cache, outer_frame_id);
    }
  else
    {
      /* Construct the frame ID using the function start.  */
      trad_frame_set_id (cache, frame_id_build (sp, func));
    }

  return cache;
}

static void
aarch64_fbsd_trapframe_this_id (frame_info_ptr this_frame,
				void **this_cache, struct frame_id *this_id)
{
  struct trad_frame_cache *cache =
    aarch64_fbsd_trapframe_cache (this_frame, this_cache);
  
  trad_frame_get_id (cache, this_id);
}

static struct value *
aarch64_fbsd_trapframe_prev_register (frame_info_ptr this_frame,
				      void **this_cache, int regnum)
{
  struct trad_frame_cache *cache =
    aarch64_fbsd_trapframe_cache (this_frame, this_cache);

  return trad_frame_get_register (cache, this_frame, regnum);
}

static int
aarch64_fbsd_trapframe_sniffer (const struct frame_unwind *self,
				frame_info_ptr this_frame,
				void **this_prologue_cache)
{
  const char *name;

  find_pc_partial_function (get_frame_func (this_frame), &name, NULL, NULL);
  return (name && ((strcmp (name, "handle_el1h_sync") == 0)
		   || (strcmp (name, "handle_el1h_irq") == 0)
		   || (strcmp (name, "handle_el0_sync") == 0)
		   || (strcmp (name, "handle_el0_irq") == 0)
		   || (strcmp (name, "handle_el0_error") == 0)
		   || (strcmp (name, "fork_trampoline") == 0)));
}

static const struct frame_unwind aarch64_fbsd_trapframe_unwind = {
  "aarch64 FreeBSD kernel trap",
  SIGTRAMP_FRAME,
  default_frame_unwind_stop_reason,
  aarch64_fbsd_trapframe_this_id,
  aarch64_fbsd_trapframe_prev_register,
  NULL,
  aarch64_fbsd_trapframe_sniffer
};

/* Implement the 'init_osabi' method of struct gdb_osabi_handler.  */

static void
aarch64_fbsd_kernel_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);

  frame_unwind_prepend_unwinder (gdbarch, &aarch64_fbsd_trapframe_unwind);

  set_gdbarch_so_ops (gdbarch, &kld_so_ops);

  /* Enable longjmp.  */
  tdep->jb_pc = 13;

  if (tdep->abi == AARCH64_ABI_AAPCS64_CAP)
    fbsd_vmcore_set_supply_pcb (gdbarch, aarch64_fbsd_supply_cheriabi_pcb);
  else
    fbsd_vmcore_set_supply_pcb (gdbarch, aarch64_fbsd_supply_pcb);
  fbsd_vmcore_set_cpu_pcb_addr (gdbarch, kgdb_trgt_stop_pcb);
  fbsd_vmcore_set_read_description (gdbarch, aarch64_fbsd_read_description);
}

void _initialize_aarch64_kgdb_tdep ();
void
_initialize_aarch64_kgdb_tdep ()
{
  gdbarch_register_osabi_sniffer(bfd_arch_aarch64,
				 bfd_target_elf_flavour,
				 fbsd_kernel_osabi_sniffer);
  gdbarch_register_osabi (bfd_arch_aarch64, 0, GDB_OSABI_FREEBSD_KERNEL,
			  aarch64_fbsd_kernel_init_abi);
}

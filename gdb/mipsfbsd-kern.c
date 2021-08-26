/*
 * Copyright (c) 2007 Juniper Networks, Inc.
 * Copyright (c) 2004 Marcel Moolenaar
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
 *
 * from: src/gnu/usr.bin/gdb/kgdb/trgt_alpha.c,v 1.2.2.1 2005/09/15 05:32:10 marcel
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/gnu/usr.bin/gdb/kgdb/trgt_mips.c 249878 2013-04-25 04:53:01Z imp $");

#include "defs.h"
#include "frame-unwind.h"
#include "osabi.h"
#include "regcache.h"
#include "regset.h"
#include "solib.h"
#include "trad-frame.h"
#include "mips-tdep.h"

#ifdef __mips__
#include <machine/asm.h>
#include <machine/frame.h>
#endif

#include "kgdb.h"

/* Size of struct trapframe in registers. */
#define	TRAPFRAME_WORDS	74

#ifdef __mips__
_Static_assert(TRAPFRAME_WORDS * sizeof(register_t) ==
	       sizeof(struct trapframe), "TRAPFRAME_WORDS mismatch");
#endif

static const struct regcache_map_entry mips_fbsd_pcbmap[] =
  {
   { 8, MIPS_S2_REGNUM - 2, 0 },	/* s0 - s7 */
   { 1, MIPS_SP_REGNUM, 0 },
   { 1, MIPS_S2_REGNUM + 6, 0 },
   { 1, MIPS_RA_REGNUM, 0 },
   { 1, MIPS_PS_REGNUM, 0 },
   { 1, MIPS_GP_REGNUM, 0 },
   { 1, MIPS_EMBED_PC_REGNUM, 0 },
   { 0 }
  };

static const struct regset mips_fbsd_pcbregset =
  {
    mips_fbsd_pcbmap,
    regcache_supply_regset, regcache_collect_regset
  };

static bool
is_cheri_kernel()
{

  return lookup_minimal_symbol ("userspace_root_cap", (const char *) NULL,
				(struct objfile *) NULL).minsym != NULL;
}

static size_t
mipsfbsd_trapframe_size(struct gdbarch *gdbarch)
{
  size_t regsize = mips_isa_regsize (gdbarch);
  size_t size;

  size = TRAPFRAME_WORDS * regsize;
  if (mips_regnum(gdbarch)->cap0 != -1 && is_cheri_kernel ())
    size += 34 * register_size(gdbarch, mips_regnum(gdbarch)->cap0);
  return (size);
}

static void
mipsfbsd_supply_pcb(struct regcache *regcache, CORE_ADDR pcb_addr)
{
  struct gdbarch *gdbarch = regcache->arch ();
  size_t regsize = mips_isa_regsize (gdbarch);
  gdb_byte buf[regsize * 14];

  regcache->raw_supply_zeroed (MIPS_ZERO_REGNUM);

  /* Always give a value for PC in case the PCB isn't readable. */
  regcache->raw_supply_zeroed (MIPS_EMBED_PC_REGNUM);
  if (mips_regnum (gdbarch)->cap0 != -1)
    regcache->raw_supply_zeroed (mips_regnum (gdbarch)->cap_pcc);

  /* Read the entire pcb_context[] array in one go.  The pcb_context[]
     array is after the pcb_regs member which is a trapframe.  */
  CORE_ADDR pcb_context_addr = pcb_addr + mipsfbsd_trapframe_size (gdbarch);
  if (target_read_memory (pcb_context_addr, buf, sizeof(buf)) == 0)
      regcache->supply_regset (&mips_fbsd_pcbregset, -1, buf, sizeof (buf));

  if (mips_regnum(gdbarch)->cap0 != -1 && is_cheri_kernel ())
    {
      int cap0 = mips_regnum (gdbarch)->cap0;
      size_t capregsize = register_size (gdbarch, cap0);
      enum mips_abi abi = mips_abi (gdbarch);
      int numkframeregs;

      if (abi == MIPS_ABI_CHERI128)
	numkframeregs = 11;
      else
	numkframeregs = 8;
      
      gdb_byte cherikframe[capregsize * numkframeregs];

      CORE_ADDR cherikframe_addr = pcb_context_addr + sizeof(buf);

      /* Skip over pcb_onfault (padded on hybrid) and pcb_tpc.  */
      cherikframe_addr += 2 * capregsize;

      /* Skip over pcb_cherisignal.  */
      cherikframe_addr += 6 * capregsize;
      
      if (target_read_memory (cherikframe_addr, cherikframe,
			      sizeof (cherikframe)) == 0)
	{
	  /* Can't use a register map here since register numbers
	     aren't fixed.  */
	  regcache->raw_supply (cap0 + 17, cherikframe);
	  regcache->raw_supply (cap0 + 18, cherikframe + capregsize * 1);
	  regcache->raw_supply (cap0 + 19, cherikframe + capregsize * 2);
	  regcache->raw_supply (cap0 + 20, cherikframe + capregsize * 3);
	  regcache->raw_supply (cap0 + 21, cherikframe + capregsize * 4);
	  regcache->raw_supply (cap0 + 22, cherikframe + capregsize * 5);
	  regcache->raw_supply (cap0 + 23, cherikframe + capregsize * 6);
	  regcache->raw_supply (cap0 + 24, cherikframe + capregsize * 7);

	  if (numkframeregs == 11)
	    {
	      regcache->raw_supply (mips_regnum (gdbarch)->cap_pcc,
				    cherikframe + capregsize * 8);
	      regcache->raw_supply (cap0 + 11, cherikframe + capregsize * 9);
	      regcache->raw_supply (cap0 + 26, cherikframe + capregsize * 10);
	    }
	}
    }
}

static struct trad_frame_cache *
mipsfbsd_trapframe_cache (struct frame_info *this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  size_t regsize = mips_isa_regsize (gdbarch);
  enum mips_abi abi = mips_abi (gdbarch);
  int cap0 = mips_regnum (gdbarch)->cap0;
  size_t capregsize = cap0 == -1 ? 0 : register_size (gdbarch, cap0);
  struct trad_frame_cache *cache;
  CORE_ADDR addr, func, sp;
  int regnum;

  if (*this_cache != NULL)
    return ((struct trad_frame_cache *)*this_cache);

  cache = trad_frame_cache_zalloc (this_frame);
  *this_cache = cache;

  func = get_frame_func (this_frame);

  if (abi == MIPS_ABI_CHERI128)
    sp = get_cheri_frame_register_signed (this_frame, cap0 + 11
					  + gdbarch_num_regs (gdbarch));
  else
    sp = get_frame_register_signed (this_frame,
				    MIPS_SP_REGNUM + gdbarch_num_regs (gdbarch));

  /* Skip over CALLFRAME_SIZ.  */
  addr = sp;
  switch (abi) {
  case MIPS_ABI_O32:
    addr += regsize * (4 + 2);
    break;
  case MIPS_ABI_N32:
  case MIPS_ABI_N64:
    addr += regsize * 4;
    break;
  case MIPS_ABI_CHERI128:
    addr += capregsize * 4;
    break;
  }

  /* GPRs.  Skip zero.  */
  addr += regsize;
  for (regnum = MIPS_AT_REGNUM; regnum <= MIPS_RA_REGNUM; regnum++)
    {
      trad_frame_set_reg_addr (cache,
			       regnum + gdbarch_num_regs (gdbarch),
			       addr);
      addr += regsize;
    }

  regnum = MIPS_PS_REGNUM;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);
  addr += regsize;

  /* HI and LO.  */
  regnum = mips_regnum (gdbarch)->lo;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);
  addr += regsize;
  regnum = mips_regnum (gdbarch)->hi;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);
  addr += regsize;

  /* BADVADDR.  */
  regnum = mips_regnum (gdbarch)->badvaddr;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);
  addr += regsize;

  /* CAUSE.  */
  regnum = mips_regnum (gdbarch)->cause;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   addr);
  addr += regsize;

  if (mips_regnum(gdbarch)->cap0 != -1)
    {
      int cap0 = mips_regnum (gdbarch)->cap0;
      size_t capsize = register_size (gdbarch, cap0);

      /* Skip over pc, ic, and dummy. */
      addr += 3 * regsize;

      /* DDC. */
      regnum = mips_regnum (gdbarch)->cap_ddc;
      trad_frame_set_reg_addr (cache,
			       regnum + gdbarch_num_regs (gdbarch),
			       addr);
      addr += capsize;

      /* C1-C31. */
      for (regnum = 1; regnum <= 31; regnum++)
	{
	  trad_frame_set_reg_addr (cache,
				   cap0 + regnum + gdbarch_num_regs (gdbarch),
				   addr);
	  addr += capsize;
	}

      /* PC and PCC. */
      /* XXX: This is wrong as this gives the address of PC instead of
	 the offset.  However, a hybrid kernel always has a base of 0
	 for PCC.  */
      regnum = mips_regnum (gdbarch)->pc;
      trad_frame_set_reg_addr (cache,
			       regnum + gdbarch_num_regs (gdbarch),
			       addr + 8);
      regnum = mips_regnum (gdbarch)->cap_pcc;
      trad_frame_set_reg_addr (cache,
			       regnum + gdbarch_num_regs (gdbarch),
			       addr);
      addr += capsize;

      /* CAPCAUSE. */
      regnum = mips_regnum (gdbarch)->cap_cause;
      trad_frame_set_reg_addr (cache,
			       regnum + gdbarch_num_regs (gdbarch),
			       addr);

      /* XXX: No capvalid. */
    }
  else
    {
      /* PC.  */
      regnum = mips_regnum (gdbarch)->pc;
      trad_frame_set_reg_addr (cache,
			       regnum + gdbarch_num_regs (gdbarch),
			       addr);
    }
  
  trad_frame_set_id (cache, frame_id_build (sp
					    + mipsfbsd_trapframe_size (gdbarch),
					    func));
  return cache;
}

static void
mipsfbsd_trapframe_this_id (struct frame_info *this_frame,
			    void **this_cache, struct frame_id *this_id)
{
  struct trad_frame_cache *cache =
    mipsfbsd_trapframe_cache (this_frame, this_cache);
  
  trad_frame_get_id (cache, this_id);
}

static struct value *
mipsfbsd_trapframe_prev_register (struct frame_info *this_frame,
				  void **this_cache, int regnum)
{
  struct trad_frame_cache *cache =
    mipsfbsd_trapframe_cache (this_frame, this_cache);

  return trad_frame_get_register (cache, this_frame, regnum);
}

static int
mipsfbsd_trapframe_sniffer (const struct frame_unwind *self,
			    struct frame_info *this_frame,
			    void **this_prologue_cache)
{
  const char *name;

  find_pc_partial_function (get_frame_func (this_frame), &name, NULL, NULL);
  return (name && ((strcmp(name, "MipsKernIntr") == 0) ||
		   (strcmp(name, "MipsKernGenException") == 0) ||
		   (strcmp(name, "MipsTLBInvalidException") == 0)));
}

static const struct frame_unwind mipsfbsd_trapframe_unwind = {
  SIGTRAMP_FRAME,
  default_frame_unwind_stop_reason,
  mipsfbsd_trapframe_this_id,
  mipsfbsd_trapframe_prev_register,
  NULL,
  mipsfbsd_trapframe_sniffer
};

static void
mipsfbsd_kernel_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  enum mips_abi abi = mips_abi (gdbarch);

  set_gdbarch_software_single_step (gdbarch, mips_software_single_step);

  switch (abi)
    {
      case MIPS_ABI_O32:
	break;
      case MIPS_ABI_N32:
	set_gdbarch_long_double_bit (gdbarch, 128);
	/* These floatformats should probably be renamed.  MIPS uses
	   the same 128-bit IEEE floating point format that IA-64 uses,
	   except that the quiet/signalling NaN bit is reversed (GDB
	   does not distinguish between quiet and signalling NaNs).  */
	set_gdbarch_long_double_format (gdbarch, floatformats_ia64_quad);
	break;
      case MIPS_ABI_N64:
	set_gdbarch_long_double_bit (gdbarch, 128);
	/* These floatformats should probably be renamed.  MIPS uses
	   the same 128-bit IEEE floating point format that IA-64 uses,
	   except that the quiet/signalling NaN bit is reversed (GDB
	   does not distinguish between quiet and signalling NaNs).  */
	set_gdbarch_long_double_format (gdbarch, floatformats_ia64_quad);
	break;
    }

  frame_unwind_prepend_unwinder (gdbarch, &mipsfbsd_trapframe_unwind);

  set_solib_ops (gdbarch, &kld_so_ops);

  fbsd_vmcore_set_supply_pcb (gdbarch, mipsfbsd_supply_pcb);
  fbsd_vmcore_set_cpu_pcb_addr (gdbarch, kgdb_trgt_stop_pcb);
}

void
_initialize_mips_kgdb_tdep (void)
{
  gdbarch_register_osabi_sniffer(bfd_arch_mips,
				 bfd_target_elf_flavour,
				 fbsd_kernel_osabi_sniffer);
  gdbarch_register_osabi (bfd_arch_mips, 0, GDB_OSABI_FREEBSD_KERNEL,
			  mipsfbsd_kernel_init_abi);
}

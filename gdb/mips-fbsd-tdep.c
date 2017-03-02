/* Target-dependent code for FreeBSD/mips.

   Copyright (C) 2017 Free Software Foundation, Inc.

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
#include "osabi.h"
#include "regset.h"
#include "trad-frame.h"
#include "tramp-frame.h"

#include "fbsd-tdep.h"
#include "mips-tdep.h"
#include "mips-fbsd-tdep.h"

#include "solib-svr4.h"

#include "elf-bfd.h"
#include "elf/mips.h"

/* Shorthand for some register numbers used below.  */
#define MIPS_PC_REGNUM  MIPS_EMBED_PC_REGNUM
#define MIPS_FP0_REGNUM MIPS_EMBED_FP0_REGNUM
#define MIPS_FSR_REGNUM MIPS_EMBED_FP0_REGNUM + 32
#define MIPS_CAP0_REGNUM (MIPS_FSR_REGNUM + 2)
#define MIPS_PCC_REGNUM	(MIPS_CAP0_REGNUM + 32)
#define MIPS_CAP_CAUSE_REGNUM (MIPS_PCC_REGNUM + 1)

/* Core file support. */

/* Number of registers in `struct reg' from <machine/reg.h>.  The
   first 38 follow the standard MIPS layout.  The 39th holds
   IC_INT_REG on RM7K and RM9K processors.  The 40th is a dummy for
   padding.  */
#define MIPS_FBSD_NUM_GREGS	40

/* Number of registers in `struct fpreg' from <machine/reg.h>.  The
   first 32 hold floating point registers.  33 holds the FSR.  The
   34th is a dummy for padding.  */
#define MIPS_FBSD_NUM_FPREGS	34

/* Number of general capability registers in `struct cheri_frame' from
   <machine/cheri.h>.  The structure contains the first 27 capability
   registers followed by the PCC and cap_cause.  */
#define MIPS_FBSD_NUM_CAPREGS	29

/* Implement the core_read_description gdbarch method.  */

static const struct target_desc *
mips_fbsd_core_read_description (struct gdbarch *gdbarch,
				 struct target_ops *target,
				 bfd *abfd)
{
  size_t capregbits = gdbarch_ptr_bit (gdbarch);

  if (capregbits == 256)
    return tdesc_mips64_cheri256;
  else
    return NULL;
}

/* Supply a single register.  If the source register size matches the
   size the regcache expects, this can use regcache_raw_supply().  If
   they are different, this copies the source register into a buffer
   that can be passed to regcache_raw_supply().  */

static void
mips_fbsd_supply_reg (struct regcache *regcache, int regnum, const void *addr,
		      size_t len)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);

  if (register_size (gdbarch, regnum) == len)
    regcache_raw_supply (regcache, regnum, addr);
  else
    {
      enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
      gdb_byte buf[MAX_REGISTER_SIZE];
      LONGEST val;

      val = extract_signed_integer ((const gdb_byte *) addr, len, byte_order);
      store_signed_integer (buf, register_size (gdbarch, regnum), byte_order,
			    val);
      regcache_raw_supply (regcache, regnum, buf);
    }
}

/* Collect a single register.  If the destination register size
   matches the size the regcache expects, this can use
   regcache_raw_supply().  If they are different, this fetches the
   register via regcache_raw_supply() into a buffer and then copies it
   into the final destination.  */

static void
mips_fbsd_collect_reg (const struct regcache *regcache, int regnum, void *addr,
		       size_t len)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);

  if (register_size (gdbarch, regnum) == len)
    regcache_raw_collect (regcache, regnum, addr);
  else
    {
      enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
      gdb_byte buf[MAX_REGISTER_SIZE];
      LONGEST val;

      regcache_raw_collect (regcache, regnum, buf);
      val = extract_signed_integer (buf, register_size (gdbarch, regnum),
				    byte_order);
      store_signed_integer ((gdb_byte *) addr, len, byte_order, val);
    }
}

/* Supply the floating-point registers stored in FPREGS to REGCACHE.
   Each floating-point register in FPREGS is REGSIZE bytes in
   length.  */

void
mips_fbsd_supply_fpregs (struct regcache *regcache, int regnum,
			 const void *fpregs, size_t regsize)
{
  const gdb_byte *regs = (const gdb_byte *) fpregs;
  int i;

  for (i = MIPS_FP0_REGNUM; i <= MIPS_FSR_REGNUM; i++)
    if (regnum == i || regnum == -1)
      mips_fbsd_supply_reg (regcache, i,
			    regs + (i - MIPS_FP0_REGNUM) * regsize, regsize);
}

/* Supply the general-purpose registers stored in GREGS to REGCACHE.
   Each general-purpose register in GREGS is REGSIZE bytes in
   length.  */

void
mips_fbsd_supply_gregs (struct regcache *regcache, int regnum,
			const void *gregs, size_t regsize)
{
  const gdb_byte *regs = (const gdb_byte *) gregs;
  int i;

  for (i = 0; i <= MIPS_PC_REGNUM; i++)
    if (regnum == i || regnum == -1)
      mips_fbsd_supply_reg (regcache, i, regs + i * regsize, regsize);
}

/* Supply the capability registers stored in CAPREGS to REGCACHE.  Each
   capability register in CAPREGS is REGSIZE bytes in length.  */

void
mips_fbsd_supply_capregs (struct regcache *regcache, int regnum,
			  const void *capregs, size_t regsize)
{
  const gdb_byte *regs = (const gdb_byte *) capregs;
  int i;

  for (i = 0; i < 27; i++)
    if (regnum == MIPS_CAP0_REGNUM + i || regnum == -1)
      regcache_raw_supply (regcache, MIPS_CAP0_REGNUM + i, regs + i * regsize);

  if (regnum == MIPS_PCC_REGNUM || regnum == -1)
    regcache_raw_supply (regcache, MIPS_PCC_REGNUM, regs + 27 * regsize);
  if (regnum == MIPS_CAP_CAUSE_REGNUM || regnum == -1)
    regcache_raw_supply (regcache, MIPS_CAP_CAUSE_REGNUM, regs + 28 * regsize);
}


/* Collect the floating-point registers from REGCACHE and store them
   in FPREGS.  Each floating-point register in FPREGS is REGSIZE bytes
   in length.  */

void
mips_fbsd_collect_fpregs (const struct regcache *regcache, int regnum,
			  void *fpregs, size_t regsize)
{
  gdb_byte *regs = (gdb_byte *) fpregs;
  int i;

  for (i = MIPS_FP0_REGNUM; i <= MIPS_FSR_REGNUM; i++)
    if (regnum == i || regnum == -1)
      mips_fbsd_collect_reg (regcache, i,
			     regs + (i - MIPS_FP0_REGNUM) * regsize, regsize);
}

/* Collect the general-purpose registers from REGCACHE and store them
   in GREGS.  Each general-purpose register in GREGS is REGSIZE bytes
   in length.  */

void
mips_fbsd_collect_gregs (const struct regcache *regcache, int regnum,
			 void *gregs, size_t regsize)
{
  gdb_byte *regs = (gdb_byte *) gregs;
  int i;

  for (i = 0; i <= MIPS_PC_REGNUM; i++)
    if (regnum == i || regnum == -1)
      mips_fbsd_collect_reg (regcache, i, regs + i * regsize, regsize);
}

/* Collect the capability registers from REGCACHE and store them in
   CAPREGS.  Each capability register in CAPREGS is REGSIZE bytes in
   length.  */

void
mips_fbsd_collect_capregs (const struct regcache *regcache, int regnum,
			   void *capregs, size_t regsize)
{
  gdb_byte *regs = (gdb_byte *) capregs;
  int i;

  for (i = 0; i < 27; i++)
    if (regnum == MIPS_CAP0_REGNUM + i || regnum == -1)
      regcache_raw_collect (regcache, MIPS_CAP0_REGNUM + i, regs + i * regsize);

  if (regnum == MIPS_PCC_REGNUM || regnum == -1)
    regcache_raw_collect (regcache, MIPS_PCC_REGNUM, regs + 27 * regsize);
  if (regnum == MIPS_CAP_CAUSE_REGNUM || regnum == -1)
    regcache_raw_collect (regcache, MIPS_CAP_CAUSE_REGNUM, regs + 28 * regsize);
}

/* Supply register REGNUM from the buffer specified by FPREGS and LEN
   in the floating-point register set REGSET to register cache
   REGCACHE.  If REGNUM is -1, do this for all registers in REGSET.  */

static void
mips_fbsd_supply_fpregset (const struct regset *regset,
			   struct regcache *regcache,
			   int regnum, const void *fpregs, size_t len)
{
  size_t regsize = mips_abi_regsize (get_regcache_arch (regcache));

  gdb_assert (len >= MIPS_FBSD_NUM_FPREGS * regsize);

  mips_fbsd_supply_fpregs (regcache, regnum, fpregs, regsize);
}

/* Collect register REGNUM from the register cache REGCACHE and store
   it in the buffer specified by FPREGS and LEN in the floating-point
   register set REGSET.  If REGNUM is -1, do this for all registers in
   REGSET.  */

static void
mips_fbsd_collect_fpregset (const struct regset *regset,
			    const struct regcache *regcache,
			    int regnum, void *fpregs, size_t len)
{
  size_t regsize = mips_abi_regsize (get_regcache_arch (regcache));

  gdb_assert (len >= MIPS_FBSD_NUM_FPREGS * regsize);

  mips_fbsd_collect_fpregs (regcache, regnum, fpregs, regsize);
}

/* Supply register REGNUM from the buffer specified by GREGS and LEN
   in the general-purpose register set REGSET to register cache
   REGCACHE.  If REGNUM is -1, do this for all registers in REGSET.  */

static void
mips_fbsd_supply_gregset (const struct regset *regset,
			  struct regcache *regcache, int regnum,
			  const void *gregs, size_t len)
{
  size_t regsize = mips_abi_regsize (get_regcache_arch (regcache));

  gdb_assert (len >= MIPS_FBSD_NUM_GREGS * regsize);

  mips_fbsd_supply_gregs (regcache, regnum, gregs, regsize);
}

/* Collect register REGNUM from the register cache REGCACHE and store
   it in the buffer specified by GREGS and LEN in the general-purpose
   register set REGSET.  If REGNUM is -1, do this for all registers in
   REGSET.  */

static void
mips_fbsd_collect_gregset (const struct regset *regset,
			   const struct regcache *regcache,
			   int regnum, void *gregs, size_t len)
{
  size_t regsize = mips_abi_regsize (get_regcache_arch (regcache));

  gdb_assert (len >= MIPS_FBSD_NUM_GREGS * regsize);

  mips_fbsd_collect_gregs (regcache, regnum, gregs, regsize);
}

/* Supply register REGNUM from the buffer specified by CAPREGS and LEN
   in the capability register set REGSET to register cache REGCACHE.
   If REGNUM is -1, do this for all registers in REGSET.  */

static void
mips_fbsd_supply_capregset (const struct regset *regset,
			  struct regcache *regcache, int regnum,
			  const void *capregs, size_t len)
{
  size_t capregsize = gdbarch_ptr_bit (get_regcache_arch (regcache))
    / TARGET_CHAR_BIT;

  gdb_assert (len >= MIPS_FBSD_NUM_CAPREGS * capregsize);

  mips_fbsd_supply_capregs (regcache, regnum, capregs, capregsize);
}

/* Collect register REGNUM from the register cache REGCACHE and store
   it in the buffer specified by CAPREGS and LEN in the general-purpose
   register set REGSET.  If REGNUM is -1, do this for all registers in
   REGSET.  */

static void
mips_fbsd_collect_capregset (const struct regset *regset,
			     const struct regcache *regcache,
			     int regnum, void *capregs, size_t len)
{
  size_t capregsize = gdbarch_ptr_bit (get_regcache_arch (regcache))
    / TARGET_CHAR_BIT;

  gdb_assert (len >= MIPS_FBSD_NUM_CAPREGS * capregsize);

  mips_fbsd_collect_capregs (regcache, regnum, capregs, capregsize);
}

/* FreeBSD/mips register sets.  */

static const struct regset mips_fbsd_gregset =
{
  NULL,
  mips_fbsd_supply_gregset,
  mips_fbsd_collect_gregset,
};

static const struct regset mips_fbsd_fpregset =
{
  NULL,
  mips_fbsd_supply_fpregset,
  mips_fbsd_collect_fpregset,
};

static const struct regset mips_fbsd_capregset =
{
  NULL,
  mips_fbsd_supply_capregset,
  mips_fbsd_collect_capregset,
};

/* Iterate over core file register note sections.  */

static void
mips_fbsd_iterate_over_regset_sections (struct gdbarch *gdbarch,
					iterate_over_regset_sections_cb *cb,
					void *cb_data,
					const struct regcache *regcache)
{
  size_t regsize = mips_abi_regsize (gdbarch);
  size_t capregsize = gdbarch_ptr_bit (gdbarch) / TARGET_CHAR_BIT;

  cb (".reg", MIPS_FBSD_NUM_GREGS * regsize, &mips_fbsd_gregset,
      NULL, cb_data);
  cb (".reg2", MIPS_FBSD_NUM_FPREGS * regsize, &mips_fbsd_fpregset,
      NULL, cb_data);
  if (capregsize >= 128 / TARGET_CHAR_BIT)
    cb(".reg-cap", MIPS_FBSD_NUM_CAPREGS * capregsize, &mips_fbsd_capregset,
       NULL, cb_data);
}

/* Signal trampoline support.  */

#define FBSD_SYS_sigreturn	417

#define MIPS_INST_LI_V0_SIGRETURN 0x24020000 + FBSD_SYS_sigreturn
#define MIPS_INST_SYSCALL	0x0000000c
#define MIPS_INST_BREAK		0x0000000d

#define O32_SIGFRAME_UCONTEXT_OFFSET	(16)
#define O32_SIGSET_T_SIZE	(16)

#define O32_UCONTEXT_ONSTACK	(O32_SIGSET_T_SIZE)
#define O32_UCONTEXT_PC		(O32_UCONTEXT_ONSTACK + 4)
#define O32_UCONTEXT_REGS	(O32_UCONTEXT_PC + 4)
#define O32_UCONTEXT_SR		(O32_UCONTEXT_REGS + 4 * 32)
#define O32_UCONTEXT_LO		(O32_UCONTEXT_SR + 4)
#define O32_UCONTEXT_HI		(O32_UCONTEXT_LO + 4)
#define O32_UCONTEXT_FPUSED	(O32_UCONTEXT_HI + 4)
#define O32_UCONTEXT_FPREGS	(O32_UCONTEXT_FPUSED + 4)

#define O32_UCONTEXT_REG_SIZE	4

static void
mips_fbsd_sigframe_init (const struct tramp_frame *self,
			 struct frame_info *this_frame,
			 struct trad_frame_cache *cache,
			 CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR sp, ucontext_addr, addr;
  int regnum;
  gdb_byte buf[4];

  /* We find the appropriate instance of `ucontext_t' at a
     fixed offset in the signal frame.  */
  sp = get_frame_register_signed (this_frame,
				  MIPS_SP_REGNUM + gdbarch_num_regs (gdbarch));
  ucontext_addr = sp + O32_SIGFRAME_UCONTEXT_OFFSET;

  /* PC.  */
  regnum = mips_regnum (gdbarch)->pc;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   ucontext_addr + O32_UCONTEXT_PC);

  /* GPRs.  */
  for (regnum = MIPS_ZERO_REGNUM, addr = ucontext_addr + O32_UCONTEXT_REGS;
       regnum <= MIPS_RA_REGNUM; regnum++, addr += O32_UCONTEXT_REG_SIZE)
    trad_frame_set_reg_addr (cache,
			     regnum + gdbarch_num_regs (gdbarch),
			     addr);

  regnum = MIPS_PS_REGNUM;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   ucontext_addr + O32_UCONTEXT_SR);

  /* HI and LO.  */
  regnum = mips_regnum (gdbarch)->lo;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   ucontext_addr + O32_UCONTEXT_LO);
  regnum = mips_regnum (gdbarch)->hi;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   ucontext_addr + O32_UCONTEXT_HI);

  if (target_read_memory (ucontext_addr + O32_UCONTEXT_FPUSED, buf, 4) == 0 &&
      extract_unsigned_integer (buf, 4, byte_order) != 0)
    {
      for (regnum = 0, addr = ucontext_addr + O32_UCONTEXT_FPREGS;
	   regnum < 32; regnum++, addr += O32_UCONTEXT_REG_SIZE)
	trad_frame_set_reg_addr (cache,
				 regnum + gdbarch_fp0_regnum (gdbarch),
				 addr);
      trad_frame_set_reg_addr (cache, mips_regnum (gdbarch)->fp_control_status,
			       addr);
    }

  trad_frame_set_id (cache, frame_id_build (sp, func));
}

#define MIPS_INST_ADDIU_A0_SP_O32 (0x27a40000 \
				   + O32_SIGFRAME_UCONTEXT_OFFSET)

static const struct tramp_frame mips_fbsd_sigframe =
{
  SIGTRAMP_FRAME,
  MIPS_INSN32_SIZE,
  {
    { MIPS_INST_ADDIU_A0_SP_O32, -1 },	/* addiu   a0, sp, SIGF_UC */
    { MIPS_INST_LI_V0_SIGRETURN, -1 },	/* li      v0, SYS_sigreturn */
    { MIPS_INST_SYSCALL, -1 },		/* syscall */
    { MIPS_INST_BREAK, -1 },		/* break */
    { TRAMP_SENTINEL_INSN, -1 }
  },
  mips_fbsd_sigframe_init
};

#define N64_SIGFRAME_UCONTEXT_OFFSET	(32)
#define N64_SIGSET_T_SIZE	(16)

#define N64_UCONTEXT_ONSTACK	(N64_SIGSET_T_SIZE)
#define N64_UCONTEXT_PC		(N64_UCONTEXT_ONSTACK + 8)
#define N64_UCONTEXT_REGS	(N64_UCONTEXT_PC + 8)
#define N64_UCONTEXT_SR		(N64_UCONTEXT_REGS + 8 * 32)
#define N64_UCONTEXT_LO		(N64_UCONTEXT_SR + 8)
#define N64_UCONTEXT_HI		(N64_UCONTEXT_LO + 8)
#define N64_UCONTEXT_FPUSED	(N64_UCONTEXT_HI + 8)
#define N64_UCONTEXT_FPREGS	(N64_UCONTEXT_FPUSED + 8)

#define N64_UCONTEXT_REG_SIZE	8

static void
mips64_fbsd_sigframe_init (const struct tramp_frame *self,
			   struct frame_info *this_frame,
			   struct trad_frame_cache *cache,
			   CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR sp, ucontext_addr, addr;
  int regnum;
  gdb_byte buf[4];

  /* We find the appropriate instance of `ucontext_t' at a
     fixed offset in the signal frame.  */
  sp = get_frame_register_signed (this_frame,
				  MIPS_SP_REGNUM + gdbarch_num_regs (gdbarch));
  ucontext_addr = sp + N64_SIGFRAME_UCONTEXT_OFFSET;

  /* PC.  */
  regnum = mips_regnum (gdbarch)->pc;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   ucontext_addr + N64_UCONTEXT_PC);

  /* GPRs.  */
  for (regnum = MIPS_ZERO_REGNUM, addr = ucontext_addr + N64_UCONTEXT_REGS;
       regnum <= MIPS_RA_REGNUM; regnum++, addr += N64_UCONTEXT_REG_SIZE)
    trad_frame_set_reg_addr (cache,
			     regnum + gdbarch_num_regs (gdbarch),
			     addr);

  regnum = MIPS_PS_REGNUM;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   ucontext_addr + N64_UCONTEXT_SR);

  /* HI and LO.  */
  regnum = mips_regnum (gdbarch)->lo;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   ucontext_addr + N64_UCONTEXT_LO);
  regnum = mips_regnum (gdbarch)->hi;
  trad_frame_set_reg_addr (cache,
			   regnum + gdbarch_num_regs (gdbarch),
			   ucontext_addr + N64_UCONTEXT_HI);

  if (target_read_memory (ucontext_addr + N64_UCONTEXT_FPUSED, buf, 4) == 0 &&
      extract_unsigned_integer (buf, 4, byte_order) != 0)
    {
      for (regnum = 0, addr = ucontext_addr + N64_UCONTEXT_FPREGS;
	   regnum < 32; regnum++, addr += N64_UCONTEXT_REG_SIZE)
	trad_frame_set_reg_addr (cache,
				 regnum + gdbarch_fp0_regnum (gdbarch),
				 addr);
      trad_frame_set_reg_addr (cache, mips_regnum (gdbarch)->fp_control_status,
			       addr);
    }

  trad_frame_set_id (cache, frame_id_build (sp, func));
}

#define MIPS_INST_DADDIU_A0_SP_N64 (0x67a40000 \
				    + N64_SIGFRAME_UCONTEXT_OFFSET)

static const struct tramp_frame mips64_fbsd_sigframe =
{
  SIGTRAMP_FRAME,
  MIPS_INSN32_SIZE,
  {
    { MIPS_INST_DADDIU_A0_SP_N64, -1 },	/* daddiu  a0, sp, SIGF_UC */
    { MIPS_INST_LI_V0_SIGRETURN, -1 },	/* li      v0, SYS_sigreturn */
    { MIPS_INST_SYSCALL, -1 },		/* syscall */
    { MIPS_INST_BREAK, -1 },		/* break */
    { TRAMP_SENTINEL_INSN, -1 }
  },
  mips64_fbsd_sigframe_init
};

/* Shared library support.  */

/* FreeBSD/mips uses a slightly different `struct link_map' than the
   other FreeBSD platforms as it includes an additional `l_off'
   member.  */

static struct link_map_offsets *
mips_fbsd_ilp32_fetch_link_map_offsets (void)
{
  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
    {
      lmp = &lmo;

      lmo.r_version_offset = 0;
      lmo.r_version_size = 4;
      lmo.r_map_offset = 4;
      lmo.r_brk_offset = 8;
      lmo.r_ldsomap_offset = -1;

      lmo.link_map_size = 24;
      lmo.l_addr_offset = 0;
      lmo.l_name_offset = 8;
      lmo.l_ld_offset = 12;
      lmo.l_next_offset = 16;
      lmo.l_prev_offset = 20;
    }

  return lmp;
}

static struct link_map_offsets *
mips_fbsd_lp64_fetch_link_map_offsets (void)
{
  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
    {
      lmp = &lmo;

      lmo.r_version_offset = 0;
      lmo.r_version_size = 4;
      lmo.r_map_offset = 8;
      lmo.r_brk_offset = 16;
      lmo.r_ldsomap_offset = -1;

      lmo.link_map_size = 48;
      lmo.l_addr_offset = 0;
      lmo.l_name_offset = 16;
      lmo.l_ld_offset = 24;
      lmo.l_next_offset = 32;
      lmo.l_prev_offset = 40;
    }

  return lmp;
}

static struct link_map_offsets *
mips_fbsd_c128_fetch_link_map_offsets (void)
{
  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
    {
      lmp = &lmo;

      lmo.r_version_offset = 0;
      lmo.r_version_size = 4;
      lmo.r_map_offset = 16;
      lmo.r_brk_offset = 32;
      lmo.r_ldsomap_offset = -1;

      lmo.link_map_size = 96;
      lmo.l_addr_offset = 0;
      lmo.l_name_offset = 32; 
      lmo.l_ld_offset = 48;
      lmo.l_next_offset = 64;
      lmo.l_prev_offset = 80;
    }

  return lmp;
}

static struct link_map_offsets *
mips_fbsd_c256_fetch_link_map_offsets (void)
{
  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
    {
      lmp = &lmo;

      lmo.r_version_offset = 0;
      lmo.r_version_size = 4;
      lmo.r_map_offset = 32;
      lmo.r_brk_offset = 64;
      lmo.r_ldsomap_offset = -1;

      lmo.link_map_size = 192;
      lmo.l_addr_offset = 0;
      lmo.l_name_offset = 64; 
      lmo.l_ld_offset = 96;
      lmo.l_next_offset = 128;
      lmo.l_prev_offset = 160;
    }

  return lmp;
}

/* Both capability formats store the cursor at the same relative offset
   from the start of the capability.  */

static CORE_ADDR
mips_fbsd_cheri_pointer_to_address (struct gdbarch *gdbarch, struct type *type,
				   const gdb_byte *buf)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  if (type->length == 8)
    return extract_unsigned_integer (buf, 8, byte_order);
  else
    return extract_unsigned_integer (buf + 8, 8, byte_order);
}

static void
mips_fbsd_cheri_address_to_pointer (struct gdbarch *gdbarch, struct type *type,
				    gdb_byte *buf, CORE_ADDR addr)
{
  /* XXX: This does not generate a valid capability.  However, a round-trip
     that converts an address to a pointer back to an address will work
     with this implementation. */
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  memset (buf, 0, type->length);
  if (type->length == 8)
    store_unsigned_integer (buf, 8, byte_order, addr);
  else
    store_unsigned_integer (buf + 8, 8, byte_order, addr);
}

/* default_auxv_parse almost works, but we want to parse entries that
   pass pointers and extract the pointer instead of returning just
   the first N bytes as an address.  */

static int
mips_fbsd_cheri_auxv_parse (struct gdbarch *gdbarch, gdb_byte **readptr,
			   gdb_byte *endptr, CORE_ADDR *typep, CORE_ADDR *valp)
{
  const int sizeof_auxv_field = gdbarch_ptr_bit (gdbarch) / TARGET_CHAR_BIT;
  const int sizeof_long = gdbarch_long_bit (gdbarch) / TARGET_CHAR_BIT;
  const enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  gdb_byte *ptr = *readptr;

  if (endptr == ptr)
    return 0;

  if (endptr - ptr < sizeof_auxv_field * 2)
    return -1;

  *typep = extract_unsigned_integer (ptr, sizeof_long, byte_order);
  ptr += sizeof_auxv_field;

  switch (*typep)
    {
    case AT_PHDR:
    case AT_BASE:
    case AT_ENTRY:
    case AT_FREEBSD_EXECPATH:
    case AT_FREEBSD_CANARY:
    case AT_FREEBSD_PAGESIZES:
    case AT_FREEBSD_TIMEKEEP:
      *valp = extract_typed_address (ptr,
				     builtin_type (gdbarch)->builtin_data_ptr);
      break;
    default:
      *valp = extract_unsigned_integer (ptr, sizeof_long, byte_order);
    }
  ptr += sizeof_auxv_field;

  *readptr = ptr;
  return 1;
}

static int
mips_fbsd_is_cheri(struct bfd *abfd)
{
  if ((elf_elfheader (abfd)->e_flags & (EF_MIPS_ABI | EF_MIPS_MACH))
      == (E_MIPS_ABI_CHERIABI | E_MIPS_MACH_CHERI256)
      || (elf_elfheader (abfd)->e_flags & (EF_MIPS_ABI | EF_MIPS_MACH))
      == (E_MIPS_ABI_CHERIABI | E_MIPS_MACH_CHERI128))
    return 1;
  if (elf_elfheader (abfd)->e_machine == EM_MIPS_CHERI
      || elf_elfheader (abfd)->e_machine == EM_MIPS_CHERI128)
    return 1;
  return 0;
}

static int
mips_fbsd_cheri_size(struct bfd *abfd)
{
  if ((elf_elfheader (abfd)->e_flags & EF_MIPS_ABI) == E_MIPS_ABI_CHERIABI)
    {
      switch (elf_elfheader (abfd)->e_flags & EF_MIPS_MACH)
	{
	case E_MIPS_MACH_CHERI256:
	  return 256;
	case E_MIPS_MACH_CHERI128:
	  return 128;
	default:
	  return 0;
	}
    }
  switch (elf_elfheader (abfd)->e_machine)
    {
    case EM_MIPS_CHERI:
      return 256;
    case EM_MIPS_CHERI128:
      return 128;
    default:
      return 0;
    }
}
  
static void
mips_fbsd_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  enum mips_abi abi = mips_abi (gdbarch);
  int cap_size;

  /* Generic FreeBSD support.  */
  fbsd_init_abi (info, gdbarch);

  set_gdbarch_software_single_step (gdbarch, mips_software_single_step);

  switch (abi)
    {
      case MIPS_ABI_O32:
	tramp_frame_prepend_unwinder (gdbarch, &mips_fbsd_sigframe);
	break;
      case MIPS_ABI_N32:
	break;
      case MIPS_ABI_N64:
	tramp_frame_prepend_unwinder (gdbarch, &mips64_fbsd_sigframe);
	break;
    }

  set_gdbarch_iterate_over_regset_sections
    (gdbarch, mips_fbsd_iterate_over_regset_sections);

  set_gdbarch_core_read_description (gdbarch, mips_fbsd_core_read_description);

  /* CHERI */
  if (info.abfd != NULL  && mips_fbsd_is_cheri (info.abfd)) {
    cap_size = mips_fbsd_cheri_size (info.abfd);
    set_gdbarch_addr_bit (gdbarch, 64);
    set_gdbarch_ptr_bit (gdbarch, cap_size);
    set_gdbarch_dwarf2_addr_size (gdbarch, 8);
    set_gdbarch_pointer_to_address (gdbarch,
				    mips_fbsd_cheri_pointer_to_address);
    set_gdbarch_address_to_pointer (gdbarch,
				    mips_fbsd_cheri_address_to_pointer);
    set_gdbarch_auxv_parse (gdbarch, mips_fbsd_cheri_auxv_parse);
    set_solib_svr4_fetch_link_map_offsets
      (gdbarch, cap_size == 128 ?
       mips_fbsd_c128_fetch_link_map_offsets :
       mips_fbsd_c256_fetch_link_map_offsets);
    return;
  }

  /* FreeBSD/mips has SVR4-style shared libraries.  */
  set_solib_svr4_fetch_link_map_offsets
    (gdbarch, (gdbarch_ptr_bit (gdbarch) == 32 ?
	       mips_fbsd_ilp32_fetch_link_map_offsets :
	       mips_fbsd_lp64_fetch_link_map_offsets));
}


/* Provide a prototype to silence -Wmissing-prototypes.  */
void _initialize_mips_fbsd_tdep (void);

void
_initialize_mips_fbsd_tdep (void)
{
  gdbarch_register_osabi (bfd_arch_mips, 0, GDB_OSABI_FREEBSD_ELF,
			  mips_fbsd_init_abi);
}

/* Target-dependent code for FreeBSD/aarch64.

   Copyright (C) 2017-2023 Free Software Foundation, Inc.

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

#include "gdbarch.h"
#include "fbsd-tdep.h"
#include "aarch64-tdep.h"
#include "aarch64-fbsd-tdep.h"
#include "comparts.h"
#include "inferior.h"
#include "gdbcore.h"
#include "osabi.h"
#include "solib-svr4.h"
#include "target.h"
#include "tramp-frame.h"
#include "trad-frame.h"

#include "gdbsupport/capability.h"

/* Register maps.  */

static const struct regcache_map_entry aarch64_fbsd_gregmap[] =
  {
    { 30, AARCH64_X0_REGNUM, 8 }, /* x0 ... x29 */
    { 1, AARCH64_LR_REGNUM, 8 },
    { 1, AARCH64_SP_REGNUM, 8 },
    { 1, AARCH64_PC_REGNUM, 8 },
    { 1, AARCH64_CPSR_REGNUM, 4 },
    { 0 }
  };

static const struct regcache_map_entry aarch64_fbsd_fpregmap[] =
  {
    { 32, AARCH64_V0_REGNUM, 16 }, /* v0 ... v31 */
    { 1, AARCH64_FPSR_REGNUM, 4 },
    { 1, AARCH64_FPCR_REGNUM, 4 },
    { 0 }
  };

/* Register numbers are relative to tdep->tls_regnum_base.  */

static const struct regcache_map_entry aarch64_fbsd_tls_regmap[] =
  {
    { 1, 0, 8 },	/* tpidr */
    { 0 }
  };

/* Register numbers are relative to tdep->cap_reg_base.  */

static const struct regcache_map_entry aarch64_fbsd_capregmap[] =
  {
    { 30, AARCH64_C0_REGNUM(0), 16 }, /* c0 ... c29 */
    { 1, AARCH64_CLR_REGNUM(0), 16 },
    { 1, AARCH64_ECSP_REGNUM(0), 16 },
    { 1, AARCH64_PCC_REGNUM(0), 16 },
    { 1, AARCH64_EDDC_REGNUM(0), 16 },
    { 1, AARCH64_ECTPIDR_REGNUM(0), 16 },
    { 1, REGCACHE_MAP_SKIP, 16 }, /* ctpidrro */
    { 1, AARCH64_CID_REGNUM(0), 16 },
    { 1, AARCH64_RCSP_REGNUM(0), 16 },
    { 1, AARCH64_RDDC_REGNUM(0), 16 },
    { 1, AARCH64_RCTPIDR_REGNUM(0), 16 },
    { 2, REGCACHE_MAP_SKIP, 8 },  /* tagmask and pad */
    { 0 }
  };

#define	TAGMASK_OFFSET		(16 * 40)

/* In a signal frame, sp points to a 'struct sigframe' which is
   defined as:

   struct sigframe {
	   siginfo_t	sf_si;
	   ucontext_t	sf_uc;
   };

   ucontext_t is defined as:

   struct __ucontext {
	   sigset_t	uc_sigmask;
	   mcontext_t	uc_mcontext;
	   ...
   };

   The mcontext_t contains the general purpose register set followed
   by the floating point register set.  The floating point register
   set is only valid if the _MC_FP_VALID flag is set in mc_flags.  */

#define AARCH64_SIGFRAME_UCONTEXT_OFFSET	80
#define AARCH64_UCONTEXT_MCONTEXT_OFFSET	16
#define	AARCH64_MCONTEXT_FPREGS_OFFSET		272
#define	AARCH64_MCONTEXT_FLAGS_OFFSET		800
#define AARCH64_MCONTEXT_FLAG_FP_VALID		0x1

/* Implement the "init" method of struct tramp_frame.  */

static void
aarch64_fbsd_sigframe_init (const struct tramp_frame *self,
			     frame_info_ptr this_frame,
			     struct trad_frame_cache *this_cache,
			     CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR sp = get_frame_register_unsigned (this_frame, AARCH64_SP_REGNUM);
  CORE_ADDR mcontext_addr
    = (sp
       + AARCH64_SIGFRAME_UCONTEXT_OFFSET
       + AARCH64_UCONTEXT_MCONTEXT_OFFSET);
  gdb_byte buf[4];

  trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_gregmap, mcontext_addr,
			     regcache_map_entry_size (aarch64_fbsd_gregmap));

  if (target_read_memory (mcontext_addr + AARCH64_MCONTEXT_FLAGS_OFFSET, buf,
			  4) == 0
      && (extract_unsigned_integer (buf, 4, byte_order)
	  & AARCH64_MCONTEXT_FLAG_FP_VALID))
    trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_fpregmap,
			       mcontext_addr + AARCH64_MCONTEXT_FPREGS_OFFSET,
			       regcache_map_entry_size (aarch64_fbsd_fpregmap));

  trad_frame_set_id (this_cache, frame_id_build (sp, func));
}

static const struct tramp_frame aarch64_fbsd_sigframe =
{
  SIGTRAMP_FRAME,
  4,
  {
    {0x910003e0, ULONGEST_MAX},		/* mov  x0, sp  */
    {0x91014000, ULONGEST_MAX},		/* add  x0, x0, #SF_UC  */
    {0xd2803428, ULONGEST_MAX},		/* mov  x8, #SYS_sigreturn  */
    {0xd4000001, ULONGEST_MAX},		/* svc  0x0  */
    {TRAMP_SENTINEL_INSN, ULONGEST_MAX}
  },
  aarch64_fbsd_sigframe_init
};

/* The CheriABI sigframe replaces struct gpregs at offset 0 of
   mcontext_t with a struct capregs.  This holds capability-sized
   registers for all GPRs.  To aid with this, two extra register maps
   are defined below.  The first one populates the X registers from
   mc_capregs.  The second populates the C registers.  */

#define AARCH64C_SIGFRAME_UCONTEXT_OFFSET	112
#define AARCH64C_UCONTEXT_MCONTEXT_OFFSET	16
#define	AARCH64C_MCONTEXT_CAPREGS_OFFSET	0
#define	AARCH64C_MCONTEXT_FPREGS_OFFSET		544
#define	AARCH64C_MCONTEXT_FLAGS_OFFSET		1072
#define AARCH64C_MCONTEXT_FLAG_FP_VALID		0x1
#define	AARCH64C_MCONTEXT_SPSR_OFFSET		1076

static const struct regcache_map_entry aarch64_fbsd_cheriabi_gregmap[] =
  {
    { 30, AARCH64_X0_REGNUM, 16 }, /* x0 ... x29 */
    { 1, AARCH64_LR_REGNUM, 16 },
    { 1, AARCH64_SP_REGNUM, 16 },
    { 1, AARCH64_PC_REGNUM, 16 },
    { 0 }
  };

const struct regcache_map_entry aarch64_fbsd_cheriabi_capregmap[] =
  {
    { 30, AARCH64_C0_REGNUM(0), 16 }, /* c0 ... c29 */
    { 1, AARCH64_CLR_REGNUM(0), 16 },
    { 1, AARCH64_ECSP_REGNUM(0), 16 },
    { 1, AARCH64_PCC_REGNUM(0), 16 },
    { 1, AARCH64_EDDC_REGNUM(0), 16 },
    { 0 }
  };

/* Implement the "init" method of struct tramp_frame.  */

static void
aarch64_fbsd_cheriabi_sigframe_init (const struct tramp_frame *self,
				     frame_info_ptr this_frame,
				     struct trad_frame_cache *this_cache,
				     CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR sp = get_frame_register_unsigned (this_frame, tdep->cap_reg_ecsp);
  CORE_ADDR mcontext_addr
    = (sp
       + AARCH64C_SIGFRAME_UCONTEXT_OFFSET
       + AARCH64C_UCONTEXT_MCONTEXT_OFFSET);
  gdb_byte buf[4];

  /* SPSR.  */
  trad_frame_set_reg_addr (this_cache, AARCH64_CPSR_REGNUM,
			   mcontext_addr + AARCH64C_MCONTEXT_SPSR_OFFSET);

  /* X registers.  */
  trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_cheriabi_gregmap,
			     mcontext_addr + AARCH64C_MCONTEXT_CAPREGS_OFFSET,
			     regcache_map_entry_size
			     (aarch64_fbsd_cheriabi_gregmap));

  /* C registers.  */
  trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_cheriabi_capregmap,
			     mcontext_addr + AARCH64C_MCONTEXT_CAPREGS_OFFSET,
			     regcache_map_entry_size
			     (aarch64_fbsd_cheriabi_capregmap),
			     tdep->cap_reg_base);

  if (target_read_memory (mcontext_addr + AARCH64C_MCONTEXT_FLAGS_OFFSET, buf,
			  4) == 0
      && (extract_unsigned_integer (buf, 4, byte_order)
	  & AARCH64C_MCONTEXT_FLAG_FP_VALID))
    trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_fpregmap,
			       mcontext_addr + AARCH64C_MCONTEXT_FPREGS_OFFSET,
			       regcache_map_entry_size (aarch64_fbsd_fpregmap));

  trad_frame_set_id (this_cache, frame_id_build (sp, func));
}

static const struct tramp_frame aarch64_fbsd_cheriabi_sigframe =
{
  SIGTRAMP_FRAME,
  4,
  {
    {0x0201c3e0, ULONGEST_MAX},		/* add  c0, csp, #SF_UC  */
    {0xd2803428, ULONGEST_MAX},		/* mov  x8, #SYS_sigreturn  */
    {0xd4000001, ULONGEST_MAX},		/* svc  0x0  */
    {TRAMP_SENTINEL_INSN, ULONGEST_MAX}
  },
  aarch64_fbsd_cheriabi_sigframe_init
};

/* CheriABI compartmentalization trampoline frames.

   These unwind past the start of tramp_pop_frame.  */

/* Determine which stack pointer to pull CSP from by reading the new
   PCC from an address and checking its permissions.  */

static int
c18nframe_pcc_executive (frame_info_ptr this_frame, CORE_ADDR pcc_addr)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);
  struct value *val = frame_unwind_got_memory (this_frame, tdep->cap_reg_pcc,
					       pcc_addr);
  val->fetch_lazy ();
  capability cap = aarch64_capability_from_value (val);
  return cap.check_permissions (CAP_PERM_EXECUTIVE);
}

/* Version 0 is before commit 7f60b7deff9943eed7d9d94f3643d90ed9120d6d.  */

static const struct regcache_map_entry aarch64_fbsd_c18n_gregmap_v0[] =
  {
    { 2, REGCACHE_MAP_SKIP, 8 }, /* next and cookie */
    { 1, REGCACHE_MAP_SKIP, 16 }, /* rcsp (o_stack) */
    { 1, AARCH64_PC_REGNUM, 16 },
    { 11, AARCH64_X0_REGNUM + 19, 16 }, /* x19 ... x29 */
    { 0 }
  };

const struct regcache_map_entry aarch64_fbsd_c18n_capregmap_v0[] =
  {
    { 2, REGCACHE_MAP_SKIP, 8 }, /* next and cookie */
    { 1, AARCH64_RCSP_REGNUM(0), 16 },
    { 1, AARCH64_PCC_REGNUM(0), 16 },
    { 11, AARCH64_C0_REGNUM(0) + 19, 16 }, /* c19 ... c29 */
    { 0 }
  };

/* Implement the "init" method of struct tramp_frame.  */

static void
aarch64_fbsd_c18nframe_init_v0 (const struct tramp_frame *self,
				frame_info_ptr this_frame,
				struct trad_frame_cache *this_cache,
				CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  gdb_byte buf[8];

  /* Fetch the address of the executive CSP which points to the
     trusted frame.  */
  CORE_ADDR sp = frame_unwind_register_unsigned (this_frame,
						 tdep->cap_reg_ecsp);

  /* Saved X registers.  */
  trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_c18n_gregmap_v0, sp,
			     regcache_map_entry_size
			     (aarch64_fbsd_c18n_gregmap_v0));

  /* Saved C registers.  */
  trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_c18n_capregmap_v0, sp,
			     regcache_map_entry_size
			     (aarch64_fbsd_c18n_capregmap_v0),
			     tdep->cap_reg_base);

  bool csp_is_ecsp = c18nframe_pcc_executive (this_frame, sp + 32);
  if (!csp_is_ecsp)
    trad_frame_set_reg_addr (this_cache, tdep->cap_reg_csp, sp + 16);

  if (target_read_memory (sp, buf, 8) == 0)
    {
      ULONGEST next = extract_unsigned_integer (buf, 8, byte_order);

      /* Update ECSP with address from next.  */
      struct value *ecsp = frame_unwind_register_value (this_frame,
							tdep->cap_reg_ecsp);
      struct value *new_ecsp = aarch64_convert_pointer_to_capability (ecsp,
								      next);
      trad_frame_set_reg_value_bytes (this_cache, tdep->cap_reg_ecsp,
				      new_ecsp->contents ());
      if (csp_is_ecsp)
	trad_frame_set_reg_value_bytes (this_cache, tdep->cap_reg_csp,
					new_ecsp->contents ());
    }

  trad_frame_set_id (this_cache, frame_id_build (sp, func));
}

static const struct tramp_frame aarch64_fbsd_c18nframe_v0 =
{
  COMPARTMENT_FRAME,
  4,
  {
    {0xa9402fea, ULONGEST_MAX},		/* ldp     x10, x11, [csp]  */
    {0xc24007ec, ULONGEST_MAX},		/* ldr     c12, [csp, #16]  */
    {0x42c14ffe, ULONGEST_MAX},		/* ldp     c30, c19, [csp, #32] */
    {TRAMP_SENTINEL_INSN, ULONGEST_MAX}
  },
  aarch64_fbsd_c18nframe_init_v0,
};

/* The second version is after commit
   7f60b7deff9943eed7d9d94f3643d90ed9120d6d and assumes a compartment
   ID at the bottom of the restricted stack.  */

static const struct regcache_map_entry aarch64_fbsd_c18n_gregmap_v1[] =
  {
    { 1, AARCH64_X0_REGNUM + 29, 16 }, /* x29 */
    { 1, AARCH64_PC_REGNUM, 16 },
    { 2, REGCACHE_MAP_SKIP, 8 }, /* next and cookie */
    { 1, REGCACHE_MAP_SKIP, 16 }, /* rcsp (o_sp) */
    { 10, AARCH64_X0_REGNUM + 19, 16 }, /* x19 ... x28 */
    { 0 }
  };

const struct regcache_map_entry aarch64_fbsd_c18n_capregmap_v1[] =
  {
    { 1, AARCH64_C0_REGNUM(0) + 29, 16 }, /* c29 */
    { 1, AARCH64_PCC_REGNUM(0), 16 },
    { 2, REGCACHE_MAP_SKIP, 8 }, /* next and cookie */
    { 1, AARCH64_RCSP_REGNUM(0), 16 },
    { 10, AARCH64_C0_REGNUM(0) + 19, 16 }, /* c19 ... c28 */
    { 0 }
  };

/* Implement the "init" method of struct tramp_frame.  */

static void
aarch64_fbsd_c18nframe_init_v1 (const struct tramp_frame *self,
				frame_info_ptr this_frame,
				struct trad_frame_cache *this_cache,
				CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  gdb_byte buf[8];

  /* Fetch the address of the executive CSP which points to the
     trusted frame.  */
  CORE_ADDR sp = frame_unwind_register_unsigned (this_frame,
						 tdep->cap_reg_ecsp);

  /* Saved X registers.  */
  trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_c18n_gregmap_v1, sp,
			     regcache_map_entry_size
			     (aarch64_fbsd_c18n_gregmap_v1));

  /* Saved C registers.  */
  trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_c18n_capregmap_v1, sp,
			     regcache_map_entry_size
			     (aarch64_fbsd_c18n_capregmap_v1),
			     tdep->cap_reg_base);

  bool csp_is_ecsp = c18nframe_pcc_executive (this_frame, sp + 16);
  if (!csp_is_ecsp)
    trad_frame_set_reg_addr (this_cache, tdep->cap_reg_csp, sp + 48);

  if (target_read_memory (sp + 32, buf, 8) == 0)
    {
      ULONGEST next = extract_unsigned_integer (buf, 8, byte_order);

      /* Update ECSP with address from next.  */
      struct value *ecsp = frame_unwind_register_value (this_frame,
							tdep->cap_reg_ecsp);
      struct value *new_ecsp = aarch64_convert_pointer_to_capability (ecsp,
								      next);
      trad_frame_set_reg_value_bytes (this_cache, tdep->cap_reg_ecsp,
				      new_ecsp->contents ());
      if (csp_is_ecsp)
	trad_frame_set_reg_value_bytes (this_cache, tdep->cap_reg_csp,
					new_ecsp->contents ());
    }

  trad_frame_set_id (this_cache, frame_id_build (sp, func));
}

static void
aarch64_fbsd_c18nframe_print_info_v1 (frame_info_ptr this_frame,
				      struct ui_out *uiout)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  gdb_byte buf[2];

  /* Fetch the address of the bottom of the restricted CSP.  */
  struct value *val = frame_unwind_register_value (this_frame,
						   tdep->cap_reg_rcsp);
  capability rcsp = aarch64_capability_from_value (val);
  CORE_ADDR bottom = rcsp.get_limit ();

  /* The stack bottom is 32 bytes in size.  */
  bottom -= 32;

  /* Read the compartment ID.  */
  if (target_read_memory (bottom, buf, 2) == 0)
    {
      ULONGEST cid = extract_unsigned_integer (buf, 2, byte_order);
      uiout->text (", caller id ");
      uiout->field_string ("caller-id", pulongest (cid));
    }
}

static const struct tramp_frame aarch64_fbsd_c18nframe_v1 =
{
  COMPARTMENT_FRAME,
  4,
  {
    {0x42c07bfd, ULONGEST_MAX},		/* ldp     c29, c30, [csp]  */
    {0xa9422fea, ULONGEST_MAX},		/* ldp     x10, x11, [csp, #32]  */
    {0x42c1cfec, ULONGEST_MAX},		/* ldp     c12, c19, [csp, #48] */
    {TRAMP_SENTINEL_INSN, ULONGEST_MAX}
  },
  aarch64_fbsd_c18nframe_init_v1,
  nullptr,
  nullptr,
  aarch64_fbsd_c18nframe_print_info_v1
};

/* The current version is after commit
   9adf0524a740f88d3991ee277cd71e4f61ef0626 and assumes a compartment
   ID and optional compartment name address at the bottom of the
   restricted stack.  Also includes a proper rcsp and ecsp address in
   the frame.  */

static const struct regcache_map_entry aarch64_fbsd_c18n_gregmap[] =
  {
    { 1, AARCH64_X0_REGNUM + 29, 16 }, /* x29 */
    { 1, AARCH64_PC_REGNUM, 16 },
    { 2, REGCACHE_MAP_SKIP, 8 }, /* next and cookie */
    { 1, REGCACHE_MAP_SKIP, 16 }, /* rcsp (n_sp) */
    { 2, REGCACHE_MAP_SKIP, 8 }, /* o_sp and csp */
    { 10, AARCH64_X0_REGNUM + 19, 16 }, /* x19 ... x28 */
    { 0 }
  };

const struct regcache_map_entry aarch64_fbsd_c18n_capregmap[] =
  {
    { 1, AARCH64_C0_REGNUM(0) + 29, 16 }, /* c29 */
    { 1, AARCH64_PCC_REGNUM(0), 16 },
    { 2, REGCACHE_MAP_SKIP, 8 }, /* next and cookie */
    { 1, AARCH64_RCSP_REGNUM(0), 16 },
    { 2, REGCACHE_MAP_SKIP, 8 }, /* o_sp and csp */
    { 10, AARCH64_C0_REGNUM(0) + 19, 16 }, /* c19 ... c28 */
    { 0 }
  };

/* Implement the "init" method of struct tramp_frame.  */

static void
aarch64_fbsd_c18nframe_init (const struct tramp_frame *self,
			     frame_info_ptr this_frame,
			     struct trad_frame_cache *this_cache,
			     CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  gdb_byte buf[8];

  /* Fetch the address of the executive CSP which points to the
     trusted frame.  */
  CORE_ADDR sp = frame_unwind_register_unsigned (this_frame,
						 tdep->cap_reg_ecsp);

  /* Saved X registers.  */
  trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_c18n_gregmap, sp,
			     regcache_map_entry_size
			     (aarch64_fbsd_c18n_gregmap));

  /* Saved C registers.  */
  trad_frame_set_reg_regmap (this_cache, aarch64_fbsd_c18n_capregmap, sp,
			     regcache_map_entry_size
			     (aarch64_fbsd_c18n_capregmap),
			     tdep->cap_reg_base);

  bool csp_is_ecsp = c18nframe_pcc_executive (this_frame, sp + 16);
  if (!csp_is_ecsp)
    trad_frame_set_reg_addr (this_cache, tdep->cap_reg_csp, sp + 48);

  if (target_read_memory (sp + 72, buf, 8) == 0)
    {
      ULONGEST csp = extract_unsigned_integer (buf, 8, byte_order);

      /* Update ECSP with address from csp.  */
      struct value *ecsp = frame_unwind_register_value (this_frame,
							tdep->cap_reg_ecsp);
      struct value *new_ecsp = aarch64_convert_pointer_to_capability (ecsp,
								      csp);
      trad_frame_set_reg_value_bytes (this_cache, tdep->cap_reg_ecsp,
				      new_ecsp->contents ());
      if (csp_is_ecsp)
	trad_frame_set_reg_value_bytes (this_cache, tdep->cap_reg_csp,
					new_ecsp->contents ());
    }

  trad_frame_set_id (this_cache, frame_id_build (sp, func));
}

static bool
fetch_c18n_stack_info (struct gdbarch *gdbarch, struct value *val,
		       LONGEST &id, gdb::unique_xmalloc_ptr<char> &name)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  gdb_byte buf[16];

  id = -1;
  name.reset (nullptr);

  /* Compute the address of the bottom of the compartment's stack.
     The compartment stack bottom is 32 bytes in size, so if the
     capability is too small, just bail.  */
  capability rcsp = aarch64_capability_from_value (val);
  if (rcsp.get_length () < 32)
    return false;

  CORE_ADDR bottom = rcsp.get_limit () - 32;

  /* Read the compartment ID and compartment name address.  */
  if (target_read_memory (bottom, buf, sizeof (buf)) != 0)
    return false;

  id = extract_unsigned_integer (buf, 2, byte_order);

  CORE_ADDR name_addr = extract_unsigned_integer (buf + 8, 8, byte_order);
  if (name_addr != 0)
    name = target_read_string (name_addr, 1024);

  return true;
}

static void
aarch64_fbsd_c18nframe_print_info (frame_info_ptr this_frame,
				   struct ui_out *uiout)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);
  gdb::unique_xmalloc_ptr<char> name;
  LONGEST id;

  /* The caller's restricted stack.  */
  struct value *caller = frame_unwind_register_value (this_frame,
						      tdep->cap_reg_rcsp);
  uiout->text (", from ");
  if (fetch_c18n_stack_info (gdbarch, caller, id, name))
    {
      if (name != nullptr)
	uiout->message ("\"%pF\" ", string_field ("caller-name", name.get ()));
      uiout->message ("(ID: %pF)", signed_field ("caller-id", id));
    }
  else
    uiout->text ("<unknown>");

  /* The callee's restricted stack.  */
  struct value *callee = get_frame_register_value (this_frame,
						   tdep->cap_reg_rcsp);
  uiout->text (" to ");
  if (fetch_c18n_stack_info (gdbarch, callee, id, name))
    {
      if (name != nullptr)
	uiout->message ("\"%pF\" ", string_field ("callee-name", name.get ()));
      uiout->message ("(ID: %pF)", signed_field ("callee-id", id));
    }
  else
    uiout->text ("<unknown>");
}

static const struct tramp_frame aarch64_fbsd_c18nframe =
{
  COMPARTMENT_FRAME,
  4,
  {
    {0x42c07bfd, ULONGEST_MAX},		/* ldp     c29, c30, [csp]  */
    {0xa9422fea, ULONGEST_MAX},		/* ldp     x10, x11, [csp, #32]  */
    {0x42c1b3ef, ULONGEST_MAX},		/* ldp     c15, c12, [csp, #48] */
    {TRAMP_SENTINEL_INSN, ULONGEST_MAX}
  },
  aarch64_fbsd_c18nframe_init,
  nullptr,
  nullptr,
  aarch64_fbsd_c18nframe_print_info
};

/* Register set definitions.  */

const struct regset aarch64_fbsd_gregset =
  {
    aarch64_fbsd_gregmap,
    regcache_supply_regset, regcache_collect_regset
  };

const struct regset aarch64_fbsd_fpregset =
  {
    aarch64_fbsd_fpregmap,
    regcache_supply_regset, regcache_collect_regset
  };

static void
aarch64_fbsd_supply_tls_regset (const struct regset *regset,
				struct regcache *regcache,
				int regnum, const void *buf, size_t size)
{
  struct gdbarch *gdbarch = regcache->arch ();
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);

  regcache->supply_regset (regset, tdep->tls_regnum_base, regnum, buf, size);
}

static void
aarch64_fbsd_collect_tls_regset (const struct regset *regset,
				 const struct regcache *regcache,
				 int regnum, void *buf, size_t size)
{
  struct gdbarch *gdbarch = regcache->arch ();
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);

  regcache->collect_regset (regset, tdep->tls_regnum_base, regnum, buf, size);
}

const struct regset aarch64_fbsd_tls_regset =
  {
    aarch64_fbsd_tls_regmap,
    aarch64_fbsd_supply_tls_regset, aarch64_fbsd_collect_tls_regset
  };

static int
tag_map_regno(aarch64_gdbarch_tdep *tdep, int idx)
{
  switch (idx)
    {
    default:
      return AARCH64_C0_REGNUM(tdep->cap_reg_base) + idx;
    case 35:
      return -1;	/* ctpidrro */
    case 36:
      return AARCH64_CID_REGNUM(tdep->cap_reg_base);
    case 37:
      return AARCH64_RCSP_REGNUM(tdep->cap_reg_base);
    case 38:
      return AARCH64_RDDC_REGNUM(tdep->cap_reg_base);
    case 39:
      return AARCH64_RCTPIDR_REGNUM(tdep->cap_reg_base);
    }
}

static void
aarch64_fbsd_supply_capregset (const struct regset *regset,
			       struct regcache *regcache,
			       int regnum, const void *buf, size_t size)
{
  struct gdbarch *gdbarch = regcache->arch ();
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);

  regcache->supply_regset (regset, tdep->cap_reg_base, regnum, buf, size);

  uint64_t tag_map = extract_unsigned_integer ((const gdb_byte *)buf
					       + TAGMASK_OFFSET, 8,
					       gdbarch_byte_order (gdbarch));
  for (unsigned i = 0; i < 40; i++)
    {
      int regno;
      bool tag;

      tag = tag_map & 1;
      tag_map >>= 1;
      regno = tag_map_regno(tdep, i);
      if (regno == -1)
	continue;
      if (regnum == -1 || regno == regnum)
	regcache->raw_supply_tag (regno, tag);
    }
}

static void
aarch64_fbsd_collect_capregset (const struct regset *regset,
				const struct regcache *regcache,
				int regnum, void *buf, size_t size)
{
  struct gdbarch *gdbarch = regcache->arch ();
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);

  regcache->collect_regset (regset, tdep->cap_reg_base, regnum, buf, size);

  uint64_t tag_map = extract_unsigned_integer ((const gdb_byte *)buf
					       + TAGMASK_OFFSET, 8,
					       gdbarch_byte_order (gdbarch));
  for (unsigned i = 0; i < 40; i++)
    {
      uint64_t mask;
      int regno;

      regno = tag_map_regno(tdep, i);
      if (regno == -1)
	continue;
      if (regnum == -1 || regno == regnum)
	{
	  mask = (uint64_t)1 << i;
	  if (regcache->raw_collect_tag (regno))
	    tag_map |= mask;
	  else
	    tag_map &= ~mask;
	}
    }
  store_unsigned_integer ((gdb_byte *)buf + TAGMASK_OFFSET, 8,
			  gdbarch_byte_order (gdbarch), tag_map);
}

const struct regset aarch64_fbsd_capregset =
  {
    aarch64_fbsd_capregmap,
    aarch64_fbsd_supply_capregset, aarch64_fbsd_collect_capregset
  };

/* Implement the "iterate_over_regset_sections" gdbarch method.  */

static void
aarch64_fbsd_iterate_over_regset_sections (struct gdbarch *gdbarch,
					   iterate_over_regset_sections_cb *cb,
					   void *cb_data,
					   const struct regcache *regcache)
{
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);

  cb (".reg", AARCH64_FBSD_SIZEOF_GREGSET, AARCH64_FBSD_SIZEOF_GREGSET,
      &aarch64_fbsd_gregset, NULL, cb_data);
  cb (".reg2", AARCH64_FBSD_SIZEOF_FPREGSET, AARCH64_FBSD_SIZEOF_FPREGSET,
      &aarch64_fbsd_fpregset, NULL, cb_data);

  if (tdep->has_tls ())
    cb (".reg-aarch-tls", AARCH64_FBSD_SIZEOF_TLSREGSET,
	AARCH64_FBSD_SIZEOF_TLSREGSET, &aarch64_fbsd_tls_regset,
	"TLS register", cb_data);

  if (tdep->has_capability ())
    cb (".reg-cap", AARCH64_FBSD_SIZEOF_CAPREGSET,
	AARCH64_FBSD_SIZEOF_CAPREGSET, &aarch64_fbsd_capregset, NULL,
	cb_data);
}

/* Implement the "core_read_description" gdbarch method.  */

static const struct target_desc *
aarch64_fbsd_core_read_description (struct gdbarch *gdbarch,
				    struct target_ops *target, bfd *abfd)
{
  asection *tls = bfd_get_section_by_name (abfd, ".reg-aarch-tls");
  asection *cap = bfd_get_section_by_name (abfd, ".reg-cap");

  aarch64_features features;
  features.tls = tls != nullptr? 1 : 0;
  features.capability = cap != nullptr;

  return aarch64_read_description (features);
}

/* Implement the get_thread_local_address gdbarch method.  */

static CORE_ADDR
aarch64_fbsd_get_thread_local_address (struct gdbarch *gdbarch, ptid_t ptid,
				       CORE_ADDR lm_addr, CORE_ADDR offset)
{
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);
  struct regcache *regcache;
  int regnum;

  regcache = get_thread_arch_regcache (current_inferior ()->process_target (),
				       ptid, gdbarch);

  if (tdep->has_capability () && tdep->abi == AARCH64_ABI_AAPCS64_CAP)
    regnum = tdep->cap_reg_ctpidr;
  else
    regnum = tdep->tls_regnum_base;
  target_fetch_registers (regcache, regnum);

  ULONGEST tpidr;
  if (regcache->cooked_read (regnum, &tpidr) != REG_VALID)
    error (_("Unable to fetch %%tpidr"));

  /* %tpidr points to the TCB whose first member is the dtv
      pointer.  */
  CORE_ADDR dtv_addr = tpidr;
  return fbsd_get_thread_local_address (gdbarch, dtv_addr, lm_addr, offset);
}

struct fbsd_comparts_data
{
  /* Layout of struct compart.  */
  LONGEST compart_size = 0;
  LONGEST compart_name_off = 0;
  LONGEST compart_libs_off = 0;
  LONGEST compart_imports_off = 0;
  LONGEST compart_trusts_off = 0;

  /* Additional fields in r_debug.  */
  LONGEST r_comparts_size_off = 0;
  LONGEST r_comparts_off = 0;
};

static const registry<program_space>::key<fbsd_comparts_data>
  fbsd_comparts_data_handle;

static struct fbsd_comparts_data *
get_fbsd_comparts_data (struct program_space *pspace)
{
  struct fbsd_comparts_data *data;

  data = fbsd_comparts_data_handle.get (pspace);
  if (data == NULL)
    data = fbsd_comparts_data_handle.emplace (pspace);

  return data;
}

/* Lookup offsets of fields in the runtime linker's 'struct compart'
   needed to enumerate compartments.  */

static void
aarch64_fbsd_fetch_compart_offsets (struct gdbarch *gdbarch,
				    struct fbsd_comparts_data *data)
{
  try
    {
      /* Fetch offsets from debug symbols in rtld.  */
      struct symbol *compart_sym
	= lookup_symbol_in_language ("compart", NULL, STRUCT_DOMAIN,
				     language_c, NULL).symbol;
      if (compart_sym == NULL)
	error (_("Unable to find struct compart symbol"));
      data->compart_name_off = lookup_struct_elt (compart_sym->type (),
						  "name", 0).offset / 8;
      data->compart_libs_off = lookup_struct_elt (compart_sym->type (),
						  "libs", 0).offset / 8;
      data->compart_imports_off = lookup_struct_elt (compart_sym->type (),
						     "imports", 0).offset / 8;
      data->compart_trusts_off = lookup_struct_elt (compart_sym->type (),
						    "trusts", 0).offset / 8;
      data->compart_size = compart_sym->type ()->length ();

      data->r_comparts_size_off = 84;
      data->r_comparts_off = 96;
      return;
    }
  catch (const gdb_exception_error &e)
    {
      data->compart_size = -1;
    }

  try
    {
      /* Fetch size from a global variable in rtld.  */
      data->compart_size = fbsd_read_integer_by_name (gdbarch, "_compart_size");

      /* Assume default layout.  */
      data->compart_name_off = 0;
      data->compart_libs_off = 16;
      data->compart_imports_off = 48;
      data->compart_trusts_off = 80;

      data->r_comparts_size_off = 84;
      data->r_comparts_off = 96;
      return;
    }
  catch (const gdb_exception_error &e)
    {
      data->compart_size = -1;
    }
}

/* Implement the current_compartments gdbarch method.  */

static compart_list
aarch64_fbsd_current_comparts (struct gdbarch *gdbarch)
{
  CORE_ADDR debug_base = svr4_elf_locate_base ();
  if (debug_base == 0)
    return {};

  struct fbsd_comparts_data *data
    = get_fbsd_comparts_data (current_program_space);

  if (data->compart_size == 0)
    aarch64_fbsd_fetch_compart_offsets (gdbarch, data);

  if (data->compart_size == -1)
    return {};

  LONGEST count;
  if (safe_read_memory_integer(debug_base + data->r_comparts_size_off, 4,
			       gdbarch_byte_order (gdbarch), &count) == 0)
    error (_("Unable to read compartment count"));

  struct type *ptr_type = builtin_type (gdbarch)->builtin_data_ptr;
  CORE_ADDR comparts_addr = read_memory_typed_address (debug_base +
						       data->r_comparts_off,
						       ptr_type);

  compart_list comparts;
  for (LONGEST i = 0; i < count; i++)
    {
      compart_up c (new compart ());
      c->id = i;
      c->addr = comparts_addr + i * data->compart_size;
      CORE_ADDR name_addr
	= read_memory_typed_address (c->addr + data->compart_name_off,
				     ptr_type);
      gdb::unique_xmalloc_ptr<char> name
	= target_read_string (name_addr, SO_NAME_MAX_PATH_SIZE - 1);
      if (name == nullptr)
	c->name = "unknown";
      else
	c->name = name.get ();
      comparts.push_back (std::move (c));
    }
  return comparts;
}

/* Fetch a vector of strings from a struct string_base.  */

static std::vector<std::string>
aarch64_fetch_string_base (struct gdbarch *gdbarch, CORE_ADDR addr)
{
  struct type *ptr_type = builtin_type (gdbarch)->builtin_data_ptr;
  CORE_ADDR buf_addr = read_memory_typed_address (addr, ptr_type);
  LONGEST size = read_memory_integer (addr + ptr_type->length (), 8,
				      gdbarch_byte_order (gdbarch));
  if (size == 0)
    return {};

  gdb::unique_xmalloc_ptr<char> buf ((char *) xmalloc (size + 1));
  read_memory (buf_addr, (gdb_byte *) buf.get (), size);
  buf.get ()[size] = '\0';

  std::vector<std::string> list;
  char *cp = buf.get ();
  char *end = cp + size;
  while (cp < end) {
    if (*cp != '\0')
      list.emplace_back (cp);
    cp += strlen (cp) + 1;
  }
  return list;
}

/* Implement the fetch_compart_info gdbarch method.  */

static void
aarch64_fbsd_fetch_compart_info (struct gdbarch *gdbarch,
				 compart *c)
{
  struct fbsd_comparts_data *data
    = get_fbsd_comparts_data (current_program_space);

  try
    {
      c->libraries
	= aarch64_fetch_string_base (gdbarch, c->addr + data->compart_libs_off);
    }
  catch (const gdb_exception_error &e)
    {
    }

  try
    {
      c->imports
	= aarch64_fetch_string_base (gdbarch,
				     c->addr + data->compart_imports_off);
    }
  catch (const gdb_exception_error &e)
    {
    }

  try
    {
      c->trusts
	= aarch64_fetch_string_base (gdbarch,
				     c->addr + data->compart_trusts_off);
    }
  catch (const gdb_exception_error &e)
    {
    }
}

/* Implement the 'init_osabi' method of struct gdb_osabi_handler.  */

static void
aarch64_fbsd_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  aarch64_gdbarch_tdep *tdep = gdbarch_tdep<aarch64_gdbarch_tdep> (gdbarch);

  /* Generic FreeBSD support.  */
  fbsd_init_abi (info, gdbarch);

  if (tdep->abi == AARCH64_ABI_AAPCS64_CAP)
    {
      set_solib_svr4_fetch_link_map_offsets
	(gdbarch, svr4_lp64_cheri_fetch_link_map_offsets);
      set_gdbarch_current_comparts (gdbarch, aarch64_fbsd_current_comparts);
      set_gdbarch_fetch_compart_info (gdbarch, aarch64_fbsd_fetch_compart_info);

      tramp_frame_prepend_unwinder (gdbarch, &aarch64_fbsd_cheriabi_sigframe);
      tramp_frame_prepend_unwinder (gdbarch, &aarch64_fbsd_c18nframe_v0);
      tramp_frame_prepend_unwinder (gdbarch, &aarch64_fbsd_c18nframe_v1);
      tramp_frame_prepend_unwinder (gdbarch, &aarch64_fbsd_c18nframe);
    }
  else
    {
      set_solib_svr4_fetch_link_map_offsets (gdbarch,
					     svr4_lp64_fetch_link_map_offsets);

      tramp_frame_prepend_unwinder (gdbarch, &aarch64_fbsd_sigframe);
    }

  /* Enable longjmp.  */
  tdep->jb_pc = 13;

  set_gdbarch_iterate_over_regset_sections
    (gdbarch, aarch64_fbsd_iterate_over_regset_sections);
  set_gdbarch_core_read_description (gdbarch,
				     aarch64_fbsd_core_read_description);

  if (tdep->has_tls () || tdep->abi == AARCH64_ABI_AAPCS64_CAP)
    {
      set_gdbarch_fetch_tls_load_module_address (gdbarch,
						 svr4_fetch_objfile_link_map);
      set_gdbarch_get_thread_local_address
	(gdbarch, aarch64_fbsd_get_thread_local_address);
    }
}

void _initialize_aarch64_fbsd_tdep ();
void
_initialize_aarch64_fbsd_tdep ()
{
  gdbarch_register_osabi (bfd_arch_aarch64, 0, GDB_OSABI_FREEBSD,
			  aarch64_fbsd_init_abi);
}

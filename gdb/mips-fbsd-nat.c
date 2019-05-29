/* Native-dependent code for FreeBSD/mips.

   Copyright (C) 2017-2019 Free Software Foundation, Inc.

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
#include "inferior.h"
#include "regcache.h"
#include "target.h"

#include <sys/types.h>
#include <sys/ptrace.h>
#include <machine/reg.h>

#include "fbsd-nat.h"
#include "mips-tdep.h"
#include "mips-fbsd-tdep.h"
#include "inf-ptrace.h"

struct mips_fbsd_nat_target final : public fbsd_nat_target
{
  void fetch_registers (struct regcache *, int) override;
  void store_registers (struct regcache *, int) override;
};

static mips_fbsd_nat_target the_mips_fbsd_nat_target;

/* Determine if PT_GETREGS fetches REGNUM.  */

static bool
getregs_supplies (struct gdbarch *gdbarch, int regnum)
{
  return (regnum >= MIPS_ZERO_REGNUM
	  && regnum <= mips_regnum (gdbarch)->pc);
}

/* Determine if PT_GETFPREGS fetches REGNUM.  */

static bool
getfpregs_supplies (struct gdbarch *gdbarch, int regnum)
{
  return (regnum >= mips_regnum (gdbarch)->fp0
	  && regnum <= mips_regnum (gdbarch)->fp_implementation_revision);
}

/* Fetch register REGNUM from the inferior.  If REGNUM is -1, do this
   for all registers.  */

void
mips_fbsd_nat_target::fetch_registers (struct regcache *regcache, int regnum)
{
  pid_t pid = get_ptrace_pid (regcache->ptid ());

  struct gdbarch *gdbarch = regcache->arch ();
  if (regnum == -1 || getregs_supplies (gdbarch, regnum))
    {
      struct reg regs;

      if (ptrace (PT_GETREGS, pid, (PTRACE_TYPE_ARG3) &regs, 0) == -1)
	perror_with_name (_("Couldn't get registers"));

      mips_fbsd_supply_gregs (regcache, regnum, &regs, sizeof (register_t));
    }

  if (regnum == -1 || getfpregs_supplies (gdbarch, regnum))
    {
      struct fpreg fpregs;

      if (ptrace (PT_GETFPREGS, pid, (PTRACE_TYPE_ARG3) &fpregs, 0) == -1)
	perror_with_name (_("Couldn't get floating point status"));

      mips_fbsd_supply_fpregs (regcache, regnum, &fpregs,
			       sizeof (f_register_t));
    }
}

/* Store register REGNUM back into the inferior.  If REGNUM is -1, do
   this for all registers.  */

void
mips_fbsd_nat_target::store_registers (struct regcache *regcache, int regnum)
{
  pid_t pid = get_ptrace_pid (regcache->ptid ());

  struct gdbarch *gdbarch = regcache->arch ();
  if (regnum == -1 || getregs_supplies (gdbarch, regnum))
    {
      struct reg regs;

      if (ptrace (PT_GETREGS, pid, (PTRACE_TYPE_ARG3) &regs, 0) == -1)
	perror_with_name (_("Couldn't get registers"));

      mips_fbsd_collect_gregs (regcache, regnum, (char *) &regs,
			       sizeof (register_t));

      if (ptrace (PT_SETREGS, pid, (PTRACE_TYPE_ARG3) &regs, 0) == -1)
	perror_with_name (_("Couldn't write registers"));
    }

  if (regnum == -1 || getfpregs_supplies (gdbarch, regnum))
    {
      struct fpreg fpregs;

      if (ptrace (PT_GETFPREGS, pid, (PTRACE_TYPE_ARG3) &fpregs, 0) == -1)
	perror_with_name (_("Couldn't get floating point status"));

      mips_fbsd_collect_fpregs (regcache, regnum, (char *) &fpregs,
				sizeof (f_register_t));

      if (ptrace (PT_SETFPREGS, pid, (PTRACE_TYPE_ARG3) &fpregs, 0) == -1)
	perror_with_name (_("Couldn't write floating point status"));
    }
}

#ifdef PT_GETQTRACE
#include "gdbcmd.h"

static  struct cmd_list_element *qtrace_cmdlist = NULL;

/*
 * Toggling the user-only qtrace is slightly hacky since we are doing it in the
 * gdb process and not the debugged one. However, nothing else except the
 * qtrace tool uses these magic nops so this should be safe.
 */
static void
cmd_qtrace_enable_user_only(const char *args, int from_tty)
{
  __asm__ __volatile__("ori $0, $0, 0xdeaf");
}

static void
cmd_qtrace_disable_user_only (const char *args, int from_tty)
{
  __asm__ __volatile__("ori $0, $0, 0xfaed");
}

static void
cmd_qtrace_start (const char *args, int from_tty)
{
  if (ptrace (PT_SETQTRACE, get_ptrace_pid (inferior_ptid), NULL, 1)
      == -1)
    perror_with_name (_("Couldn't enable qtrace"));
}

static void
cmd_qtrace_stop (const char *args, int from_tty)
{
  cmd_qtrace_disable_user_only(args, from_tty);
  if (ptrace (PT_SETQTRACE, get_ptrace_pid (inferior_ptid), NULL, 0)
      == -1)
    perror_with_name (_("Couldn't disable qtrace"));
}

static void
cmd_qtrace_start_user_only(const char *args, int from_tty)
{
  cmd_qtrace_enable_user_only(args, from_tty);
  cmd_qtrace_start(args, from_tty);
}

static void
cmd_qtrace_start_full(const char *args, int from_tty)
{
  cmd_qtrace_disable_user_only(args, from_tty);
  cmd_qtrace_start(args, from_tty);
}

static void
add_qtrace_commands (void)
{
  add_prefix_cmd ("qtrace", class_obscure, cmd_qtrace_start,
		  _("Start tracing."), &qtrace_cmdlist, "qtrace ", 0,
		  &cmdlist);

  add_cmd ("stop", class_obscure, cmd_qtrace_stop, _("Stop tracing."),
	   &qtrace_cmdlist);
  add_cmd ("start-full", class_obscure, cmd_qtrace_start_full, _("Start tracing."),
	   &qtrace_cmdlist);
  add_cmd ("start-user", class_obscure, cmd_qtrace_start_user_only, _("Start user-mode only tracing."),
	   &qtrace_cmdlist);
  add_cmd ("enable-user-only", class_obscure, cmd_qtrace_enable_user_only,
	   _("Turn on user-mode only qtrace."), &qtrace_cmdlist);
  add_cmd ("disable-user-only", class_obscure, cmd_qtrace_disable_user_only,
	   _("Turn off user-mode only qtrace."), &qtrace_cmdlist);
}
#endif

void
_initialize_mips_fbsd_nat (void)
{
  add_inf_child_target (&the_mips_fbsd_nat_target);

#ifdef PT_GETQTRACE
  add_qtrace_commands ();
#endif
}

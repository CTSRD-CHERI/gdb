/* Handle intra-process compartments

   Copyright (C) 2024 Free Software Foundation, Inc.

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

#include "command.h"
#include "comparts.h"
#include "gdbarch.h"
#include "progspace.h"
#include "ui-out.h"
#include "cli/cli-cmds.h"
#include "cli/cli-style.h"

/* See comparts.h.  */

bool debug_comparts;

/* Sort a list of compartments by Id.  */

static void
sort_comparts (compart_list &list)
{
  std::sort (list.begin (), list.end (),
	     [](compart_up &a, compart_up &b) { return a->id < b->id; });
}

/* See comparts.h.  */

void
update_compart_list (int from_tty)
{
  unsigned int entry_generation = get_frame_cache_generation ();

  if (entry_generation == current_program_space->compart_generation)
    return;

  gdbarch *gdbarch = target_gdbarch ();
  compart_list inferior = gdbarch_current_comparts (gdbarch);

  if (inferior.empty ())
    {
      current_program_space->compart_list.clear ();
      current_program_space->compart_generation = entry_generation;
      return;
    }

  sort_comparts (inferior);

  /* Require unique compartment IDs.  */
  LONGEST last_id = -1;
  for (const compart_up &c : inferior)
    {
      if (c->id == last_id)
	error (_("Duplicate compartment %s"), plongest (last_id));
      last_id = c->id;
    }

  compart_list new_list;

  auto inf_it = inferior.begin ();
  auto inf_end = inferior.end ();
  auto gdb_it = current_program_space->compart_list.begin ();
  auto gdb_end = current_program_space->compart_list.end ();

  while (gdb_it != gdb_end && inf_it != inf_end)
    {
      compart *gdb_c = gdb_it->get ();
      compart *inf_c = inf_it->get ();

      if (gdb_c->id < inf_c->id)
	{
	  /* Compartment removed.  */
	  comparts_debug_printf ("removed %s (%s)", plongest (gdb_c->id),
				 gdb_c->name.c_str ());
	  gdb_it++;
	  continue;
	}

      if (gdb_c->id == inf_c->id)
	{
	  if (gdb_c->addr == inf_c->addr &&
	      gdb_c->name == inf_c->name)
	    {
	      /* Compartment stayed the same.  */
	      new_list.push_back (std::move (*gdb_it));
	    }
	  else
	    {
	      /* Compartment ID reused.  */
	      comparts_debug_printf ("removed %s (%s)", plongest (gdb_c->id),
				     gdb_c->name.c_str ());
	      comparts_debug_printf ("added %s (%s)", plongest (inf_c->id),
				     inf_c->name.c_str ());
	      gdbarch_fetch_compart_info (gdbarch, inf_c);
	      new_list.push_back (std::move (*inf_it));
	    }

	  gdb_it++;
	  inf_it++;
	  continue;
	}

      /* New compartment before 'gdb_c'.  */
      comparts_debug_printf ("added %s (%s)", plongest (inf_c->id),
			     inf_c->name.c_str ());
      gdbarch_fetch_compart_info (gdbarch, inf_c);
      new_list.push_back (std::move (*inf_it));
      inf_it++;
    }

  /* Add any remaining compartments from 'inferior'.  */
  while (inf_it != inf_end)
    {
      compart *inf_c = inf_it->get ();
      comparts_debug_printf ("added %s (%s)", plongest (inf_c->id),
			     inf_c->name.c_str ());
      gdbarch_fetch_compart_info (gdbarch, inf_c);
      new_list.push_back (std::move (*inf_it));
      inf_it++;
    }

  current_program_space->compart_list = std::move(new_list);
  current_program_space->compart_generation = entry_generation;
}

/* Implement the "info compartments" command.  Walk through the
   compartments list and print information about each attached
   compartment matching PATTERN.  If PATTERN is elided, print them
   all.  */

static void
info_compartments_command (const char *pattern, int from_tty)
{
  struct ui_out *uiout = current_uiout;

  if (pattern)
    {
      char *re_err = re_comp (pattern);

      if (re_err)
	error (_("Invalid pattern: %s"), re_err);
    }

  update_compart_list (from_tty);

  /* ui_out_emit_table table_emitter needs to know the number of rows,
     so we need to make two passes over the compartments.  */

  int nr_comparts = 0;
  int max_name = strlen ("Name");
  for (const compart_up &compart : current_program_space->compart_list)
    {
      if (pattern && !re_exec (compart->name.c_str ()))
	continue;
      nr_comparts++;
      if (compart->name.length () > max_name)
	max_name = compart->name.length ();
    }

  {
    ui_out_emit_table table_emitter (uiout, 3, nr_comparts, "CompartmentTable");

    uiout->table_header (4, ui_right, "id", "Id");
    uiout->table_header (max_name, ui_left, "name", "Name");
    uiout->table_header (0, ui_left, "libraries", "Libraries");

    uiout->table_body ();

    for (const compart_up &compart : current_program_space->compart_list)
      {
	if (pattern && !re_exec (compart->name.c_str ()))
	  continue;

	ui_out_emit_tuple tuple_emitter (uiout, "compartment");

	uiout->field_signed ("id", compart->id);
	uiout->field_string ("name", compart->name);

	if (compart->libraries.empty ())
	  uiout->field_skip ("libraries");
	else
	  {
	    ui_out_emit_list list_emitter (uiout, "libraries");

	    bool first = true;
	    for (std::string lib : compart->libraries)
	      {
		if (first)
		  first = false;
		else
		  uiout->text (" ");
		uiout->field_string ("name", lib, file_name_style.style ());
	      }
	  }

	uiout->text ("\n");
      }
  }

  if (nr_comparts == 0)
    {
      if (pattern)
	uiout->message (_("No compartments matched.\n"));
      else
	uiout->message (_("No compartments.\n"));
    }
}

const struct compart *
compart_info (LONGEST id)
{
  update_compart_list (0);

  for (const compart_up &compart : current_program_space->compart_list)
    {
      if (compart->id == id)
	return (compart.get ());
      if (compart->id > id)
	return (nullptr);
    }
  return (nullptr);
}

void _initialize_comparts ();
void
_initialize_comparts ()
{
  add_info ("compartments", info_compartments_command,
	    _("Status of intra-process compartments."));

  add_setshow_boolean_cmd ("comparts", class_maintenance,
			   &debug_comparts, _("\
Set comparts debugging."), _("\
Show comparts debugging."), _("\
When true, comparts-related debugging output is enabled."),
			   nullptr, nullptr,
			   &setdebuglist, &showdebuglist);
}

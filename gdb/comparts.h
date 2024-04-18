/* Intra-process compartment declarations

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

#ifndef COMPARTS_H
#define COMPARTS_H

#include <memory>
#include <string>
#include <vector>

/* A single compartment.  */

struct compart
{
  /* Integer ID.  */
  LONGEST id;

  /* Human-readable name.  */
  std::string name;

  /* Address of compartment structure.  */
  CORE_ADDR addr;

  /* List of libraries belonging to this compartment.  */
  std::vector<std::string> libraries;

  /* List of symbols that can be imported.  */
  std::vector<std::string> imports;

  /* List of symbols trusted by the library.  */
  std::vector<std::string> trusts;
};

typedef std::unique_ptr<compart> compart_up;

/* A list of compartments.  */

typedef std::vector<compart_up> compart_list;

/* Value of the 'set debug comparts' configuration variable.  */

extern bool debug_comparts;

/* Print a "comparts" debug statement.  */

#define comparts_debug_printf(fmt, ...) \
  debug_prefixed_printf_cond (debug_comparts, "comparts", fmt, ##__VA_ARGS__)

/* Synchronize GDB's compartment list with inferior's.

   If FROM_TTY is non-null, feel free to print messages about what
   we're doing.  */

extern void update_compart_list (int from_tty);

#endif /* COMPARTS_H */

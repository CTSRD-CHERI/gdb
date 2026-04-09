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
#include "frame.h"
#include "gdbarch.h"
#include "gdbsupport/buildargv.h"
#include "gdbsupport/gdb_tilde_expand.h"
#include "gdbsupport/print-utils.h"
#include "gdbtypes.h"
#include "regcache.h"
#include "target.h"
#include "valprint.h"
#include "cli/cli-cmds.h"
#include "cli/cli-style.h"

#include <map>
#include <vector>

class region_cache
{
public:
  void add_regions (const std::vector<named_memory_region> &regions)
  {
    for (auto it = regions.begin (); it != regions.end (); it++)
      tree.emplace (it->start, &*it);
  }

  const named_memory_region *find (CORE_ADDR addr) const
  {
    if (tree.empty ())
      return nullptr;

    auto it = tree.lower_bound (addr);
    if (it != tree.begin() && (it == tree.end() || it->first > addr))
      it--;

    gdb_assert (it != tree.end ());

    const named_memory_region *region = it->second;
    if (addr >= region->start && addr < region->end)
      return region;
    return nullptr;
  }

private:
  std::map<CORE_ADDR, const named_memory_region *> tree;
};

class as_ranges
{
public:
  typedef std::pair<CORE_ADDR, ULONGEST> range;

  /* Returns vector of previously-unvisited ranges.  */
  std::vector<range> visit (CORE_ADDR start, ULONGEST length);

private:
  std::map<CORE_ADDR, ULONGEST> visited;
};

struct cheritree_state
{
  std::vector<named_memory_region> regions;
  region_cache region_cache;
  as_ranges ranges;
  bool first = true;
  bool json = false;
};

std::vector<as_ranges::range>
as_ranges::visit (CORE_ADDR start, ULONGEST length)
{
  CORE_ADDR end = start + length;
  std::vector<range> ranges;

  /* If visited is empty, mark the entire range.  */
  if (visited.empty ())
    {
      visited[start] = length;
      ranges.emplace_back (start, length);
      return ranges;
    }

  /* Find the entry that is either adjacent with or overlaps
     with the start of the new range.  lower_bound is close but can be
     one range too far.  */
  auto it = visited.lower_bound (start);
  if (it != visited.begin() && (it == visited.end() || it->first > start))
    {
      it--;

      CORE_ADDR it_end = it->first + it->second;

      /* This range ends before the start of the new range, so
	 skip back over this range.  */
      if (it_end < start)
	{
	  it++;
	  if (it == visited.end())
	    {
	      /* The new range starts after the end of the last
		 range.  */
	      visited[start] = length;
	      ranges.emplace_back (start, length);
	      return ranges;
	    }
	}
    }
  gdb_assert (it != visited.end());

  /* New range ends before the start of this range.  */
  if (end < it->first)
    {
      /* Entirely new range.  */
      visited[start] = length;
      ranges.emplace_back (start, length);
      return ranges;
    }

  /* If the new range starts before but overlaps with this range,
     create a new range and merge it with this range.  */
  if (start < it->first)
    {
      CORE_ADDR new_length = it->first - start;
      ranges.emplace_back (start, new_length);
      visited[start] = new_length + it->second;

      /* Move back to the new range.  */
      auto old_it = it;
      it--;
      gdb_assert (it->first == start);

      /* Delete the now-merged range.  */
      visited.erase (old_it);

      /* The main loop below will take care of advancing start over
	 the newly added range.  */
    }

  /* Keep extending the current range until the new range is
     completely marked.  */
  for (;;)
    {
      CORE_ADDR it_end = it->first + it->second;
      gdb_assert (start >= it->first && start <= it_end);

      /* Is the new range fully covered?  */
      if (end <= it_end)
	return ranges;

      /* Skip over the covered part of the new range.  */
      start = it_end;
      length = end - it_end;

      /* Grow this range if this is the last range or if the next range
	 is beyond the end.  */
      auto next_it = it;
      next_it++;
      if (next_it == visited.end() || next_it->first > end)
	{
	  ranges.emplace_back (start, length);
	  it->second += length;
	  return ranges;
	}

      /* Add the hole until the next range.  */
      CORE_ADDR hole_len = next_it->first - start;
      ranges.emplace_back (start, hole_len);

      /* Merge with the next range.  */
      it->second += hole_len + next_it->second;
      visited.erase (next_it);

      /* Loop back to the top which will advance over the hole.  */
    }
}

/* Lookup a capability register by name.  */

static int
capability_register_by_name (gdbarch *gdbarch, const char *name)
{
  for (int i = 0; i < gdbarch_num_cooked_regs (gdbarch); i++)
    {
      struct type *type = register_type (gdbarch, i);
      if (!is_capability (type))
	continue;

      if (strcmp (name, gdbarch_register_name (gdbarch, i)) == 0)
	return i;
    }

  error (_("Unknown register `%s'."), name);
}

/* Parse a register set.  */

static std::set<int>
parse_regs (gdbarch *gdbarch, char *arg)
{
  std::set<int> regs;
  char *last, *word;

  for (word = strtok_r (arg, ",", &last); word != NULL;
       word = strtok_r (NULL, ",", &last))
    {
      if (word[0] == '\0')
	continue;

      char *trailer = strchr(word, '-');
      if (trailer != NULL)
	error (_("Register ranges not yet supported."));

      regs.insert (capability_register_by_name (gdbarch, word));
    }

  return regs;
}

static void
print_capability (gdbarch *gdbarch, cheritree_state &state, struct value *val,
		  const char *origin, int depth)
{
  const gdb_byte *contents = val->contents_for_printing ().data ();
  ULONGEST offset = 0;

  if (state.json)
    {
      if (!state.first)
	gdb_printf(",\n");
      state.first = false;
      gdb_printf ("\t{ \"depth\": %d,", depth);
    }
  else
    {
      for (int i = 0; i < depth; i++)
	gdb_printf (" ");
    }

  if (state.json)
    gdb_printf (" \"origin\": \"%s\",", origin);
  else
    gdb_printf ("%s:", origin);

  if (state.json)
    gdbarch_print_cap_json (gdbarch, contents, val->tag (), gdb_stdout);
  else
    {
      gdb_printf (" ");
      gdbarch_print_cap (gdbarch, contents, val->tag (), true, gdb_stdout);
      gdb_printf ("  ");
    }

  CORE_ADDR addr = gdbarch_pointer_to_address (gdbarch, val->type (),
					       contents);

  const named_memory_region *region = state.region_cache.find (addr);
  if (region != nullptr)
    {
      if (state.json)
	gdb_printf (" \"mapping\": \"%s\",", region->name.c_str ());
      else
	gdb_printf ("%s", region->name.c_str ());
      offset = addr - region->start;
    }

  std::string symname, filename;
  int symoffset, line, unmapped;
  if (build_address_symbolic (gdbarch, addr, true, false, &symname, &symoffset,
			      &filename, &line, &unmapped) == 0)
    {
      if (state.json)
	gdb_printf (" \"symbol\": \"%s\",", symname.c_str ());
      else
	gdb_printf ("!%s", symname.c_str ());
      offset = symoffset;
    }

  if (state.json)
    gdb_printf (" \"offset\": %s", pulongest (offset));
  else if (offset != 0)
    gdb_printf ("+0x%s", phex_nz (offset, sizeof offset));

  if (state.json)
    gdb_printf (" }");
  else
    gdb_printf ("\n");
}

/* Maximum number of CHERI tags to fetch from the target in a single
   call.  */
#define MAX_TAGS_TO_TRANSFER	1024

static void
print_capability_tree (gdbarch *gdbarch, cheritree_state &state,
		       struct value *val, const char *origin, int depth)
{
  try
    {
      if (val->lazy ())
	val->fetch_lazy ();
    }
  catch (const gdb_exception_error &)
    {
      /* If the value cannot be fetched, just return.  */
      return;
    }

  if (!val->tagged () || !val->tag ())
    return;

  print_capability (gdbarch, state, val, origin, depth);

  if (!gdbarch_can_read_pointers (gdbarch, val))
    return;

  /* Fetch capability bounds to determine region of memory to search.  */
  auto bounds = gdbarch_get_capability_bounds (gdbarch, val);
  CORE_ADDR start = bounds.first;
  ULONGEST length = bounds.second;

  /* Truncate bounds to range of aligned capabilities.  */
  struct type *cap_type = builtin_type (gdbarch)->builtin_intcap_t;
  ULONGEST stride = cap_type->length ();
  if (length < stride)
    return;
  CORE_ADDR offset = start % stride;
  if (offset != 0)
    {
      start += (stride - offset);
      length -= (stride - offset);
    }
  length &= ~(stride - 1);
  if (length == 0)
    return;

  auto unvisited_ranges = state.ranges.visit (start, length);
  for (const auto &pair : unvisited_ranges)
    {
      start = pair.first;
      CORE_ADDR end = start + pair.second;
      while (start < end)
	{
	  auto tagged_range =
	    target_first_memtag_range (start, end - start,
				       static_cast<int> (memtag_type::cheri));
	  if (tagged_range.len == 0)
	    break;

	  while (tagged_range.len > 0)
	    {
	      gdb::byte_vector tags;
	      size_t todo = tagged_range.len;
	      if (todo > MAX_TAGS_TO_TRANSFER * stride)
		todo = MAX_TAGS_TO_TRANSFER * stride;
	      if (!target_fetch_memtags (tagged_range.address, todo, tags,
					 static_cast<int> (memtag_type::cheri)))
		{
		  warning (_("Failed to read CHERI tags from memory range [%s,%s)."),
			   paddress (gdbarch, tagged_range.address),
			   paddress (gdbarch, tagged_range.address + todo));
		}
	      else
		{
		  gdb_assert (tags.size () == todo / stride);
		  for (size_t i = 0; i < tags.size (); i++)
		    {
		      /* Scanning memory can be slow, allow the user
			 to cancel.  */
		      QUIT;

		      if (tags[i] == 0)
			continue;

		      CORE_ADDR cap_addr = tagged_range.address + i * stride;
		      struct value *cap_val = value_at_lazy (cap_type,
							     cap_addr);
		      std::string addr_name (paddress (gdbarch, cap_addr));
		      print_capability_tree (gdbarch, state, cap_val,
					     addr_name.c_str (), depth + 1);
		      release_value (cap_val);
		    }
		}

	      tagged_range.address += todo;
	      tagged_range.len -= todo;
	    }

	  start = tagged_range.address;
	}
    }
}

/* Implement the "info cheritree" command.  */

static void
info_cheritree_command (const char *args, int from_tty)
{
  frame_info_ptr frame = get_selected_frame (_("No stack."));
  gdbarch *gdbarch = get_frame_arch (frame);
  std::set<int> roots = gdbarch_get_capability_roots (gdbarch);
  bool json = false;
  bool first_include = true;
  bool print_mappings = false;

  if (args)
    {
      gdb_argv built_argv (args);

      for (char **argv = built_argv.get (); *argv != NULL; argv++)
	{
	  if (*argv[0] == '-')
	    {
	      if (strcmp(*argv, "-include") == 0)
		{
		  ++argv;
		  if (!*argv)
		    error (_("No argument to -include"));
		  if (first_include)
		    {
		      roots.clear();
		      first_include = false;
		    }
		  for (int regnum : parse_regs (gdbarch, *argv))
		    roots.insert (regnum);
		}
	      else if (strcmp(*argv, "-exclude") == 0)
		{
		  ++argv;
		  if (!*argv)
		    error (_("No argument to -exclude"));
		  for (int regnum : parse_regs (gdbarch, *argv))
		    roots.erase (regnum);
		}
	      else if (strcmp(*argv, "-json") == 0)
		json = true;
	      else if (strcmp(*argv, "-mappings") == 0)
		print_mappings = true;
	      else
		error (_("Invalid argument"));
	    }
	  else
	    error (_("Invalid argument"));
	}
    }

  if (gdbarch_capability_bit (gdbarch) == 0)
    error (_("Non-CHERI architecture"));

  cheritree_state state;
  state.json = json;
  state.regions = target_get_named_memory_regions ();
  state.region_cache.add_regions (state.regions);
  if (json)
    {
      gdb_printf ("{\n");
      gdb_printf ("    \"mappings\": [\n");
      bool first = true;
      for (const auto &region : state.regions)
	{
	  if (!first)
	    gdb_printf (",\n");
	  first = false;

	  gdb_printf ("\t{ \"start\": %s, \"end\": %s, \"mapping\": \"%s\" }",
		      pulongest (region.start), pulongest (region.end),
		      region.name.c_str ());
	}
      if (!first)
	gdb_printf ("\n");
      gdb_printf ("    ],\n");
      gdb_printf ("    \"capabilities\": [\n");
    }
  else if (print_mappings)
    {
      for (const auto &region : state.regions)
	gdb_printf ("%s-%s %s\n", paddress (gdbarch, region.start),
		    paddress (gdbarch, region.end), region.name.c_str ());
    }

  for (int regnum : roots)
    {
      struct value *val = get_frame_register_value (frame, regnum);
      if (!val->optimized_out () && val->entirely_available ())
	print_capability_tree (gdbarch, state, val,
			       gdbarch_register_name (gdbarch, regnum), 0);
      release_value (val);
    }

  if (json)
    {
      gdb_printf ("    ]\n");
      gdb_printf ("}\n");
    }
}

void _initialize_cheri ();
void
_initialize_cheri ()
{
  add_info ("cheritree", info_cheritree_command, _("\
Display reachable capabilities from the current frame.\n\
\n\
Usage: info cheritree [OPTION]...\n\
"));
}

/* Definitions for targets which report shared library events.

   Copyright (C) 2021 Hesham Almatary.
   Copyright (C) 2007-2013 Free Software Foundation, Inc.

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
#include "objfiles.h"
#include "solist.h"
#include "symtab.h"
#include "symfile.h"
#include "target.h"
#include "common/vec.h"
#include "solib-rtems.h"
#include "solib.h"
#include "solist.h"
#include "gdbcore.h"

#include "exceptions.h"
#include "breakpoint.h"

#include "bfd-target.h"
#include "elf-bfd.h"
#include "exec.h"
#include "auxv.h"
#include "gdb_bfd.h"
#include "probe.h"

enum sections
{
  rap_text = 0,
  rap_const = 1,
  rap_ctor = 2,
  rap_dtor = 3,
  rap_data = 4,
  rap_bss = 5,
  rap_secs = 6
};

#define MAX_SECTION_NAME_L 32
struct sec_info {
  char name[MAX_SECTION_NAME_L];
  uint32_t addr_low;
  uint32_t addr_high;
  uint32_t rap_id;
  struct sec_info *next;
};

struct lm_info_rtems : public lm_info_base
{
  /* The library's name.  The name is normally kept in the struct
     so_list; it is only here during XML parsing.  */

  char *name;
  char *rpath;
  uint32_t rpathlen;

  CORE_ADDR lm_addr;
  CORE_ADDR l_name_addr;
  CORE_ADDR l_rpath;

  CORE_ADDR text_addr_low;
  CORE_ADDR text_addr_high;

  struct sec_info *si;

  CORE_ADDR l_next;
  CORE_ADDR l_prev;
};

typedef struct lm_info_rtems *lm_info_p;
DEF_VEC_P(lm_info_p);

#define RTEMS_DEBUG 0

static const char * const solib_break_names[] =
{
  "_rtld_debug_state",
  NULL
};

/* Per-architecture data key. */
static struct gdbarch_data *solib_rtems_data;

struct solib_rtems_ops
{
  /* Return a description of the layout of `struct link_map` */
  struct link_map_offsets *(*fetch_link_map_offsets)(void);
};

struct target_so_ops rtems_so_ops;

void
set_solib_rtems_fetch_link_map_offsets (struct gdbarch *gdbarch,
                                        struct link_map_offsets *(*flmo) (void))
{
  struct solib_rtems_ops *ops = (struct solib_rtems_ops *) gdbarch_data (gdbarch, solib_rtems_data);

  ops->fetch_link_map_offsets = flmo;

  set_solib_ops (gdbarch, &rtems_so_ops);
}

static struct link_map_offsets *
rtems_fetch_link_map_offsets (void)
{
  struct solib_rtems_ops *ops = (struct solib_rtems_ops *) gdbarch_data (target_gdbarch (),
                                              solib_rtems_data);

  gdb_assert (ops->fetch_link_map_offsets);
  return ops->fetch_link_map_offsets ();
}

static int
rtems_have_link_map_offsets (void)
{
  struct solib_rtems_ops *ops = (struct solib_rtems_ops *) gdbarch_data (target_gdbarch (),
                                              solib_rtems_data);

  return (ops->fetch_link_map_offsets != NULL);
}

struct link_map_offsets *
rtems_ilp32_fetch_link_map_offsets (void)
{
  /* Note: the link map and r_debug should be the same with rtl target. */

  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
  {
    lmp = &lmo;

    lmo.r_version_offset = 0;
    lmo.r_version_size = 4;
    lmo.r_map_offset = 4;

    lmo.link_map_size = 52;

    lmo.l_name_offset = 0;
    lmo.l_sec_num_offset = 4;
    lmo.l_sec_detail_offset = 8;
    lmo.l_base_sec_addr_offset = 12;
    lmo.l_rpathlen_offset = 36;
    lmo.l_rpath_offset = 40;
    lmo.l_next_offset = 44;
    lmo.l_prev_offset = 48;

    lmo.sec_map_size = 16;
    lmo.s_name_offset = 0;
    lmo.s_addr_offset = 4;
    lmo.s_size_offset = 8;
    lmo.s_rap_id_offset = 12;
  }

  return lmp;
}

struct link_map_offsets *
rtems_lp64_fetch_link_map_offsets (void)
{
  /* Note: the link map and r_debug should be the same with rtl target. */

  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
  {
    lmp = &lmo;

    lmo.r_version_offset = 0;
    lmo.r_version_size = 4;
    lmo.r_map_offset = 4;

    lmo.link_map_size = 96;

    lmo.l_name_offset = 0;
    lmo.l_sec_num_offset = 8;
    lmo.l_sec_detail_offset = 12;
    lmo.l_base_sec_addr_offset = 20;
    lmo.l_rpathlen_offset = 68;
    lmo.l_rpath_offset = 72;
    lmo.l_next_offset = 80;
    lmo.l_prev_offset = 88;

    lmo.sec_map_size = 20;
    lmo.s_name_offset = 0;
    lmo.s_addr_offset = 8;
    lmo.s_size_offset = 12;
    lmo.s_rap_id_offset = 16;
  }

  return lmp;
}

struct link_map_offsets *
rtems_c64_fetch_link_map_offsets (void)
{
  /* Note: the link map and r_debug should be the same with rtl target. */

  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
  {
    lmp = &lmo;

    lmo.r_version_offset = 0;
    lmo.r_version_size = 4;
    lmo.r_map_offset = 4;

    lmo.link_map_size = 96;

    lmo.l_name_offset = 0;
    lmo.l_sec_num_offset = 8;
    lmo.l_sec_detail_offset = 12;
    lmo.l_base_sec_addr_offset = 20;
    lmo.l_rpathlen_offset = 68;
    lmo.l_rpath_offset = 72;
    lmo.l_next_offset = 80;
    lmo.l_prev_offset = 88;

    lmo.sec_map_size = 20;
    lmo.s_name_offset = 0;
    lmo.s_addr_offset = 8;
    lmo.s_size_offset = 12;
    lmo.s_rap_id_offset = 16;
  }

  return lmp;
}

struct link_map_offsets *
rtems_c128_fetch_link_map_offsets (void)
{
  /* Note: the link map and r_debug should be the same with rtl target. */

  static struct link_map_offsets lmo;
  static struct link_map_offsets *lmp = NULL;

  if (lmp == NULL)
  {
    lmp = &lmo;

    lmo.r_version_offset = 0;
    lmo.r_version_size = 4;
    lmo.r_map_offset = 16;

    lmo.link_map_size = 208;

    lmo.l_name_offset = 0;
    lmo.l_sec_num_offset = 16;
    lmo.l_sec_detail_offset = 32;
    lmo.l_base_sec_addr_offset = 48;
    lmo.l_rpathlen_offset = 144;
    lmo.l_rpath_offset = 160;
    lmo.l_next_offset = 176;
    lmo.l_prev_offset = 192;

    lmo.sec_map_size = 32;
    lmo.s_name_offset = 0;
    lmo.s_addr_offset = 16;
    lmo.s_size_offset = 20;
    lmo.s_rap_id_offset = 24;
  }

  return lmp;
}

static std::unique_ptr<lm_info_rtems>
lm_info_read (CORE_ADDR lm_addr)
{
  struct link_map_offsets *lmo = rtems_fetch_link_map_offsets ();
  std::unique_ptr<lm_info_rtems> lm_info;

  gdb::byte_vector lm (lmo->link_map_size);

  if (target_read_memory (lm_addr, lm.data (), lmo->link_map_size) != 0)
    {
      warning (_("Error reading dynamically loaded file list entry at %s"),
               paddress (target_gdbarch (), lm_addr));
    }
  else
    {
      int errcode;
      CORE_ADDR rpath;
      int sec_num;
      int rap_sec_addr[rap_secs], i;
      int rap_sec_size[rap_secs];
      gdb_byte *sm;
      int rap_id = 0;
      CORE_ADDR sm_addr, sec_detail_addr;
      struct type *ptr_type =
        builtin_type (target_gdbarch ())->builtin_data_ptr;

      lm_info.reset (new struct lm_info_rtems);
      lm_info->lm_addr = lm_addr;
      lm_info->si = NULL;

      lm_info->l_name_addr = extract_typed_address (&lm[lmo->l_name_offset],
                                                    ptr_type);

      lm_info->l_next = extract_typed_address (&lm[lmo->l_next_offset],
                                               ptr_type);
      lm_info->l_prev = extract_typed_address (&lm[lmo->l_prev_offset],
                                               ptr_type);

      sec_detail_addr = extract_typed_address (&lm[lmo->l_sec_detail_offset], ptr_type);
      sec_num = extract_typed_address (&lm[lmo->l_sec_num_offset], ptr_type);

      for (i = 0; i < rap_secs; i++)
        {
          rap_sec_addr[i] =
            extract_typed_address (&lm[lmo->l_base_sec_addr_offset + i],
                                   ptr_type);
        }

      /* Rpath */
      rpath = extract_typed_address (&lm[lmo->l_rpath_offset],
                                     ptr_type);
      lm_info->rpathlen = extract_typed_address (&lm[lmo->l_rpathlen_offset],
                                                 ptr_type);
      if (lm_info->rpathlen > 0)
        {
          lm_info->rpath = (char *) xmalloc (lm_info->rpathlen);
          if (target_read_memory (rpath, (gdb_byte *) lm_info->rpath,
                                  lm_info->rpathlen) != 0)
            {
              warning (_("Error reading dynamically loaded file list entry at %s"),
                       paddress (target_gdbarch (), lm_addr)),
                      xfree(lm_info->rpath), lm_info->rpath = NULL;
            }
        }
      else lm_info->rpath = NULL;

      /* Section map */

      /* Begin */
      sm_addr = sec_detail_addr;

      sm = (gdb_byte *) xmalloc (lmo->sec_map_size * sec_num);

      if (target_read_memory (sm_addr, sm, lmo->sec_map_size  * sec_num) != 0)
        {
          warning (_("Error reading dynamically loaded file list entry at %s"),
                   paddress (target_gdbarch (), sm_addr)),
                  sm_addr = 0;
        }
      else
        {
          gdb::unique_xmalloc_ptr<char> sec_name;
          CORE_ADDR name;
          struct sec_info *sec_info;
          int i = 0;
          gdb_byte *tmp = sm;

          memset (rap_sec_size, 0, sizeof (rap_sec_size));
          while (i < sec_num)
            {
              tmp = sm + i * lmo->sec_map_size;

              name = extract_typed_address (&tmp[lmo->s_name_offset], ptr_type);
              target_read_string (name, &sec_name,
                                  SO_NAME_MAX_PATH_SIZE - 1, &errcode);
              if (errcode)
                {
                  warning (_("failed to read exec sec_name from attached section: %s"),
                           safe_strerror (errcode));
                  return 0;
                }

              sec_info = (struct sec_info *) xzalloc (sizeof (*sec_info));

              strncpy (sec_info->name, sec_name.get (), MAX_SECTION_NAME_L - 1);
              sec_info->name[MAX_SECTION_NAME_L - 1] = '\0';

              rap_id = extract_typed_address (&tmp[lmo->s_rap_id_offset],
                                              ptr_type);
              //rap_sec_addr[rap_id] = rap_sec_addr[rap_id] +
              //  extract_typed_address (&tmp[lmo->s_addr_offset], ptr_type);
              sec_info->addr_low = rap_sec_addr[rap_id] +
                extract_typed_address (&tmp[lmo->s_addr_offset], ptr_type);
              if (rap_id == 0)
                lm_info->text_addr_low = sec_info->addr_low;

              rap_sec_size[rap_id] +=
                extract_typed_address (&tmp[lmo->s_size_offset],
                                       ptr_type);
              sec_info->addr_high = sec_info->addr_low +
                extract_typed_address (&tmp[lmo->s_size_offset],
                                       ptr_type);
              //sec_info->addr_low = rap_sec_addr[rap_id];
              //sec_info->addr_high = rap_sec_addr[rap_id] + rap_sec_size[rap_id];
              sec_info->next = NULL;

              if (lm_info->si == NULL)
                {
                  lm_info->si = sec_info;
                }
              else
                {
                  sec_info->next = lm_info->si;
                  lm_info->si = sec_info;
                }

              ++i;
            }
        }

      lm_info->text_addr_high = lm_info->text_addr_low + rap_sec_size [0];

      /* End */
    }

  return lm_info;
}

/* Per pspace RTEMS specific data.  */

struct rtems_info
{
  CORE_ADDR debug_base;	/* Base of dynamic linker structures.  */
};

static const struct program_space_data *solib_rtems_pspace_data;

/* Get the current rtems data. If none is found yet, add it now. This
 * function always return a valid object. */

static struct rtems_info *
get_rtems_info (void)
{
  struct rtems_info *info;

  info  = (struct rtems_info *) program_space_data (current_program_space, solib_rtems_pspace_data);

  if (info != NULL)
    return info;

  info = XCNEW (struct rtems_info);
  set_program_space_data (current_program_space, solib_rtems_pspace_data, info);
  return info;
}
static int
rtems_read_so_list (CORE_ADDR lm, CORE_ADDR prev_lm,
           struct so_list ***link_ptr_ptr, int ignore_first)
{
  CORE_ADDR first_l_name = 0;
  CORE_ADDR next_lm;

  for (; lm != 0; prev_lm = lm, lm = next_lm)
    {
      int errcode;
      gdb::unique_xmalloc_ptr<char> buffer;

      so_list_up newobj (XCNEW (struct so_list));

      lm_info_rtems *li = lm_info_read (lm).release ();
      newobj->lm_info = li;
      if (li == NULL)
    return 0;

      next_lm = li->l_next;

      if (li->l_prev != prev_lm)
    {
      warning (_("Corrupted shared library list: %s != %s"),
           paddress (target_gdbarch (), prev_lm),
           paddress (target_gdbarch (), li->l_prev));
      return 0;
    }

      /* Extract this shared object's name.  */
      target_read_string ((CORE_ADDR) li->l_name_addr, &buffer, SO_NAME_MAX_PATH_SIZE - 1,
              &errcode);
      if (errcode != 0)
    {
      warning (_("failed to read exec filename from attached file"));
      return 0;
    }

      strncpy (newobj->so_name, buffer.get (), SO_NAME_MAX_PATH_SIZE - 1);
      newobj->so_name[SO_NAME_MAX_PATH_SIZE - 1] = '\0';
      strcpy (newobj->so_original_name, newobj->so_name);

      newobj->next = 0;
      /* Don't free it now.  */
      **link_ptr_ptr = newobj.release ();
      *link_ptr_ptr = &(**link_ptr_ptr)->next;
    }

  return 1;
}

/* Locate the _rtld_debug symbol */
static CORE_ADDR
elf_locate_base (void)
{
  struct bound_minimal_symbol msymbol;

  msymbol = lookup_minimal_symbol ("_rtld_debug", NULL, symfile_objfile);
  if (msymbol.minsym != NULL)
    {
      return BMSYMBOL_VALUE_ADDRESS (msymbol);
    }

  /* Not found */
  return 0;
}

static CORE_ADDR
locate_base (struct rtems_info *info)
{
  if (info->debug_base == 0 && rtems_have_link_map_offsets ())
    info->debug_base = elf_locate_base ();
  return info->debug_base;
}

static CORE_ADDR
solib_rtems_r_map (struct rtems_info *info)
{
  struct link_map_offsets *lmo = rtems_fetch_link_map_offsets ();
  struct type *ptr_type = builtin_type (target_gdbarch ())->builtin_data_ptr;
  CORE_ADDR addr = 0;
  volatile struct gdb_exception ex;

  TRY
    {
      addr = read_memory_typed_address (info->debug_base + lmo->r_map_offset,
                                        ptr_type);
    }
  CATCH (ex, RETURN_MASK_ERROR)
    {
      exception_print (gdb_stderr, ex);
    }
  END_CATCH

  return addr;
}

static struct so_list *
rtems_current_sos (void)
{
  CORE_ADDR lm;
  struct so_list *head = NULL;
  struct so_list **link_ptr = &head;
  struct rtems_info *info;
  int ignore_first = 0;

  info = get_rtems_info ();

  info->debug_base = 0;
  locate_base (info);

  /* This must not support dynamic loading for RTL */
  if (! info->debug_base)
    return NULL;

  lm = solib_rtems_r_map (info);
  if (lm)
    rtems_read_so_list (lm, 0, &link_ptr, ignore_first);

  return head;
}

static void
rtems_pspace_data_cleanup (struct program_space *pspace, void *arg)
{
  // TODO
}


static void * solib_rtems_init (struct obstack *obstack)
{
  struct solib_rtems_ops *ops;

  ops = OBSTACK_ZALLOC (obstack, struct solib_rtems_ops);
  ops->fetch_link_map_offsets = NULL;
  return ops;
}

static int
enable_break (struct rtems_info *info, int from_tty)
{
  struct bound_minimal_symbol msymbol;
  const char * const *bkpt_namep;
  gdb_byte *interp_name;
  CORE_ADDR sym_addr;

  for (bkpt_namep = solib_break_names; *bkpt_namep != NULL; bkpt_namep++)
    {
      msymbol = lookup_minimal_symbol (*bkpt_namep, NULL, symfile_objfile);
      if ((msymbol.minsym != NULL) && (BMSYMBOL_VALUE_ADDRESS(msymbol) != 0))
        {
          sym_addr = BMSYMBOL_VALUE_ADDRESS (msymbol);
          sym_addr = gdbarch_convert_from_func_ptr_addr (target_gdbarch (),
                                                         sym_addr,
                                                         current_top_target ());
          create_solib_event_breakpoint (target_gdbarch (), sym_addr);
          return 1;
        }
    }

  return 0;
}

static void
rtems_solib_create_inferior_hook (int from_tty)
{
  struct rtems_info *info;

  info = get_rtems_info ();

  if (!target_has_execution)
    return;

  if (!enable_break (info, from_tty)) {}

  return;
}

static void
rtems_clear_solib (void)
{
  struct rtems_info *info;

  info = get_rtems_info ();
  info->debug_base = 0;
#if RTEMS_DEBUG
  printf ("%s\n", __func__);
#endif
}

static void
rtems_free_so (struct so_list *so)
{
  // FIXME
}

static void
rtems_relocate_section_addresses (struct so_list *so,
                                  struct target_section *sec)
{
  const char *sec_name = bfd_section_name (so->afbd, sec->the_bfd_section);
  struct lm_info_rtems *lm_info = (lm_info_rtems *) so->lm_info;
  struct sec_info *sec_info = lm_info->si;

#if RTEMS_DEBUG
  printf ("Relocate section: object file %s\n", so->so_original_name);
  printf ("         section name: %s\n", sec_name);
#endif

  while (sec_info)
    {
      if (strcmp (sec_name, sec_info->name) == 0)
        {
          sec->addr = sec_info->addr_low;
          sec->endaddr = sec_info->addr_high;
#if RTEMS_DEBUG
          //printf ("%s %x %x\n", sec_name, sec->addr, sec->endaddr);
#endif
          break;
        }
      else
        {
          sec_info = sec_info->next;
        }
    }
}

static int
rtems_open_symbol_file_object (int from_tty)
{
  CORE_ADDR lm, l_name;
  gdb::unique_xmalloc_ptr<char> filename;
  int errcode;
  struct link_map_offsets *lmo = rtems_fetch_link_map_offsets ();
  struct type *ptr_type = builtin_type (target_gdbarch ())->builtin_data_ptr;
  int l_name_size = TYPE_LENGTH (ptr_type);
  gdb::byte_vector l_name_buf (l_name_size);
  struct rtems_info *info = get_rtems_info ();
  symfile_add_flags add_flags = 0;

  if (from_tty)
    add_flags |= SYMFILE_VERBOSE;

  if (symfile_objfile)
    if (!query (_("Attempt to reload symbols from process? ")))
      return 0;

  /* Always locate the debug struct, in case it has moved.  */
  info->debug_base = 0;
  if (locate_base (info) == 0)
    return 0;   /* failed somehow...  */

  /* First link map member should be the executable.  */
  lm = solib_rtems_r_map (info);
  if (lm == 0)
    return 0;   /* failed somehow...  */

  /* Read address of name from target memory to GDB.  */
  read_memory (lm + lmo->l_name_offset, l_name_buf.data (), l_name_size);

  /* Convert the address to host format.  */
  l_name = extract_typed_address (l_name_buf.data (), ptr_type);

  if (l_name == 0)
    return 0;       /* No filename.  */

  /* Now fetch the filename from target memory.  */
  target_read_string (l_name, &filename, SO_NAME_MAX_PATH_SIZE - 1, &errcode);

  if (errcode)
    {
      warning (_("failed to read exec filename from attached file: %s"),
           safe_strerror (errcode));
      return 0;
    }

  /* Have a pathname: read the symbol file.  */
  symbol_file_add_main (filename.get (), add_flags);

  return 1;
}

static int
rtems_in_dynsym_resolve_code (CORE_ADDR pc)
{
  return 0;
}

/* Show infrun and gdbarch_debug msg. */
extern unsigned int debug_infrun;
extern unsigned int gdbarch_debug;
extern enum overlay_debugging_state overlay_debugging;

static void
set_debug (void)
{
#if RTEMS_DEBUG
  debug_infrun = 1;
  overlay_debugging = ovly_on;
//  gdbarch_debug = 2;
#endif
}

/* -Wmissing-prototypes */
extern initialize_file_ftype _initialize_rtems_solib;

void
_initialize_rtems_solib (void)
{
  solib_rtems_data = gdbarch_data_register_pre_init (solib_rtems_init);
  solib_rtems_pspace_data
    = register_program_space_data_with_cleanup (NULL, rtems_pspace_data_cleanup);

  rtems_so_ops.relocate_section_addresses = rtems_relocate_section_addresses;
  rtems_so_ops.free_so = rtems_free_so;
  rtems_so_ops.clear_solib = rtems_clear_solib;
  rtems_so_ops.solib_create_inferior_hook = rtems_solib_create_inferior_hook;
  rtems_so_ops.current_sos = rtems_current_sos;
  rtems_so_ops.open_symbol_file_object = rtems_open_symbol_file_object;
  rtems_so_ops.in_dynsym_resolve_code = rtems_in_dynsym_resolve_code;
  rtems_so_ops.bfd_open = solib_bfd_open;

  //set_debug ();
}

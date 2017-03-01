/* THIS FILE IS GENERATED.  -*- buffer-read-only: t -*- vi:set ro:
  Original: mips64-cheri256.xml */

#include "defs.h"
#include "osabi.h"
#include "target-descriptions.h"

struct target_desc *tdesc_mips64_cheri256;
static void
initialize_tdesc_mips64_cheri256 (void)
{
  struct target_desc *result = allocate_target_description ();
  struct tdesc_feature *feature;
  struct tdesc_type *field_type;
  struct tdesc_type *type;

  set_tdesc_architecture (result, bfd_scan_arch ("mips"));

  feature = tdesc_create_feature (result, "org.gnu.gdb.mips.cpu");
  tdesc_create_reg (feature, "r0", 0, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r1", 1, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r2", 2, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r3", 3, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r4", 4, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r5", 5, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r6", 6, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r7", 7, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r8", 8, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r9", 9, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r10", 10, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r11", 11, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r12", 12, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r13", 13, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r14", 14, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r15", 15, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r16", 16, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r17", 17, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r18", 18, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r19", 19, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r20", 20, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r21", 21, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r22", 22, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r23", 23, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r24", 24, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r25", 25, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r26", 26, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r27", 27, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r28", 28, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r29", 29, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r30", 30, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "r31", 31, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "lo", 33, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "hi", 34, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "pc", 37, 1, NULL, 64, "int");

  feature = tdesc_create_feature (result, "org.gnu.gdb.mips.cp0");
  tdesc_create_reg (feature, "status", 32, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "badvaddr", 35, 1, NULL, 64, "int");
  tdesc_create_reg (feature, "cause", 36, 1, NULL, 64, "int");

  feature = tdesc_create_feature (result, "org.gnu.gdb.mips.fpu");
  tdesc_create_reg (feature, "f0", 38, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f1", 39, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f2", 40, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f3", 41, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f4", 42, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f5", 43, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f6", 44, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f7", 45, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f8", 46, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f9", 47, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f10", 48, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f11", 49, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f12", 50, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f13", 51, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f14", 52, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f15", 53, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f16", 54, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f17", 55, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f18", 56, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f19", 57, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f20", 58, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f21", 59, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f22", 60, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f23", 61, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f24", 62, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f25", 63, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f26", 64, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f27", 65, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f28", 66, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f29", 67, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f30", 68, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "f31", 69, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fcsr", 70, 1, "float", 64, "int");
  tdesc_create_reg (feature, "fir", 71, 1, "float", 64, "int");

  feature = tdesc_create_feature (result, "org.gnu.gdb.mips.cheri256");
  type = tdesc_create_flags (feature, "cap256_perms", 8);
  tdesc_add_flag (type, 0, "s");
  tdesc_add_flag (type, 1, "G");
  tdesc_add_flag (type, 2, "X");
  tdesc_add_flag (type, 3, "R");
  tdesc_add_flag (type, 4, "W");
  tdesc_add_flag (type, 5, "RC");
  tdesc_add_flag (type, 6, "WC");
  tdesc_add_flag (type, 7, "WLC");
  tdesc_add_flag (type, 8, "S");
  tdesc_add_flag (type, 11, "SR");
  tdesc_add_bitfield (type, "uP", 16, 31);
  tdesc_add_bitfield (type, "type", 32, 55);
  tdesc_add_flag (type, 63, "V");

  type = tdesc_create_struct (feature, "cheri_cap256");
  field_type = tdesc_named_type (feature, "cap256_perms");
  tdesc_add_field (type, "attr", field_type);
  field_type = tdesc_named_type (feature, "uint64");
  tdesc_add_field (type, "cursor", field_type);
  field_type = tdesc_named_type (feature, "uint64");
  tdesc_add_field (type, "base", field_type);
  field_type = tdesc_named_type (feature, "uint64");
  tdesc_add_field (type, "length", field_type);

  type = tdesc_create_flags (feature, "cap_cause", 8);
  tdesc_add_bitfield (type, "reg", 0, 7);
  tdesc_add_bitfield (type, "exccode", 8, 15);

  tdesc_create_reg (feature, "c0", 72, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c1", 73, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c2", 74, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c3", 75, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c4", 76, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c5", 77, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c6", 78, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c7", 79, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c8", 80, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c9", 81, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c10", 82, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c11", 83, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c12", 84, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c13", 85, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c14", 86, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c15", 87, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c16", 88, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c17", 89, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c18", 90, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c19", 91, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c20", 92, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c21", 93, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c22", 94, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c23", 95, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c24", 96, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c25", 97, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c26", 98, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c27", 99, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c28", 100, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c29", 101, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c30", 102, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "c31", 103, 1, "capability", 256, "cheri_cap256");
  tdesc_create_reg (feature, "cap_cause", 104, 1, "capability", 64, "cap_cause");

  tdesc_mips64_cheri256 = result;
}

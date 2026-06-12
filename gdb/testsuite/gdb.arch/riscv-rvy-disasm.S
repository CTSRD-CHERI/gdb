    # Copyright 2026 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

        .section .riscv.attributes,"",@0x70000003
        .byte 65
        .word 24
        .asciz "riscv"
        .byte 1
        .word 14
        .byte 5
        .asciz "rv64y"

        .text
        .globl main
        .type main, @function
main:
        .option norvc
        # yadd gp, ra, sp
        .insn r 0x7b, 0, 0x03, gp, ra, sp
        # yhir gp, ra
        .word 0x0400d1fb
        # ybndswi gp, ra, 4096
        .word 0xe000d1fb
        # ybndswi gp, ra, 256
        .word 0xf000d1fb
        addi x1, x1, 1
        ret
        .size main, .-main

#as: -march=rv32gc_xcheri1p0 -mabi=il32pc64d
#source: xcheri-compressed-32.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+0:[ 	]+6522[ 	]+clc[ 	]+ca0,8\(csp\)
[ 	]+2:[ 	]+6562[ 	]+clc[ 	]+ca0,24\(csp\)
[ 	]+4:[ 	]+6588[ 	]+clc[ 	]+ca0,8\(ca1\)
[ 	]+6:[ 	]+e588[ 	]+csc[ 	]+ca0,8\(ca1\)
[ 	]+8:[ 	]+e42a[ 	]+csc[ 	]+ca0,8\(csp\)

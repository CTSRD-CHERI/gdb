#as: -march=rv64gc_xcheri1p0 -mabi=l64pc128d
#source: xcheri-compressed-64.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+0:[ 	]+2522[ 	]+clc[ 	]+ca0,16\(csp\)
[ 	]+2:[ 	]+2562[ 	]+clc[ 	]+ca0,48\(csp\)
[ 	]+4:[ 	]+2588[ 	]+clc[ 	]+ca0,16\(ca1\)
[ 	]+6:[ 	]+a588[ 	]+csc[ 	]+ca0,16\(ca1\)
[ 	]+8:[ 	]+a42a[ 	]+csc[ 	]+ca0,16\(csp\)

#as: --defsym RVY=1
#source: rvy64c-encoding-overlap.s
#objdump: -d
#name: RV64Y encoding overlap (with Y)

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+2588[ 	]+ly[ 	]+a0,16\(a1\)
[ 	]+2:[ 	]+a1c8[ 	]+sy[ 	]+a0,256\(a1\)
[ 	]+4:[ 	]+2522[ 	]+ly[ 	]+a0,16\(sp\)
[ 	]+6:[ 	]+a42a[ 	]+sy[ 	]+a0,16\(sp\)

#as: --defsym RVY=1
#source: rvy32c-encoding-overlap.s
#objdump: -d
#name: RV32Y encoding overlap (with Y)

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+61c8[ 	]+ly[ 	]+a0,128\(a1\)
[ 	]+2:[ 	]+e1c8[ 	]+sy[ 	]+a0,128\(a1\)
[ 	]+4:[ 	]+6532[ 	]+ly[ 	]+a0,264\(sp\)
[ 	]+6:[ 	]+e22a[ 	]+sy[ 	]+a0,256\(sp\)

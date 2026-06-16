#as: --defsym RVY=1
#source: rvy32c-encoding-overlap.s
#objdump: -d -M no-aliases
#name: RV32Y encoding overlap (with Y, no-aliases)

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+61c8[ 	]+c\.ly[ 	]+a0,128\(a1\)
[ 	]+2:[ 	]+e1c8[ 	]+c\.sy[ 	]+a0,128\(a1\)
[ 	]+4:[ 	]+6532[ 	]+c\.lysp[ 	]+a0,264\(sp\)
[ 	]+6:[ 	]+e22a[ 	]+c\.sysp[ 	]+a0,256\(sp\)

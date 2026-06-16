#as: --defsym RVY=1
#source: rvy64c-encoding-overlap.s
#objdump: -d -M no-aliases
#name: RV64Y encoding overlap (with Y, no-aliases)

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+2588[ 	]+c\.ly[ 	]+a0,16\(a1\)
[ 	]+2:[ 	]+a1c8[ 	]+c\.sy[ 	]+a0,256\(a1\)
[ 	]+4:[ 	]+2522[ 	]+c\.lysp[ 	]+a0,16\(sp\)
[ 	]+6:[ 	]+a42a[ 	]+c\.sysp[ 	]+a0,16\(sp\)

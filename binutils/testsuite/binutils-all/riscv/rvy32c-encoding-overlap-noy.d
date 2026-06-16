#as: --defsym RVY=0
#source: rvy32c-encoding-overlap.s
#objdump: -d
#name: RV32Y encoding overlap (without Y)

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+61c8[ 	]+flw[ 	]+fa0,4\(a1\)
[ 	]+2:[ 	]+e1c8[ 	]+fsw[ 	]+fa0,4\(a1\)
[ 	]+4:[ 	]+6532[ 	]+flw[ 	]+fa0,12\(sp\)
[ 	]+6:[ 	]+e22a[ 	]+fsw[ 	]+fa0,4\(sp\)

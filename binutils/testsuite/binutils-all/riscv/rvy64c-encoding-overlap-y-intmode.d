#as: --defsym RVY=1 -mabi=lp64d
#source: rvy64c-encoding-overlap.s
#objdump: -d
#name: RV64Y encoding overlap (with Y, intmode)

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+2588[ 	]+fld[ 	]+fa0,8\(a1\)
[ 	]+2:[ 	]+a1c8[ 	]+fsd[ 	]+fa0,128\(a1\)
[ 	]+4:[ 	]+2522[ 	]+fld[ 	]+fa0,8\(sp\)
[ 	]+6:[ 	]+a42a[ 	]+fsd[ 	]+fa0,8\(sp\)

#as: -march=rv64i_xcheri1p0
#objdump: -d
#name: xcheri disassembly

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+fe0081db[ 	]+cgetperm[ 	]+gp,cra
[ 	]+4:[ 	]+162081db[ 	]+cseal[ 	]+cgp,cra,csp

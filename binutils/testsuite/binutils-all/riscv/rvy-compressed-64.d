#as: -march=rv64yfdc
#objdump: -d
#name: RV64Y compressed instructions

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+2188[ 	]+ly[ 	]+a0,0\(a1\)
[ 	]+2:[ 	]+2588[ 	]+ly[ 	]+a0,16\(a1\)
[ 	]+4:[ 	]+3de8[ 	]+ly[ 	]+a0,496\(a1\)
[ 	]+6:[ 	]+a188[ 	]+sy[ 	]+a0,0\(a1\)
[ 	]+8:[ 	]+a988[ 	]+sy[ 	]+a0,32\(a1\)
[ 	]+a:[ 	]+2502[ 	]+ly[ 	]+a0,0\(sp\)
[ 	]+c:[ 	]+2522[ 	]+ly[ 	]+a0,16\(sp\)
[ 	]+e:[ 	]+357e[ 	]+ly[ 	]+a0,1008\(sp\)
[ 	]+10:[ 	]+a02a[ 	]+sy[ 	]+a0,0\(sp\)
[ 	]+12:[ 	]+bfaa[ 	]+sy[ 	]+a0,1008\(sp\)

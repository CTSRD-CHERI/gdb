#as: -march=rv32yfdc
#objdump: -d
#name: RV32Y compressed instructions

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+6188[ 	]+ly[ 	]+a0,0\(a1\)
[ 	]+2:[ 	]+6588[ 	]+ly[ 	]+a0,8\(a1\)
[ 	]+4:[ 	]+7de8[ 	]+ly[ 	]+a0,248\(a1\)
[ 	]+6:[ 	]+e188[ 	]+sy[ 	]+a0,0\(a1\)
[ 	]+8:[ 	]+e988[ 	]+sy[ 	]+a0,16\(a1\)
[ 	]+a:[ 	]+6502[ 	]+ly[ 	]+a0,0\(sp\)
[ 	]+c:[ 	]+6522[ 	]+ly[ 	]+a0,8\(sp\)
[ 	]+e:[ 	]+757e[ 	]+ly[ 	]+a0,504\(sp\)
[ 	]+10:[ 	]+e02a[ 	]+sy[ 	]+a0,0\(sp\)
[ 	]+12:[ 	]+ffaa[ 	]+sy[ 	]+a0,504\(sp\)

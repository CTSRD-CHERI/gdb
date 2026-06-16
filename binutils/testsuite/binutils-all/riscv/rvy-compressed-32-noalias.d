#as: -march=rv32yfdc
#source: rvy-compressed-32.s
#objdump: -d -M no-aliases
#name: RV32Y compressed instructions (no-aliases)

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+6188[ 	]+c\.ly[ 	]+a0,0\(a1\)
[ 	]+2:[ 	]+6588[ 	]+c\.ly[ 	]+a0,8\(a1\)
[ 	]+4:[ 	]+7de8[ 	]+c\.ly[ 	]+a0,248\(a1\)
[ 	]+6:[ 	]+e188[ 	]+c\.sy[ 	]+a0,0\(a1\)
[ 	]+8:[ 	]+e988[ 	]+c\.sy[ 	]+a0,16\(a1\)
[ 	]+a:[ 	]+6502[ 	]+c\.lysp[ 	]+a0,0\(sp\)
[ 	]+c:[ 	]+6522[ 	]+c\.lysp[ 	]+a0,8\(sp\)
[ 	]+e:[ 	]+757e[ 	]+c\.lysp[ 	]+a0,504\(sp\)
[ 	]+10:[ 	]+e02a[ 	]+c\.sysp[ 	]+a0,0\(sp\)
[ 	]+12:[ 	]+ffaa[ 	]+c\.sysp[ 	]+a0,504\(sp\)

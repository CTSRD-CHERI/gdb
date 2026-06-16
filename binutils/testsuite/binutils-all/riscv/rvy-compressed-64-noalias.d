#as: -march=rv64yfdc
#source: rvy-compressed-64.s
#objdump: -d -M no-aliases
#name: RV64Y compressed instructions (no-aliases)

.*: +file format .*


Disassembly of section \.text:

0+000 <.*>:
[ 	]+0:[ 	]+2188[ 	]+c\.ly[ 	]+a0,0\(a1\)
[ 	]+2:[ 	]+2588[ 	]+c\.ly[ 	]+a0,16\(a1\)
[ 	]+4:[ 	]+3de8[ 	]+c\.ly[ 	]+a0,496\(a1\)
[ 	]+6:[ 	]+a188[ 	]+c\.sy[ 	]+a0,0\(a1\)
[ 	]+8:[ 	]+a988[ 	]+c\.sy[ 	]+a0,32\(a1\)
[ 	]+a:[ 	]+2502[ 	]+c\.lysp[ 	]+a0,0\(sp\)
[ 	]+c:[ 	]+2522[ 	]+c\.lysp[ 	]+a0,16\(sp\)
[ 	]+e:[ 	]+357e[ 	]+c\.lysp[ 	]+a0,1008\(sp\)
[ 	]+10:[ 	]+a02a[ 	]+c\.sysp[ 	]+a0,0\(sp\)
[ 	]+12:[ 	]+bfaa[ 	]+c\.sysp[ 	]+a0,1008\(sp\)

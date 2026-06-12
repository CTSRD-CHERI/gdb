#as: -march=rv64i
#source: rvy.s
#objdump: -d

.*:[ 	]+file format .*


Disassembly of section .text:

0+000 <target>:
[ 	]+0:[ 	]+062081fb[ 	]+yadd[ 	]+gp,ra,sp
[ 	]+4:[ 	]+060081fb[ 	]+ymv[ 	]+gp,ra
[ 	]+8:[ 	]+0010c1fb[ 	]+yaddi[ 	]+gp,ra,1
[ 	]+c:[ 	]+e010d1fb[ 	]+ybndswi[ 	]+gp,ra,1
[ 	]+10:[ 	]+000091fb[ 	]+ly[ 	]+gp,0\(ra\)
[ 	]+14:[ 	]+0030a07b[ 	]+sy[ 	]+gp,0\(ra\)
[ 	]+18:[ 	]+081131fb[ 	]+amoswap\.y[ 	]+gp,ra,\(sp\)
[ 	]+1c:[ 	]+0e1131fb[ 	]+amoswap\.y\.aqrl[ 	]+gp,ra,\(sp\)
[ 	]+20:[ 	]+100131fb[ 	]+lr\.y[ 	]+gp,\(sp\)
[ 	]+24:[ 	]+140131fb[ 	]+lr\.y\.aq[ 	]+gp,\(sp\)
[ 	]+28:[ 	]+181131fb[ 	]+sc\.y[ 	]+gp,ra,\(sp\)
[ 	]+2c:[ 	]+1e1131fb[ 	]+sc\.y\.aqrl[ 	]+gp,ra,\(sp\)
[ 	]+30:[ 	]+0400d1fb[ 	]+yhir[ 	]+gp,ra
[ 	]+34:[ 	]+0a2081fb[ 	]+ysh1add[ 	]+gp,ra,sp
[ 	]+38:[ 	]+1a2081fb[ 	]+ysh2add[ 	]+gp,ra,sp
[ 	]+3c:[ 	]+2a2081fb[ 	]+ysh3add[ 	]+gp,ra,sp
[ 	]+40:[ 	]+3a2081fb[ 	]+ysh4add[ 	]+gp,ra,sp
[ 	]+44:[ 	]+4a2081fb[ 	]+ysh1add\.uw[ 	]+gp,ra,sp
[ 	]+48:[ 	]+5a2081fb[ 	]+ysh2add\.uw[ 	]+gp,ra,sp
[ 	]+4c:[ 	]+6a2081fb[ 	]+ysh3add\.uw[ 	]+gp,ra,sp
[ 	]+50:[ 	]+7a2081fb[ 	]+ysh4add\.uw[ 	]+gp,ra,sp
[ 	]+54:[ 	]+e000d1fb[ 	]+ybndswi[ 	]+gp,ra,4096
[ 	]+58:[ 	]+eff0d1fb[ 	]+ybndswi[ 	]+gp,ra,255
[ 	]+5c:[ 	]+f000d1fb[ 	]+ybndswi[ 	]+gp,ra,256
[ 	]+60:[ 	]+f1f0d1fb[ 	]+ybndswi[ 	]+gp,ra,504
[ 	]+64:[ 	]+f200d1fb[ 	]+ybndswi[ 	]+gp,ra,512
[ 	]+68:[ 	]+fff0d1fb[ 	]+ybndswi[ 	]+gp,ra,4080
[ 	]+6c:[ 	]+0000d1fb[ 	]+srliy[ 	]+gp,ra,0
[ 	]+70:[ 	]+03f0d1fb[ 	]+srliy[ 	]+gp,ra,63
[ 	]+74:[ 	]+5600007b[ 	]+ymodeswy
[ 	]+78:[ 	]+5610007b[ 	]+ymodeswi

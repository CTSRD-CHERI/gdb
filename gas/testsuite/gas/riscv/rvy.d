#as: -march=rv64ya_zba
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
[ 	]+34:[ 	]+022081fb[ 	]+packy[ 	]+gp,ra,sp
[ 	]+38:[ 	]+162081fb[ 	]+yaddrw[ 	]+gp,ra,sp
[ 	]+3c:[ 	]+262081fb[ 	]+ypermc[ 	]+gp,ra,sp
[ 	]+40:[ 	]+362081fb[ 	]+ybndsw[ 	]+gp,ra,sp
[ 	]+44:[ 	]+462081fb[ 	]+ybndsrw[ 	]+gp,ra,sp
[ 	]+48:[ 	]+562081fb[ 	]+ymodew[ 	]+gp,ra,sp
[ 	]+4c:[ 	]+0c2081fb[ 	]+yeq[ 	]+gp,ra,sp
[ 	]+50:[ 	]+1c2081fb[ 	]+yss[ 	]+gp,ra,sp
[ 	]+54:[ 	]+0e2081fb[ 	]+ysunseal[ 	]+gp,ra,sp
[ 	]+58:[ 	]+1e2081fb[ 	]+ybld[ 	]+gp,ra,sp
[ 	]+5c:[ 	]+f00081fb[ 	]+yamask[ 	]+gp,ra
[ 	]+60:[ 	]+f40081fb[ 	]+ybaser[ 	]+gp,ra
[ 	]+64:[ 	]+f41081fb[ 	]+ypermr[ 	]+gp,ra
[ 	]+68:[ 	]+f42081fb[ 	]+ytopr[ 	]+gp,ra
[ 	]+6c:[ 	]+f43081fb[ 	]+ylenr[ 	]+gp,ra
[ 	]+70:[ 	]+f44081fb[ 	]+ytagr[ 	]+gp,ra
[ 	]+74:[ 	]+f45081fb[ 	]+ytyper[ 	]+gp,ra
[ 	]+78:[ 	]+f46081fb[ 	]+ymoder[ 	]+gp,ra
[ 	]+7c:[ 	]+f60081fb[ 	]+ysentry[ 	]+gp,ra
[ 	]+80:[ 	]+0a2081fb[ 	]+ysh1add[ 	]+gp,ra,sp
[ 	]+84:[ 	]+1a2081fb[ 	]+ysh2add[ 	]+gp,ra,sp
[ 	]+88:[ 	]+2a2081fb[ 	]+ysh3add[ 	]+gp,ra,sp
[ 	]+8c:[ 	]+3a2081fb[ 	]+ysh4add[ 	]+gp,ra,sp
[ 	]+90:[ 	]+4a2081fb[ 	]+ysh1add\.uw[ 	]+gp,ra,sp
[ 	]+94:[ 	]+5a2081fb[ 	]+ysh2add\.uw[ 	]+gp,ra,sp
[ 	]+98:[ 	]+6a2081fb[ 	]+ysh3add\.uw[ 	]+gp,ra,sp
[ 	]+9c:[ 	]+7a2081fb[ 	]+ysh4add\.uw[ 	]+gp,ra,sp
[ 	]+a0:[ 	]+e000d1fb[ 	]+ybndswi[ 	]+gp,ra,4096
[ 	]+a4:[ 	]+eff0d1fb[ 	]+ybndswi[ 	]+gp,ra,255
[ 	]+a8:[ 	]+f000d1fb[ 	]+ybndswi[ 	]+gp,ra,256
[ 	]+ac:[ 	]+f1f0d1fb[ 	]+ybndswi[ 	]+gp,ra,504
[ 	]+b0:[ 	]+f200d1fb[ 	]+ybndswi[ 	]+gp,ra,512
[ 	]+b4:[ 	]+fff0d1fb[ 	]+ybndswi[ 	]+gp,ra,4080
[ 	]+b8:[ 	]+5600007b[ 	]+ymodeswy
[ 	]+bc:[ 	]+5610007b[ 	]+ymodeswi

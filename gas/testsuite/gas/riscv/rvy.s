target:
	yadd		gp, ra, sp
	ymv		gp, ra
	yaddi		gp, ra, 1
	ybndswi		gp, ra, 1
	ly		gp, 0(ra)
	sy		gp, 0(ra)
	amoswap.y	gp, ra, (sp)
	amoswap.y.aqrl	gp, ra, (sp)
	lr.y		gp, (sp)
	lr.y.aq		gp, (sp)
	sc.y		gp, ra, (sp)
	sc.y.aqrl	gp, ra, (sp)
	srliy		gp, ra, 64
	packy		gp, ra, sp
	yaddrw		gp, ra, sp
	ypermc		gp, ra, sp
	ybndsw		gp, ra, sp
	ybndsrw		gp, ra, sp
	ymodew		gp, ra, sp
	yeq		gp, ra, sp
	yss		gp, ra, sp
	ysunseal	gp, ra, sp
	ybld		gp, ra, sp
	yamask		gp, ra
	ybaser		gp, ra
	ypermr		gp, ra
	ytopr		gp, ra
	ylenr		gp, ra
	ytagr		gp, ra
	ytyper		gp, ra
	ymoder		gp, ra
	ysentry		gp, ra
	ysh1add		gp, ra, sp
	ysh2add		gp, ra, sp
	ysh3add		gp, ra, sp
	ysh4add		gp, ra, sp
	ysh1add.uw	gp, ra, sp
	ysh2add.uw	gp, ra, sp
	ysh3add.uw	gp, ra, sp
	ysh4add.uw	gp, ra, sp
	ybndswi		gp, ra, 4096
	ybndswi		gp, ra, 255
	ybndswi		gp, ra, 256
	ybndswi		gp, ra, 504
	ybndswi		gp, ra, 512
	ybndswi		gp, ra, 4080
	ymodeswy
	ymodeswi

.data
pad:
	.word 0x42
.align 4
cap:
	.capinit pad
	.8byte 0x0
	.8byte 0x0
ptr:
	.8byte pad

.text
.globl _start
.type _start STT_FUNC
_start:
	ldr	c2, [c2, :lo12:cap]
	ldr	c2, [x2, :lo12:cap]
	ldr	x2, [x2, :lo12:cap]
	ldr	w2, [x2, :lo12:cap]

add:
	add	c0, c0, :lo12:ptr

f1:
	adrp	c2, :got:cap
	ldr	c2, [c2, :got_lo12:cap]
	ldr	c2, [x2, :got_lo12:ptr]
	ldr	x2, [c2, :got_lo12:ptr]
	ldr	x2, [x2, :got_lo12:ptr]

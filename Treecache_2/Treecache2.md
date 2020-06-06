# Treecache 2

> #TeamRBTrees is back, and now they're planting more trees!
> 
> Connect to their donation interface at `nc pwn.hsctf.com 5009`.

> > Hint: Check your edge cases. Taking input is hard.

## Solution

### Outline
1. The vulnerability is that setting description length equal to `0` gives a heap overflow.
2. Leak the libc address by freeing a chunk onto the smallbin freelist and then using `malloc` first-fit to put the address of the leak in the `name` or `amount` parameter of a donation.
3. Use the heap overflow to poison the forward pointer of a chunk on the tcache freelist to get arbitrary write.
4. Write `system` to `__free_hook` and then `free` a chunk containing the string `/bin/sh` to get a shell.

### Vulnerability
We present a solution orthogonal to Treecache 1; of course, the exact same exploit and script will work on both. As always, we begin with a `checksec`.
```
$ checksec trees2
[*] '/trees2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
While this is a pretty sad `checksec` all things considered, we begin to get the idea that this is going to be heap exploitation given all of the protections against stack exploits.

Reversing the binary is quite painful; Ghidra's `Auto-create struct` functionality is enormously helpful. In short, the donations are stored as in a [red-black tree](https://en.wikipedia.org/wiki/Red%E2%80%93black_tree) indexed by the donation `id`. While occasionally a bit helpful, understanding red-black trees is *not required* to solve the challenge.

The hint suggests that the bug occurs when taking input. After reversing, we see that (if I remember correctly), all user input is first passed through the `read_str` function. Ghidra decompiles it to something like the following.
```c
void read_str(char *ptr, int len)
{
	int read_char;
	int i;
	
	i = 0;
	do {
		read_char = read(0,ptr + i,1);
		if (read_char != 1) {
			return;
		}
		i = i + 1;
	} while ((i != len) && (ptr[(long)i + -1] != '\n'));
	ptr[(long)i + -1] = '\0';
	return;
}
```
Immediately strange about this code is that it's taking input with a `do`-`while` loop, which means that as long as the first byte is valid, it will always get written down, which while suspicious is not ground-breaking. Additionally, the length check is on `i != len`, which means that if `i` is bigger than `len`, then this length check will never terminate the loop.

However, the edge case mentioned in the hint is if `len` is equal to `0`. In this case, first the `do`-`while` loop will trigger, reading in the first byte and incrementing `i` immediately. Then because the check is `i != len`, the loop allows overflows because `i > len` always.

Under normal circumstances (such as if the programmer is always passing in a positive integer to `len`), this is not a critical weakness. So we look for places that the user might be able to sneak in a `len = 0`. This occurs in the `edit_description` function; the part we care about decompiles roughly to the following.
```c
		puts("Enter length of new description.");
		read_ulong(&len_desc);
		if (len_desc < 0x401) {
			free(node->description);
			desc = (char *)malloc(len_desc);
			puts("Enter new description.");
			read_str(desc,(int)len_desc);		// len_desc = 0 is vulnerable!
			node->description = desc;
			puts("Enter new amount.");
			read_ulong(&(node->amount));
			printf("Edited entry %lu.\n",id);
		}
```
Thus, if we set the length of the description to `0`, we pass the unsigned long check of `len_desc < 0x401`, and we get the overflow described above. Because this overflow is happening with `malloc`'s memory, this means we get to overflow the allocated chunk, giving a heap overflow. This is a critical vulnerability.

### Leaking LIBC
Vulnerability notwithstanding, the typical way to leak libc is to use the fact that freed (smallbin) chunks exist on linked lists of freed chunks which start and end in libc. Because we are dealing with libc 2.29, we have to deal with the tcache, which stores up to seven freed chunks in a freelist in the heap. Simply freeing an eigth chunk will force `free` to place it onto one of libc's freelists, writing libc pointers into the chunk in the process. If we ask `malloc` for the eighth chunk back and read from it, we will have read out a libc pointer.

The details of exactly how this was accomplished are a bit annoying. Because descriptions are null-terminated (safely) by the program, we didn't find a way to allocate a description and then read out the leaked pointer. Rather, we observe that we can also leak using the `amount` and `name` fields of the donation. The corresponding section in `print_donation` roughly decompiles to the following.
```c
		printf("%lu trees\n", a->amount);
		printf("Donator: %s\n", a->name);
		printf("Description: %s\n", a->description);
```
In practice, we freed eight large chunks (with eight large descriptions), the first seven of which go onto the tcache freelist. Then we can call `make_donation` a whole bunch of times until we force `malloc` into splitting up the eigth large chunk into smaller donation-sized chunks. Because of the way splitting works, each of these small chunks also contains libc pointers. Eventually one of them will have the libc pointer stored in `amount` or `name`, which we can read from the print. Inelegant, but functional.

### Exploiting the Vulnerability
With libc leaked, we know we where want to write (`__free_hook`) and what we want to write (`system`). Now, my favorite of the freelists is tcache because it does practically no sanity checks on the pointers it receives. A chunk on the tcache freelist will look like the following.
```
0000000000000000      0000000000000101 <-- size of chunk (unchecked)
00007fff31415900      0000000000000000 <-- pointer to next chunk on freelist
...
```
Recall that we when we ask for `0` bytes in the description, the program lets us write continuously for as long as we want, potentially overflowing the chunk. So the set-up is as follows. First allocate our malicious `0`-byte chunk and then allocate a larger chunk below it. The part of the heap we care about looks something like the following.
```
0000000000000000      0000000000000021 <-- the 0-byte chunk
0000000000000000      0000000000000000
0000000000000000      0000000000000101 <-- the larger chunk
0000000000000000      0000000000000000
...
```
Now, free the bottom chunk onto the tcache freelist. This will make tcache store the pointer to the next chunk inside of the freed chunk.
```
0000000000000000      0000000000000021
0000000000000000      0000000000000000
0000000000000000      0000000000000101
00007fff31415900      0000000000000000 <-- tcache put this here
...
```
However, if we call `edit_donation` on the `0`-byte chunk (and receive it back), then our heap overflow can corrupt tcache's forward pointer.
```
0000000000000000      0000000000000021
deadbeefdeadbeef      deadbeefdeadbeef
deadbeefdeadbeef      deadbeefdeadbeef <-- size of chunk also corrupted
00007f00deadbeef      0000000000000000 <-- tcache's pointer has been corrupted
...
```
Because we just freed the large chunk onto the tcache freelist, the top of the tcache freelist currenlt points to the corrupted chunk. If we `malloc` for a chunk of size `0x100`, `malloc` will hand us back the corrupted chunk and then write the corrupted pointer `0x00007f00deadbeef` onto the tcache freelist. Then the next time we ask for a chunk of size `0x100`, the top of the tcache freelist will read `0x00007f00deadbeef`, so `malloc` will let us write at `0x00007f00deadbeef`. This gives us arbitrary write from tcache poison.

### Finishing Up
At this point, the remainder of the exploit is routine. It will be helpful to have a chunk in the heap with the string `/bin/sh` in it; simply edit a donation and enter all the strings as `/bin/sh`. Now use the leaked libc address to compute the addresses of `__free_hook` and `system`. Use the arbitrary write described above to write `system` into `__free_hook`. Finally, free the donation with the `/bin/sh`; this would normally call `free` with that pointer, but `__free_hook` overwrote `free` so that we are now calling `system('/bin/sh')`. This gives us a shell, from which we can easily get the flag.

The full exploit, with poor comments, can be found [here](/Treecache_2/tree2force.py). The original `.c` file in the challenge can be found [here](/trees2.c).

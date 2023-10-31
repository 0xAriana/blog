---
layout: page
title: "VLC 3.0.13 - MMS Stream bugs - Heap overflow + Integer underflow"
nav_order: 1
permalink: /real_bugs/vlc/mms
---
# Background
In VLC, IO (network stream protocols and more) is done under modules/access.
There is an old protocol called MMS (Microsoft media server) - [MMS Wiki](https://en.wikipedia.org/wiki/Microsoft_Media_Server)
There are two implementations used by VLC - MMST (MMS over TCP) and MMSH (MMS over HTTP).

## Packets
According to the logic in the VLC code, the packets are in the following formats:

| 2 bytes | 2 bytes | 4 bytes | 2 bytes | 2 bytes | n bytes |
| ------- | ------- | ------- | ------- | ------- | --- |
| `i_type`        |      `i_size`   |      `i_sequence`   |   `i_unknown`      |      `i_size2`   | data |


# Issues
## GetPacket  - Heap overflow
Packets are received in GetPacket:

```C
static int GetPacket( stream_t * p_access, chunk_t *p_ck )
{
    access_sys_t *p_sys = p_access->p_sys;
    int restsize;
    /* chunk_t */
    memset( p_ck, 0, sizeof( chunk_t ) );
    /* Read the chunk header */
    /* Some headers are short, like 0x4324. Reading 12 bytes will cause us
     * to lose synchronization with the stream. Just read to the length
     * (4 bytes), decode and then read up to 8 additional bytes to get the
     * entire header.
     */
    if( vlc_tls_Read( p_sys->stream, p_sys->buffer, 4, true ) < 4 )
    {
       msg_Err( p_access, "cannot read data 2" );
       return VLC_EGENERIC;
    }
    p_ck->i_type = GetWLE( p_sys->buffer);
    p_ck->i_size = GetWLE( p_sys->buffer + 2);
    restsize = p_ck->i_size;
    if( restsize > 8 )
        restsize = 8;
    if( vlc_tls_Read( p_sys->stream, p_sys->buffer + 4, restsize, true ) < restsize )
    {
        msg_Err( p_access, "cannot read data 3" );
        return VLC_EGENERIC;
    }
    p_ck->i_sequence  = GetDWLE( p_sys->buffer + 4);
    p_ck->i_unknown   = GetWLE( p_sys->buffer + 8);
    /* Set i_size2 to 8 if this header was short, since a real value won't be
     * present in the buffer. Using 8 avoid reading additional data for the
     * packet.
     */
    if( restsize < 8 )
        p_ck->i_size2 = 8;
    else
        p_ck->i_size2 = GetWLE( p_sys->buffer + 10);
    p_ck->p_data      = p_sys->buffer + 12;
    p_ck->i_data      = p_ck->i_size2 - 8;
    if( p_ck->i_type == 0x4524 )   // $E (End-of-Stream Notification) Packet
    {
        if( p_ck->i_sequence == 0 )
        {
            msg_Warn( p_access, "EOF" );
            return VLC_EGENERIC;
        }
        else
        {
            msg_Warn( p_access, "next stream following" );
            return VLC_EGENERIC;
        }
    }
    else if( p_ck->i_type == 0x4324 ) // $C (Stream Change Notification) Packet
    {
        /* 0x4324 is CHUNK_TYPE_RESET: a new stream will follow with a sequence of 0 */
        msg_Warn( p_access, "next stream following (reset) seq=%d", p_ck->i_sequence  );
        return VLC_EGENERIC;
    }
    else if( (p_ck->i_type != 0x4824) && (p_ck->i_type != 0x4424) )
    {
        /* Unsupported so far:
         * $M (Metadata) Packet               0x4D24
         * $P (Packet-Pair) Packet            0x5024
         * $T (Test Data Notification) Packet 0x5424
         */
        msg_Err( p_access, "unrecognized chunk FATAL (0x%x)", p_ck->i_type );
        return VLC_EGENERIC;
    }
    if( (p_ck->i_data > 0) &&
        (vlc_tls_Read( p_sys->stream, &p_sys->buffer[12], p_ck->i_data,
                       true ) < p_ck->i_data) )
    {
        msg_Err( p_access, "cannot read data 4" );
        return VLC_EGENERIC;
    }
#if 0
    if( (p_sys->i_packet_sequence != 0) &&
        (p_ck->i_sequence != p_sys->i_packet_sequence) )
    {
        msg_Warn( p_access, "packet lost ? (%d != %d)", p_ck->i_sequence, p_sys->i_packet_sequence );
    }
#endif
    p_sys->i_packet_sequence = p_ck->i_sequence + 1;
    p_sys->i_packet_used   = 0;
    p_sys->i_packet_length = p_ck->i_data;
    p_sys->p_packet        = p_ck->p_data;
    return VLC_SUCCESS;
}
```

We can see that there are 3 sequence of data receival:
1.  We receive 4 bytes which of type and `i_size` which describe the size of the next read (capped to 8).
2. We receive 8 bytes which are the rest of the header: `i_sequence`, `i_unknown` and `i_size2` which is the total size of the packet (including the headers and data).
3. Reading the data.

The issue is that when they calculate the remaining size of the packet to read:

```C
p_ck->i_data = p_ck->i_size2 - 8;
```
Instead of decreasing 12 (which is the size of the already read headers), they only decrease 8.
later on, `i_data` bytes is going to be read from the socket into the buffer `p_ck->p_data` at:

```C
    if( (p_ck->i_data > 0) &&
        (vlc_tls_Read( p_sys->stream, &p_sys->buffer[12], p_ck->i_data,
                       true ) < p_ck->i_data) )
    {
        msg_Err( p_access, "cannot read data 4" );
        return VLC_EGENERIC;
    }
```
And as we can see, it's being read into offset 12 of the buffer.

The size being read is capped to `i_size2 = 0xffff - 8 = 0xfff7` , so if the buffer size is less then
`0xfff7 + 0xc = 0x10003` we'll get an overflow.
looking at the struct which contains the buffer we can see the size:

```C
#define BUFFER_SIZE 65536
typedef struct
{
    int             i_proto;
    struct vlc_tls *stream;
    vlc_url_t       url;
    bool      b_proxy;
    vlc_url_t       proxy;
    int             i_request_context;
    uint8_t         buffer[BUFFER_SIZE + 1];
    bool      b_broadcast;
    uint8_t         *p_header;
    int             i_header;
    uint8_t         *p_packet;
    uint32_t        i_packet_sequence;
    unsigned int    i_packet_used;
    unsigned int    i_packet_length;
    uint64_t        i_start;
    uint64_t        i_position;
    asf_header_t    asfh;
    vlc_guid_t          guid;
} access_sys_t;
```
This struct is located on the heap, and the buffer size is 65536 + 1 = 0x10001 which is smaller.
Hence we get an heap overflow.

### Showcase
I compiled VLC myself using the following [guidelines](https://wiki.videolan.org/UnixCompile/) to get debug symbols.

Implemented a basic MMSH server which get's to the first time `GetPacket` is being called (`Describe->GetHeader->GetPacket`), 
passes the checks and send 0xffff bytes of 'A' (0x41) as the packet data,
set a break point after reading the data (read 4), and we can get the following using gdb:

![Pasted image 20230829030323](https://github.com/0xAriana/blog/assets/121199478/6bf59e52-e9cf-4e6b-8c98-8c0ba44d45ef)

As we can see buffer is filled by a lot of A's (0x41), and that the next struct field `b_broadcast` is set to 65 which is 0x41 - 'A', which confirms our assumption.

## GetPacket - integer underflow
When calculating the data size, we already saw the following line:

```C
p_ck->i_data      = p_ck->i_size2 - 8;
```
Since we control `i_size2` we think this might cause an underflow.
Now, looking at the definitions of `i_data` and `i_size2` in the `chunk_t` struct:

```C
typedef struct
{
    uint16_t i_type;
    uint16_t i_size;

    uint32_t i_sequence;
    uint16_t i_unknown;

    uint16_t i_size2;

    int      i_data;
    uint8_t  *p_data;

} chunk_t;
```
We can see that `i_data` is int, and `i_size2` is `uint16_t`.

Normally, copying any value of uint16 to int is fine, since the value is zero-extended by default.

However, when we decrement 8, the order of the subtraction is important, since, if we:
1. Copy the uint16 to the int.
2. Substract 8.
We might get an int underflow.
this is confirmed by the dissasembly (using IDA) of the relevant function:
![Pasted image 20230907102509](https://github.com/0xAriana/blog/assets/121199478/6aa86bca-2b3f-47a9-a410-3f1e3f99a8a5)


* r11d is the lower dword of r11 register.
* rbp+174 is the address of the local variable containing `i_size2`.

And we can see that the uint16 value is first copied (zero-extended) into r11d, and only then we subtract 8 from r11d. 

This is not very useful as of the moment, since the following sanity checks validates that `i_data` > 0:

```C
    if( (p_ck->i_data > 0) &&
        (vlc_tls_Read( p_sys->stream, &p_sys->buffer[12], p_ck->i_data,
                       true ) < p_ck->i_data) )
    {
        msg_Err( p_access, "cannot read data 4" );
        return VLC_EGENERIC;
    }
```
However, the value of `i_data` is being written to `p_sys->i_packet_length`:

```C
    p_sys->i_packet_length = p_ck->i_data;
```
Which might be useful somewhere else, I didn't verify this bug using my custom server + gdb.


# Responsible disclosure

1/09/2023 - Contacted VLC security and reported both issues.

7/09/2023 - Got a response recognizing the issues.

30/10/2023 - VLC team update that a fixed was issued and tagged 3.0.20

31/10/2023 - Published the findings and submitted a CVE.



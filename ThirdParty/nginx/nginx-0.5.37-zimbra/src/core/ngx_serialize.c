/*
 * Copyright (c) VMware, Inc. [1998 – 2011]. All Rights Reserved.
 *
 * For more information, see –
 * http://vmweb.vmware.com/legal/corporate/VMwareCopyrightPatentandTrademarkNotices.pdf
 */

#include "ngx_serialize.h"

/* serialize an unsigned integer onto a stream
   @param   stream      byte stream where to write out the integer
                        [use null to calculate the size first]
   @param   number      the number to be serialized
   @returns             the number of bytes serialized(or required)
 */
size_t serialize_number (u_char *stream, size_t number)
{
    size_t      x, y, d, digits;

    x = number;
    y = 0;
    digits = 0;

    do {
        ++digits;
        y = y*10 + (x%10);
        x/=10;
    } while (x);

    if (stream) {
        d = digits;

        do
        {
            *stream = '0' + (y%10);
            y /= 10;
            ++stream;
            --d;
        } while (d);
    }

    return digits;
}

/* deserialize an unsigned integer from a stream
   @param   stream      the byte stream
   @param   len         length of the byte stream
   @param   number      [out] the deserialized number
   @returns             number of bytes deserialized
 */
size_t deserialize_number (u_char *stream, size_t len, size_t *number)
{
    size_t  size, value;

    size = 0;
    value = 0;

    while ((len-- > 0) && (stream[size] >= '0') && (stream[size] <= '9')) {
        value *= 10;
        value += (stream[size] - '0');
        ++size;
    }

    if (number) { *number = value; }
    return size;
}

/* The serialization/deserialization of the peer information has to be 
   sensitive not only to the endianness and number of bits of the target 
   processor, but also has to be sensitive to the way the target compiler
   aligns the structure members. It is not safe to cache the entire peer
   structure, since that contains several members. The entire peer information
   actually can be serialized to just six bytes (four for the IPv4 octets), and
   two for the port.

   This is if we assume that the sockaddr datastructure pointed to by the 
   peer->sockaddr is indeed an IPv4 address (sockaddr_in), and this is a safe
   assumption to make

   On the other hand, the peer->name string contains a stringified 
   representation of the ip address and port, of the form XX.XX.XX.XX:PP,
   where XX are the octets of the IP address in human-readable order, and 
   the PP is the port number in human readbale format

   Reconstructing the ::name member will cause some additional processing
   overhead during deserialization, but the overhead is justified because of 
   the portability problems that arise due to the former method of 
   serialization

   As a side-effect of this compact form of serialization, the deserialization
   routine will need to accept a pool argument from which it will allocate
   the memory required for reconstructing the peer data structure

   Since nginx uses a form of slab allocation, repeated *alloc()s are not a
   problem

   So it is that the cached representation of the peer will be six bytes, 
   the first four of which will be the octets of the IP address of the peer
   in network-byte order (which is left to right), and the next two bytes
   will be the IPv4 port number, also in network byte order

   (note) 
   Also note that the serialize_peer_ipv4 function can be invoked with a 
   NULL stream argument, in which case no serialization will take place, 
   but the number of bytes that would have been required will be returned,
   which is useful when the size of the memory needs to be calculated
   before actually allocating memory for the stream 

   @param   stream      the byte stream onto which we should serialize the
                        peer information
                        this parameter can be null, in which case, this 
                        function just calculates the number of bytes that 
                        will be required to serialize the peer
                        if the `stream' argument is not null, it must contain
                        enough space to hold the serialized representation
                        (the size possibly being returned by a previous call
                        to this function with the `stream' parameter null)

    @param  peer        the nginx peer data structure to be serialized

    @returns            the number of bytes required for (or written during)
                        serialization
 */

size_t serialize_peer_ipv4 (u_char *stream, ngx_peer_addr_t *peer)
{
    /* TODO: assert that peer->socklen == sizeof (sockaddr_in) */
    return serialize_ipv4 (stream,(struct sockaddr_in *)peer->sockaddr);
}

size_t serialize_ipv4 (u_char *stream, struct sockaddr_in *sin)
{
    u_char              *octets;
    size_t               size, s;

    octets = (u_char *) &sin->sin_addr.s_addr;

    size = serialize_number (NULL, octets[0]) +
           serialize_number (NULL, octets[1]) +
           serialize_number (NULL, octets[2]) +
           serialize_number (NULL, octets[3]) +
           serialize_number (NULL, ntohs(sin->sin_port)) +
           4;               /* three dots for ip, plus one colon sep */

    if (stream) {
        s = 0;
        s += serialize_number (stream +s, octets[0]);
        stream[s++] = '.';
        s += serialize_number (stream +s, octets[1]);
        stream[s++] = '.';
        s += serialize_number (stream +s, octets[2]);
        stream[s++] = '.';
        s += serialize_number (stream +s, octets[3]);
        stream[s++] = ':';
        s += serialize_number (stream +s, ntohs(sin->sin_port));
    }

    return size;    
}

size_t serialize_addr_ipv4 (u_char *stream, struct sockaddr_in *sin)
{
    u_char              *octets;
    size_t               size, s;

    octets = (u_char *) &sin->sin_addr.s_addr;

    size = serialize_number (NULL, octets[0]) +
           serialize_number (NULL, octets[1]) +
           serialize_number (NULL, octets[2]) +
           serialize_number (NULL, octets[3]) +
           3;               /* three dots for ip */

    if (stream) {
        s = 0;
        s += serialize_number (stream +s, octets[0]);
        stream[s++] = '.';
        s += serialize_number (stream +s, octets[1]);
        stream[s++] = '.';
        s += serialize_number (stream +s, octets[2]);
        stream[s++] = '.';
        s += serialize_number (stream +s, octets[3]);
    }

    return size;    
}

ngx_peer_addr_t* deserialize_peer_ipv4 
    (u_char *stream, size_t len, ngx_pool_t *pool)
{
    ngx_peer_addr_t         *peer;
    struct sockaddr_in      *sin;
    u_char                  *name, *octets;
    size_t                   s,o,l,d;

    /* step 1 -- allocate memory for the required data structures */
    peer = ngx_pcalloc (pool, sizeof (ngx_peer_addr_t));
    sin = ngx_pcalloc (pool, sizeof (struct sockaddr_in));

    /* step 2 -- deserialize the sockaddr_in data structure */
    sin->sin_family = AF_INET;
    octets = (u_char *) &sin->sin_addr.s_addr;

    /* portability note: 
    
       normally when you assign an unsigned int to
       an unsigned char, C automatically chops off the extra bits of 
       the int. of course, the signedness matters, because an of 1 
       in a signed number indicates a negative value

       now, we could have written the statements below as 
       octets[n] = o;

       instead of 
       octets[n] = (u_char)o;

       but we are not sure about portability of size_t so we 
       explicitly type-cast
     */
    s = 0; l = len;
    d = deserialize_number (stream +s, l, &o);
    s += d;
    l -= d;
    octets[0] = (u_char)o;
    ++s;    /* dot */
    --l;
    d = deserialize_number (stream +s, l, &o);
    s += d;
    l -= d;
    octets[1] = (u_char)o;
    ++s;    /* dot */
    --l;
    d = deserialize_number (stream +s, l, &o);
    s += d;
    l -= d;
    octets[2] = (u_char)o;
    ++s;    /* dot */
    --l;
    d = deserialize_number (stream +s, l, &o);
    s += d;
    l -= d;
    octets[3] = (u_char)o;
    ++s;    /* colon */
    --l;
    d = deserialize_number (stream +s, l, &o);
    s += d;
    l -= d;
    sin->sin_port = htons((unsigned short int)o);

    /* step 3 -- build the stringified representation 'address:port' */
    name = ngx_pcalloc (pool, s);
    ngx_memcpy (name, stream, s);

    /* step 4 -- fill in the nginx peer data structure accordingly */
    peer->sockaddr = (struct sockaddr *)sin;
    peer->socklen = sizeof (struct sockaddr_in);
    peer->name.data = name;
    peer->name.len = s;

    return peer;
}

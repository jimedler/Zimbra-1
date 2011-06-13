#if !defined (_NGX_SERIALIZE_H_INCLUDED_)
#define _NGX_SERIALIZE_H_INCLUDED_

#include <ngx_core.h>

size_t serialize_number (u_char *stream, size_t number);
size_t deserialize_number (u_char *stream, size_t len, size_t *number);
size_t serialize_peer_ipv4 (u_char *stream, ngx_addr_t *peer);
size_t serialize_ipv4 (u_char *stream, struct sockaddr_in *sin);
size_t serialize_addr_ipv4 (u_char *stream, struct sockaddr_in *sin);
ngx_addr_t* deserialize_peer_ipv4 (u_char *stream, size_t len,
       ngx_pool_t *pool);

#endif

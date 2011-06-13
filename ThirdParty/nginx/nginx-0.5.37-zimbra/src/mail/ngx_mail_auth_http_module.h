/*
 * Copyright (c) VMware, Inc. [1998 – 2011]. All Rights Reserved.
 *
 * For more information, see –
 * http://vmweb.vmware.com/legal/corporate/VMwareCopyrightPatentandTrademarkNotices.pdf
 */

#ifndef _NGX_MAIL_AUTH_HTTP_MODULE_H_INCLUDED_
#define _NGX_MAIL_AUTH_HTTP_MODULE_H_INCLUDED_

/* Zimbra CHANGELOG:

   To share the load of the HTTP Authentication traffic, nginx needs to be 
   configured to recognize different URIs against the auth_http configuration
   directive. 

   To effect this change, the server configuration structure includes 4 arrays:
   (.) peers            One (ngx_peer_addr_t*) for each HTTP server:port
   (.) peer_failures    One (time_t) last fail time for each HTTP server:port
   (.) host_headers     One (ngx_str_t) for the corresponding Host Header string
   (.) uris             One (ngx_str_t) for each URI (eg: /cgi-bin/auth)

   The list of HTTP Auth servers is cycled through in a Round Robin fashion.
   To effect this, we maintain two variables in the server configuration, one
   indicating the current index (seed), and one containing the wrap around 
   number (max), so that the elected server always has an index of 0 .. max-1

 */

typedef struct {
    ngx_msec_t                      timeout;
    ngx_msec_t                      timeout_cache;

    ngx_str_t                       header;
    ngx_array_t                    *headers;

    ngx_array_t                     peers;
    ngx_array_t                     peer_failures;
    ngx_array_t                     host_headers;
    ngx_array_t                     uris;

    ngx_uint_t                      url_max;
    ngx_uint_t                      url_seed;

    u_char                         *file;
    ngx_uint_t                      line;

} ngx_mail_auth_http_conf_t;


typedef struct ngx_mail_auth_http_ctx_s  ngx_mail_auth_http_ctx_t;

typedef void (*ngx_mail_auth_http_handler_pt)(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx);

struct mc_workqueue_s;

struct ngx_mail_auth_http_ctx_s {
    ngx_buf_t                      *request;
    ngx_buf_t                      *response;
    ngx_peer_connection_t           peer;

    ngx_mail_auth_http_handler_pt   route_response_handler;

    ngx_uint_t                      state;
    ngx_uint_t                      hash;   /* no needed ? */

    u_char                         *header_name_start;
    u_char                         *header_name_end;
    u_char                         *header_start;
    u_char                         *header_end;

    ngx_str_t                       addr;
    ngx_str_t                       port;
    ngx_str_t                       err;
    ngx_str_t                       errmsg;
    ngx_str_t                       errcode;

    time_t                          wait_time;

    ngx_pool_t                     *pool;

    ngx_uint_t                      url_index;
    ngx_uint_t                      url_attempts;
    ngx_uint_t                      url_health_checked;

    ngx_flag_t                      wait_memcache;
};

#endif

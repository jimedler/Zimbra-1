#if !defined(_NGX_HTTP_UPSTREAM_ZMAUTH_H_INCLUDED_)
#define _NGX_HTTP_UPSTREAM_ZMAUTH_H_INCLUDED_

typedef enum {
    zmroutetype_fallback=0,
    zmroutetype_authtoken,
    zmroutetype_rest,
    zmroutetype_activesync,
    zmroutetype_caldav
} zmroutetype_t;

typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t    rrp;

    /* IPHASH */
    ngx_uint_t                          hash;
    u_char                              addr[4];    /* AF_INET addr */
    u_char                              porth;      /* AF_INET port-hi */
    u_char                              portl;      /* AF_INET port-lo */
    u_char                              tries;

    ngx_event_get_peer_pt               get_rr_peer;
    zmroutetype_t                       zmroutetype;
    ngx_addr_t                          zmpeer;
} ngx_http_upstream_zmauth_peer_data_t;

typedef struct {
    ngx_addr_t          *peer;
    ngx_str_t            hh;
    ngx_str_t            uri;
} ngx_http_upstream_zmauth_routehandler_t;

typedef struct {
    ngx_array_t                 rh;             /* ..._routehandler_t[] */
    ngx_uint_t                  rhseed;
    ngx_msec_t                  rhtimeout;
} ngx_http_upstream_zmauth_srv_conf_t;

typedef void (*ngx_http_upstream_zmauth_handler_pt)(ngx_http_request_t *r);

typedef struct {
    ngx_pool_t                                 *pool;
    ngx_log_t                                  *log;
    ngx_uint_t                                  tries;
    ngx_uint_t                                  seed;
    ngx_peer_connection_t                       peer;
    ngx_http_upstream_stage_pt                  stage;
    ngx_str_t                                   usr;
    ngx_str_t                                   qusr;
    ngx_http_upstream_zmauth_routehandler_t    *rh;
    ngx_uint_t                                  state;
    ngx_buf_t                                  *rreq;
    ngx_buf_t                                  *rresp;
    ngx_http_upstream_zmauth_handler_pt         rhandler;
    u_char                                     *header_name_start;
    u_char                                     *header_name_end;
    u_char                                     *header_start;
    u_char                                     *header_end;
    ngx_str_t                                   addr;
    ngx_str_t                                   port;
    ngx_str_t                                   err;
    ngx_http_upstream_zmauth_peer_data_t       *zmp;
} ngx_http_upstream_zmauth_ctx_t;

ngx_int_t
ngx_http_upstream_init_zmauth (ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);

#endif


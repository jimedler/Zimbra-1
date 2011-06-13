// HTTP proxy upstream routing module using Zimbra auth-token

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_serialize.h>
#include <ngx_memcache.h>
#include "ngx_http_upstream_zmauth_module.h"
#include <ctype.h>

static char *
    ngx_http_upstream_zmauth (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
    ngx_http_upstream_zmroute(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static void *ngx_http_upstream_zmauth_create_srv_conf
    (ngx_conf_t *cf);
static char *ngx_http_upstream_zmauth_merge_srv_conf
    (ngx_conf_t *cf, void *parent, void *child);
static ngx_flag_t elect_routehandler
    (ngx_http_upstream_zmauth_ctx_t *ctx, ngx_http_upstream_zmauth_srv_conf_t *zscf);
static ngx_int_t zmauth_discover_route (ngx_http_request_t *r);
static ngx_int_t zmauth_learn_route(ngx_http_request_t *r);

static ngx_int_t ngx_http_upstream_init_zmauth_peer
    (ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us,
    ngx_http_upstream_stage_pt stage);
static ngx_int_t ngx_http_upstream_get_zmauth_peer
    (ngx_peer_connection_t *pc, void *data);
static void zmauth_routelookup_dummy_handler(ngx_event_t *ev);
static void zmauth_routelookup_connect_handler(ngx_event_t *ev);
static void zmauth_dispose_context(ngx_http_request_t *r);
static void zmauth_error(ngx_http_request_t *r);
static ngx_int_t zmauth_routelookup_makerequest(ngx_http_request_t *r);
static void zmauth_routelookup_sendrequest_handler(ngx_event_t *wev);
static void zmauth_routelookup_recvresponse_handler(ngx_event_t *rev);
static void zmauth_routelookup_ignorestatusline(ngx_http_request_t *r);
static void zmauth_routelookup_processheaders(ngx_http_request_t *r);
static ngx_flag_t zmauth_check_rest(ngx_http_request_t *r, void **extra);
static ngx_flag_t zmauth_check_activesync(ngx_http_request_t *r, void **extra);
static ngx_flag_t zmauth_check_caldav(ngx_http_request_t *r,void **extra);
static ngx_flag_t zmauth_check_authtoken(ngx_http_request_t *r, void **extra);
static zmroutetype_t zmauth_check_uri(ngx_http_request_t *r, void **extra);
static ngx_flag_t zmauth_find_arg
    (/* const */ ngx_str_t *args, /* const */ ngx_str_t *arg, ngx_str_t *val);

static void mch_routelookup (mc_work_t *w);
static void mch_proxy (mc_work_t *w);
static void mch_discover_route (mc_work_t *w);
static void mch_destroy_http_pool (mc_work_t *w);

static void mcr_routelookup (ngx_http_request_t *r);
static void mcr_cachealias
    (ngx_http_request_t *r, ngx_str_t usr, ngx_str_t qusr);
static void mcr_cacheroute
    (ngx_http_request_t *r, ngx_str_t usr, ngx_str_t route);

#ifdef unused
static ngx_flag_t ngx_http_upstream_zmserver_from_cookie 
    (ngx_log_t *log, ngx_pool_t *pool, ngx_table_elt_t *cookie, ngx_addr_t *peer);
#endif

static void zmauth_translate_activesync_usr
    (ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *tgt);
static ngx_flag_t ngx_field_from_zmauthtoken
    (ngx_log_t  *log,
     ngx_pool_t *pool,
     ngx_str_t  *authtoken,
     ngx_str_t  *field,
     ngx_str_t  *value
    );
static ngx_flag_t ngx_get_cookie_value
    (
        ngx_log_t        *log,
        ngx_table_elt_t **cookies,
        ngx_uint_t        ncookies,
        ngx_str_t        *name,
        ngx_str_t        *value
    );
static ngx_flag_t ngx_get_query_string_arg
    (
        ngx_log_t       *log,
        ngx_str_t       *args,
        ngx_str_t       *name,
        ngx_str_t       *value
    );


static ngx_str_t    NGX_ZMAUTHTOKEN_ID = ngx_string("id");
static ngx_str_t    NGX_ZMAUTHTOKEN = ngx_string("ZM_AUTH_TOKEN");
static ngx_str_t    NGX_ZAUTHTOKEN = ngx_string("zauthtoken");
static ngx_str_t    NGX_HTTP_DEFAULT_AUTHMETHOD = ngx_string("other");
static ngx_str_t    NGX_HTTP_ID_AUTHMETHOD = ngx_string("zimbraId");

static ngx_command_t ngx_http_upstream_zmauth_commands[] = 
{
    {
        ngx_string("zmauth"),
        NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
        ngx_http_upstream_zmauth,
        0,
        0,
        NULL
    },

    {
        ngx_string("zmroutehandlers"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
        ngx_http_upstream_zmroute,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
    },

    {
        ngx_string("zmroute_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
        ngx_conf_set_msec_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_upstream_zmauth_srv_conf_t,rhtimeout),
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_upstream_zmauth_module_ctx = 
{
    NULL,               /* preconfiguration */
    NULL,               /* postconfiguration */
    NULL,               /* create main configuration */
    NULL,               /* init main configuration */
    ngx_http_upstream_zmauth_create_srv_conf,   /* create server config */
    ngx_http_upstream_zmauth_merge_srv_conf,    /* merge server config */
    NULL,               /* create location configuration */
    NULL                /* merge location configuration */
};

ngx_module_t ngx_http_upstream_zmauth_module = 
{
    NGX_MODULE_V1,
    &ngx_http_upstream_zmauth_module_ctx,
    ngx_http_upstream_zmauth_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

/* handle the `zmauth' configuration directive in an upstream block
 */
static char *
ngx_http_upstream_zmauth (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t    *uscf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    uscf->peer.init_upstream = ngx_http_upstream_init_zmauth;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
}

/* This is the `init_upstream' routine -- called when the main upstream
   configuration is initialized -- at this point, all the component servers
   in the upstream block should already be known, so that data-structures
   can be initialized here
 */
ngx_int_t
ngx_http_upstream_init_zmauth (ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    if (ngx_http_upstream_init_round_robin(cf,us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_zmauth_peer;
    return NGX_OK;
}

static void
ngx_http_upstream_noop_zmauth_stage (ngx_http_request_t *r)
{
    /* noop */
    return;
}

/* This function is called when an incoming http request needs to be routed to
   one of the peers inside the upstream block
 */
static ngx_int_t
ngx_http_upstream_init_zmauth_peer (ngx_http_request_t *r, 
    ngx_http_upstream_srv_conf_t *us, ngx_http_upstream_stage_pt stage)
{
    ngx_http_upstream_zmauth_peer_data_t    *zmp;
    struct sockaddr_in                      *sin;
    u_char                                  *p,*q;
    ngx_str_t                                usr;
    ngx_http_upstream_zmauth_ctx_t          *ctx;
    ngx_pool_t                              *pool;
    ngx_http_upstream_zmauth_srv_conf_t     *zscf;
    void                                    *info;

    ngx_log_debug0 (NGX_LOG_DEBUG_HTTP,r->connection->log,0,
        "zmauth: prepare route for proxy");

    zscf = ngx_http_get_module_srv_conf(r,ngx_http_upstream_zmauth_module);
    zmp = ngx_palloc (r->pool, sizeof(ngx_http_upstream_zmauth_peer_data_t));

    if (zmp == NULL) {
        return NGX_ERROR;
    }

    r->upstream->peer.data = &zmp->rrp;
    if (ngx_http_upstream_init_round_robin_peer
        (r,us,ngx_http_upstream_noop_zmauth_stage) != NGX_OK) {
        ngx_log_debug0 (NGX_LOG_DEBUG_HTTP,r->connection->log,0,
            "zmauth: cannot initialize round-robin fallback");
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_zmauth_peer;
    zmp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;

    /* initialize data for iphash for cases before AUTH TOKEN (prelogin) */

    sin = (struct sockaddr_in *)r->connection->sockaddr;
    p = (u_char *)&sin->sin_addr.s_addr;
    q = (u_char *)&sin->sin_port;
    zmp->addr[0] = p[0];
    zmp->addr[1] = p[1];
    zmp->addr[2] = p[2];
    zmp->addr[3] = p[3];
    zmp->porth = q[0];
    zmp->portl = q[1];

    zmp->hash = 89;
    zmp->tries = 0;

    zmp->zmroutetype = zmauth_check_uri(r,&info);
    if (zmp->zmroutetype != zmroutetype_fallback)
    {
        usr = *((ngx_str_t*)info);

        if (zscf->rh.nelts == 0)
        {
            ngx_log_error(NGX_LOG_ERR,r->connection->log,0,
                "zmauth: need to discover route, but no route handlers");
            return NGX_ERROR;   /* caller will fail with HTTP/500 */
        }

        ngx_log_debug0 (NGX_LOG_DEBUG_HTTP,r->connection->log,0,
            "zmauth: route lookup required to proxy request");

        pool = ngx_create_pool(2048,r->connection->log);
        if (pool == NULL) {
            return NGX_ERROR;
        }

        ctx = ngx_pcalloc (pool, sizeof(ngx_http_upstream_zmauth_ctx_t));
        if (ctx == NULL) {
            ngx_destroy_pool(pool);
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r,ctx,ngx_http_upstream_zmauth_module);

        ctx->pool = pool;
        ctx->stage = stage;
        ctx->tries = 0;
        elect_routehandler(ctx,zscf);
        ctx->usr.data = ngx_pstrdup(ctx->pool,&usr);
        ctx->usr.len = usr.len;
        ctx->qusr = ctx->usr;
        ctx->zmp = zmp;

        zmauth_learn_route(r);
    }
    else {
        /* Fallback to IPHASH */
        stage(r);
    }
    return NGX_OK;
}

static ngx_int_t zmauth_learn_route(ngx_http_request_t *r)
{
    ngx_http_upstream_zmauth_ctx_t          *ctx;
    ngx_http_upstream_zmauth_peer_data_t    *zmp;
    ngx_pool_t                              *pool;
    ngx_log_t                               *log;
    ngx_str_t                                vhost,k,pdu;
    u_char                                  *p;
    size_t                                   l;
    mc_work_t                                w;

    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    zmp = ctx->zmp;
    pool = ctx->pool;
    log = ngx_cycle->log;
    vhost = r->headers_in.host->value;

    if (zmp->zmroutetype == zmroutetype_authtoken) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP,log,0,
            "zmauth: learning route by id:%V",
            &ctx->qusr);
        mcr_routelookup(r);
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
        "zmauth: learning route, vhost:%V",
        &vhost);

    k = ngx_memcache_get_http_alias_key(pool, log, ctx->usr, vhost);

    if (k.len == 0) {    /* NOMEM */
        return zmauth_discover_route(r);
    }

    w.ctx = r;
    w.request_code = mcreq_get;
    w.response_code = mcres_unknown;
    w.on_success = mch_routelookup;
    w.on_failure = mch_routelookup;

    l = sizeof("get ") - 1 +
        k.len +
        sizeof(CRLF) - 1;

    pdu.data = ngx_palloc(pool, l);
    if (pdu.data == NULL) {     /* NOMEM */
        return zmauth_discover_route(r);
    }

    p = pdu.data;
    p = ngx_cpymem(p, "get ", sizeof("get ") - 1);
    p = ngx_cpymem(p, k.data, k.len);
    *p++ = CR;
    *p++ = LF;
    pdu.len = p - pdu.data;

    ngx_memcache_post(&w, k, pdu,/* pool */ NULL, log);
    return NGX_OK;

    // return zmauth_discover_route(r);
}

/* memcache handler (success or failure) for http user alias
 */
static void mch_routelookup (mc_work_t *w)
{
    ngx_http_request_t                      *r;
    ngx_http_upstream_zmauth_ctx_t          *ctx;
    ngx_http_upstream_zmauth_peer_data_t    *zmp;
    ngx_str_t                                qusr;

    r = (ngx_http_request_t *)w->ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_upstream_zmauth_module);
    zmp = ctx->zmp;

    if (w->response_code == mcres_success)
    {
        /* deep-copy w->payload to ctx->qusr (on pool r->pool) */
        qusr.data = ngx_pstrdup(r->pool,&w->payload);

        if (qusr.data != NULL)
        {
            qusr.len = w->payload.len;
            ctx->qusr = qusr;

            ngx_log_debug2 (NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "zmauth: usr:%V http-aliased to qusr:%V",
                &ctx->usr, &ctx->qusr
                );
        }
    }

    mcr_routelookup(r);
}

static void mcr_routelookup (ngx_http_request_t *r)
{
    ngx_http_upstream_zmauth_ctx_t          *ctx;
    ngx_http_upstream_zmauth_peer_data_t    *zmp;
    ngx_pool_t                              *pool;
    ngx_log_t                               *log;
    u_char                                  *p;
    size_t                                   l;
    ngx_str_t                                k,pdu;
    mc_work_t                                w;

    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    zmp = ctx->zmp;
    pool = ctx->pool;
    log = ngx_cycle->log;

    if (zmp->zmroutetype == zmroutetype_authtoken) {
        k = ngx_memcache_get_http_id_route_key(pool, log, ctx->qusr);
    } else {
        k = ngx_memcache_get_http_route_key(pool, log, ctx->qusr);
    }

    if (k.len == 0) {   /* NOMEM */
        zmauth_discover_route(r);
        return;
    }

    w.ctx = r;
    w.request_code = mcreq_get;
    w.response_code = mcres_unknown;
    w.on_success = mch_proxy;
    w.on_failure = mch_discover_route;

    l = sizeof("get ") - 1 +
        k.len +
        sizeof(CRLF) - 1;

    pdu.data = ngx_palloc(pool,l);
    if (pdu.data == NULL) { /* NOMEM */
        zmauth_discover_route(r);
        return;
    }

    p = pdu.data;
    p = ngx_cpymem(p, "get ", sizeof("get ") - 1);
    p = ngx_cpymem(p, k.data, k.len);
    *p++ = CR;
    *p++ = LF;
    pdu.len = p-pdu.data;

    ngx_memcache_post(&w,k,pdu,/* pool */ NULL,log);
}

/* memcache handler (cache-hit for http route)
 */
static void mch_proxy (mc_work_t *w)
{
    /* route lookup from memcache succeeded */

    ngx_http_request_t                      *r;
    ngx_http_upstream_zmauth_ctx_t          *ctx;
    ngx_http_upstream_zmauth_peer_data_t    *zmp;
    ngx_str_t                                route;
    ngx_http_upstream_stage_pt               stage;

    r = (ngx_http_request_t *)w->ctx;
    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    zmp = ctx->zmp;

    /* deep-copy w->payload to route */
    route.data = ngx_pstrdup(r->pool,&w->payload);

    if (route.data == NULL) {
        /* enomem - discover route from servlet */
        zmauth_discover_route(r);
    } else {
        route.len = w->payload.len;

        ngx_log_debug2 (NGX_LOG_DEBUG_HTTP,r->connection->log,0,
            "zmauth: learned cached route:%V for usr:%V",
            &route, &ctx->qusr
            );

        stage = ctx->stage;
        zmp->zmpeer = *deserialize_peer_ipv4 (route.data,route.len,r->pool);
        zmauth_dispose_context(r);  /* this destroys ctx->pool ! */
        stage(r);
    }
}

/* memcache handler (cache-miss for http route)
 */
static void mch_discover_route (mc_work_t *w)
{
    ngx_http_request_t                      *r;
    ngx_http_upstream_zmauth_ctx_t          *ctx;
    ngx_http_upstream_zmauth_peer_data_t    *zmp;

    r = (ngx_http_request_t *)w->ctx;
    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    zmp = ctx->zmp;

    ngx_log_debug1 (NGX_LOG_DEBUG_HTTP,r->connection->log,0,
        "zmauth: need to discover route for usr:%V",
        &ctx->usr
        );

    zmauth_discover_route(r);
}

/* discover route from lookup servlet */
static ngx_int_t zmauth_discover_route(ngx_http_request_t *r)
{
    ngx_http_upstream_zmauth_srv_conf_t         *zscf;
    ngx_http_upstream_zmauth_ctx_t              *ctx;
    ngx_int_t                                    rc;

    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    zscf = ngx_http_get_module_srv_conf(r,ngx_http_upstream_zmauth_module);

    ngx_log_debug1 (NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "zmauth: elected route handler #%d",ctx->seed);

    ctx->peer.sockaddr = ctx->rh->peer->sockaddr;
    ctx->peer.socklen = ctx->rh->peer->socklen;
    ctx->peer.name = &ctx->rh->peer->name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = r->connection->log; /* ? */
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP,r->connection->log,0,
            "zmauth: connect to route handler failed, host:%V, uri:%V",
            ctx->peer.name, &ctx->rh->uri);
        if (ctx->peer.connection) {
            ngx_close_connection(ctx->peer.connection);
        }
        if (!elect_routehandler(ctx,zscf)) {
            ngx_log_error(NGX_LOG_ERR,r->connection->log,0,
            "zmauth: all route handlers exhausted, cannot discover route");
            zmauth_dispose_context(r);
            zmauth_error(r);
            return NGX_ERROR;
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP,r->connection->log,0,
                "zmauth: failing over to route handler #%d",ctx->seed);
            return zmauth_discover_route(r);
        }
    }

    ctx->peer.connection->data = r;
    ctx->peer.connection->pool = r->connection->pool;       /* ? */
    ctx->peer.connection->read->handler = zmauth_routelookup_dummy_handler;
    ctx->peer.connection->write->handler = zmauth_routelookup_connect_handler;
    ngx_add_timer(ctx->peer.connection->read,zscf->rhtimeout);
    ngx_add_timer(ctx->peer.connection->write,zscf->rhtimeout);

    return NGX_OK;
}

static void zmauth_routelookup_dummy_handler(ngx_event_t *ev)
{
    ngx_connection_t        *c;
    ngx_http_request_t      *r;

    c = ev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP,c->log,0,
        "zmauth_routelookup_dummy_handler()");
}

static void zmauth_routelookup_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t                    *c;
    ngx_http_request_t                  *r;
    ngx_http_upstream_zmauth_ctx_t      *ctx;
    ngx_http_upstream_zmauth_srv_conf_t *zscf;
    ngx_pool_t                          *pool;
    int                                  sockerr;
    socklen_t                            sockerr_len;

    c = ev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    zscf = ngx_http_get_module_srv_conf(r,ngx_http_upstream_zmauth_module);
    pool = ctx->pool;

    sockerr=0;
    sockerr_len=sizeof(sockerr);
    getsockopt(c->fd,SOL_SOCKET,SO_ERROR,&sockerr,&sockerr_len);

    if(sockerr == EINPROGRESS) {
        /* expect to be reinvoked */
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,c->log,0,
            "zmauth: connect to route handler in progress");
        return;
    } else if (sockerr != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP,c->log,0,
            "zmauth: connect to route handler error:%d, will re-elect",
            sockerr);
        ngx_close_connection(c);
        if (!elect_routehandler(ctx,zscf)) {
            ngx_log_error(NGX_LOG_ERR,r->connection->log,0,
            "zmauth: all route handlers exhausted, cannot discover route");
            zmauth_dispose_context(r);
            zmauth_error(r);
            return;
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP,r->connection->log,0,
            "zmauth: failing over to route handler #%d",ctx->seed);
            zmauth_discover_route(r);
            return;
        }
    } else {
        if (zmauth_routelookup_makerequest(r) != NGX_OK) {
            ngx_close_connection(c);
            if (!elect_routehandler(ctx,zscf)) {
                ngx_log_error(NGX_LOG_ERR,r->connection->log,0,
                "zmauth: all route handlers exhausted, cannot discover route");
                zmauth_dispose_context(r);
                zmauth_error(r);
                return;
            } else {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP,r->connection->log,0,
                "zmauth: failing over to route handler #%d",ctx->seed);
                zmauth_discover_route(r);
                return;
            }
        }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,c->log,0,
            "zmauth: beginning route discovery");
        ctx->peer.connection->write->handler = zmauth_routelookup_sendrequest_handler;
        ctx->peer.connection->read->handler = zmauth_routelookup_recvresponse_handler;
        ctx->rhandler = zmauth_routelookup_ignorestatusline;
        ctx->peer.connection->write->handler(ctx->peer.connection->write);
        return;
    }
}

static void zmauth_routelookup_ignorestatusline(ngx_http_request_t *r)
{
    ngx_http_upstream_zmauth_ctx_t      *ctx;
    u_char                              *p, ch;
    enum  {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_skip,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zmauth: process route discovery HTTP status");

    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    state = ctx->state;

    for (p = ctx->rresp->pos; p < ctx->rresp->last; p++)
    {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            if (ch == 'H') {
                state = sw_H;
                break;
            }
            goto next;

        case sw_H:
            if (ch == 'T') {
                state = sw_HT;
                break;
            }
            goto next;

        case sw_HT:
            if (ch == 'T') {
                state = sw_HTT;
                break;
            }
            goto next;

        case sw_HTT:
            if (ch == 'P') {
                state = sw_HTTP;
                break;
            }
            goto next;

        case sw_HTTP:
            if (ch == '/') {
                state = sw_skip;
                break;
            }
            goto next;

        /* any text until end of line */
        case sw_skip:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            if (ch == LF) {
                goto done;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "zmauth: route handler &V sent invalid response",
                          ctx->peer.name);
            ngx_close_connection(ctx->peer.connection);
            zmauth_dispose_context(r);
            zmauth_error(r);
            return;
        }
    }

    ctx->rresp->pos = p;
    ctx->state = state;

    return;

next:

    p = ctx->rresp->start - 1;

done:

    ctx->rresp->pos = p + 1;
    ctx->state = 0;
    ctx->rhandler = zmauth_routelookup_processheaders;
    ctx->rhandler(r);
}

static ngx_int_t
zmauth_http_parse_header_line(ngx_http_request_t *r)
{
    u_char      c, ch, *p;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;
    ngx_http_upstream_zmauth_ctx_t      *ctx;

    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);

    state = ctx->state;

    for (p = ctx->rresp->pos; p < ctx->rresp->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;
                ctx->header_name_start = p;

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                return NGX_ERROR;
            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            return NGX_ERROR;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_ERROR;
            }
        }
    }

    ctx->rresp->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    ctx->rresp->pos = p + 1;
    ctx->state = sw_start;

    return NGX_OK;

header_done:

    ctx->rresp->pos = p + 1;
    ctx->state = sw_start;

    return NGX_DONE;
}


static void zmauth_routelookup_processheaders(ngx_http_request_t *r)
{
    ngx_http_upstream_zmauth_srv_conf_t     *zscf;
    ngx_http_upstream_zmauth_ctx_t          *ctx;
    ngx_http_upstream_zmauth_peer_data_t    *zmp;
    ngx_http_upstream_stage_pt               stage;
    size_t                                   len;
    ngx_int_t                                rc;
    ngx_str_t                                route;
    ngx_str_t                                ausr;

    zscf = ngx_http_get_module_srv_conf(r,ngx_http_upstream_zmauth_module);
    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    zmp = ctx->zmp;
    ausr = ctx->qusr;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zmauth: process route discovery HTTP headers");

    for (;;)
    {
        rc = zmauth_http_parse_header_line(r);

        if (rc == NGX_OK)
        {

#if (NGX_DEBUG)
            {
            ngx_str_t  key, value;

            key.len = ctx->header_name_end - ctx->header_name_start;
            key.data = ctx->header_name_start;
            value.len = ctx->header_end - ctx->header_start;
            value.data = ctx->header_start;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zmauth: route lookup http header: \"%V: %V\"",
                           &key, &value);
            }
#endif

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Auth-Status") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Status",
                                   sizeof("Auth-Status") - 1)
                   == 0)
            {
                len = ctx->header_end - ctx->header_start;

                if (len == 2
                    && ctx->header_start[0] == 'O'
                    && ctx->header_start[1] == 'K')
                {
                    continue;
                }

                if (len == 4
                    && ctx->header_start[0] == 'W'
                    && ctx->header_start[1] == 'A'
                    && ctx->header_start[2] == 'I'
                    && ctx->header_start[3] == 'T')
                {
                    /* we will ignore the WAIT for HTTP */
                    continue;
                }

                ctx->err.len = len;
                ctx->err.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Server") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Server",
                                   sizeof("Auth-Server") - 1)
                    == 0)
            {
                ctx->addr.len = ctx->header_end - ctx->header_start;
                ctx->addr.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Port") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Port",
                                   sizeof("Auth-Port") - 1)
                   == 0)
            {
                ctx->port.len = ctx->header_end - ctx->header_start;
                ctx->port.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-User") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-User",
                                   sizeof("Auth-User") - 1)
                   == 0)
            {
                ausr.len = ctx->header_end - ctx->header_start;
                ausr.data = ctx->header_start;

                continue;
            }


            /* Ignore Auth-Pass */
            /* Ignore Auth-Wait (TODO -- confirm this) */
            /* Ignore Auth-Error-Code */
            /* Ignore other headers */

            continue;
        }

        if (rc == NGX_DONE)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zmauth: done processing route discovery headers");

            ngx_close_connection(ctx->peer.connection);

            if (ctx->err.len) {
                /* TODO what happens if routelookup fails? */
            }

            if (ctx->addr.len == 0 || ctx->port.len == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "zmauth: route handler %V did not send server or port",
                  ctx->peer.name);
                zmauth_dispose_context(r);
                zmauth_error(r);
                return;
            } else {
                /* addr and port contain the route */
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "zmauth: route handler %V sent route %V:%V",
                  ctx->peer.name,&ctx->addr,&ctx->port);
                route.data = ngx_palloc(r->pool,ctx->addr.len+sizeof(":")-1+ctx->port.len);
                if (route.data == NULL) {
                    zmauth_dispose_context(r);
                    zmauth_error(r);
                    return;
                }
                ngx_memcpy(route.data,ctx->addr.data,ctx->addr.len);
                ngx_memcpy(route.data+ctx->addr.len,":",sizeof(":")-1);
                ngx_memcpy(route.data+ctx->addr.len+sizeof(":")-1,ctx->port.data,ctx->port.len);
                route.len = ctx->addr.len + sizeof(":")-1 + ctx->port.len;
                stage = ctx->stage;
                zmp->zmpeer = *deserialize_peer_ipv4 (route.data,route.len,r->pool);
                stage(r);       /* Begin proxying as soon as we have the route */
                mcr_cachealias(r,ctx->usr,ausr);   /* cache http user alias */
                mcr_cacheroute(r,ausr,route);   /* cache http route for future use */
                zmauth_dispose_context(r);      /* it is safe to clear the context now */
                return;
            }
        }

        if (rc == NGX_AGAIN ) {
            return;
        }

        /* rc == NGX_ERROR */

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
              "zmauth: route handler %V sent invalid header in response",
              ctx->peer.name);

        ngx_close_connection(ctx->peer.connection);
        zmauth_dispose_context(r);
        zmauth_error(r);

        return;
    }
}

static void zmauth_routelookup_sendrequest_handler(ngx_event_t *wev)
{
    ngx_connection_t                        *c;
    ngx_http_request_t                      *r;
    ngx_http_upstream_zmauth_ctx_t          *ctx;
    ngx_http_upstream_zmauth_srv_conf_t     *zscf;
    ssize_t                                 size,n;

    c = wev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    zscf = ngx_http_get_module_srv_conf(r,ngx_http_upstream_zmauth_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR,wev->log,NGX_ETIMEDOUT,
            "zmauth: route handler timed out");
        ngx_close_connection(c);
        zmauth_dispose_context(r);
        zmauth_error(r);
        return;
    }

    size = ctx->rreq->last - ctx->rreq->pos;
    n = ngx_send(c,ctx->rreq->pos,size);

    if (n == NGX_ERROR) {
        ngx_close_connection(c);
        zmauth_dispose_context(r);
        zmauth_error(r);
        return;
    }
    if (n>0) {
        ctx->rreq->pos += n;
        if (n==size) {
            wev->handler = zmauth_routelookup_dummy_handler;
            if (wev->timer_set) {
                ngx_del_timer(wev);
            }
            if (ngx_handle_write_event(wev,0) == NGX_ERROR) {
                ngx_close_connection(c);
                zmauth_dispose_context(r);
                zmauth_error(r);
                return;
            }
        }
    }
    if (!wev->timer_set) {
        ngx_add_timer(wev,zscf->rhtimeout);
    }
}

static void zmauth_routelookup_recvresponse_handler(ngx_event_t *rev)
{
    ngx_connection_t                *c;
    ngx_http_request_t              *r;
    ngx_http_upstream_zmauth_ctx_t  *ctx;
    ssize_t                          n,size;

    c = rev->data;
    r = c->data;
    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);

    if(rev->timedout) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP,c->log,0,
            "zmauth: route handler timed out, host:%V,uri:%V",
            &ctx->rh->peer->name,&ctx->rh->uri);
        ngx_close_connection(c); /* ctx->peer.connection? */
        zmauth_dispose_context(r);
        zmauth_error(r);
        return;
    }

    if(ctx->rresp == NULL) {
        ctx->rresp = ngx_create_temp_buf(ctx->pool,1024);
        /* TODO handle NULL */
    }

    size = ctx->rresp->end - ctx->rresp->last;
    n = ngx_recv(c, ctx->rresp->pos, size);

    if(n>0) {
        ctx->rresp->last += n;
        ctx->rhandler(r);
        return;
    }

    if(n==NGX_AGAIN) {
        return;
    }

    ngx_close_connection(c);
    zmauth_dispose_context(r);
    zmauth_error(r);
    return;
}

static ngx_int_t zmauth_routelookup_makerequest(ngx_http_request_t *r)
{
    ngx_http_upstream_zmauth_ctx_t      *ctx;
    ngx_http_upstream_zmauth_peer_data_t    *zmp;
    ngx_buf_t                           *b;
    size_t                               len;
    ngx_str_t                            uri;
    ngx_str_t                            hh;
    ngx_pool_t                          *pool;
    ngx_str_t                            ameth;
    ngx_str_t                            vhost;

    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    uri = ctx->rh->uri;
    hh = ctx->rh->hh;
    pool = ctx->pool;
    zmp = ctx->zmp;
    ameth = (zmp->zmroutetype == zmroutetype_authtoken ? NGX_HTTP_ID_AUTHMETHOD : NGX_HTTP_DEFAULT_AUTHMETHOD);
    vhost = r->headers_in.host->value;

    len = sizeof("GET ")-1 + uri.len + sizeof(" HTTP/1.0" CRLF)-1
        + sizeof("Host: ")-1 + hh.len + sizeof(CRLF)-1
        + sizeof("Auth-Method: ")-1 + ameth.len + sizeof(CRLF)-1
        + sizeof("Auth-User: ")-1 + ctx->usr.len + sizeof(CRLF)-1
        + sizeof("Auth-Pass: XXX" CRLF)-1
        + sizeof("Auth-Salt: SSS" CRLF)-1
        + sizeof("Auth-Protocol: http" CRLF)-1
        + sizeof("Auth-Login-Attempt: ")-1 + NGX_INT_T_LEN + sizeof(CRLF)-1
        + sizeof("X-Proxy-Host: ")-1 + vhost.len + sizeof(CRLF)-1
        + sizeof(CRLF)-1;

    b = ngx_create_temp_buf(pool,len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->last,"GET ",sizeof("GET ")-1);
    b->last = ngx_cpymem(b->last,uri.data,uri.len);
    b->last = ngx_cpymem(b->last," HTTP/1.0" CRLF,sizeof(" HTTP/1.0" CRLF)-1);
    b->last = ngx_cpymem(b->last,"Host: ",sizeof("Host: ")-1);
    b->last = ngx_cpymem(b->last,hh.data,hh.len);
    b->last = ngx_cpymem(b->last,CRLF,sizeof(CRLF)-1);
    b->last = ngx_cpymem(b->last,"Auth-Method: ",sizeof("Auth-Method: ")-1);
    b->last = ngx_cpymem(b->last,ameth.data,ameth.len);
    b->last = ngx_cpymem(b->last,CRLF,sizeof(CRLF)-1);
    b->last = ngx_cpymem(b->last,"Auth-User: ",sizeof("Auth-User: ")-1);
    b->last = ngx_cpymem(b->last,ctx->usr.data,ctx->usr.len);
    b->last = ngx_cpymem(b->last,CRLF,sizeof(CRLF)-1);
    b->last = ngx_cpymem(b->last,"Auth-Pass: XXX" CRLF,sizeof("Auth-Pass: XXX" CRLF)-1);
    b->last = ngx_cpymem(b->last,"Auth-Salt: SSS" CRLF,sizeof("Auth-Salt: SSS" CRLF)-1);
    b->last = ngx_cpymem(b->last,"Auth-Protocol: http" CRLF,sizeof("Auth-Protocol: http" CRLF)-1);
    b->last = ngx_cpymem(b->last,"Auth-Login-Attempt: 0" CRLF,sizeof("Auth-Login-Attempt: 0" CRLF)-1);
    b->last = ngx_cpymem(b->last,"X-Proxy-Host: ",sizeof("X-Proxy-Host: ")-1);
    b->last = ngx_cpymem(b->last,vhost.data,vhost.len);
    b->last = ngx_cpymem(b->last,CRLF,sizeof(CRLF)-1);
    b->last = ngx_cpymem(b->last,CRLF,sizeof(CRLF)-1);

    ctx->rreq = b;

    return NGX_OK;
}


/* This method is invoked in order to fill in the sockaddr, socklen, and name
   parameters of the peer connection data-structure (ngx_peer_connection_t)
 */
static ngx_int_t
ngx_http_upstream_get_zmauth_peer (ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_zmauth_peer_data_t    *zmp = data;
    ngx_http_upstream_rr_peer_t             *peer;
    time_t                                   now;
    uintptr_t                                m;
    ngx_uint_t                               i,n,p,hash;

    ngx_log_debug1 (NGX_LOG_DEBUG_HTTP, pc->log, 0, 
        "zmauth: prepare upstream connection, try: %d",
        pc->tries);

    if (zmp->zmroutetype != zmroutetype_fallback)
    {
        pc->sockaddr = zmp->zmpeer.sockaddr;
        pc->socklen = zmp->zmpeer.socklen;
        pc->name = &zmp->zmpeer.name;

        return NGX_OK;
    }
    else if (zmp->tries > 20 || zmp->rrp.peers->number == 1)
    {
        /* fall back to round-robin -- too many tries (>20) */
        ngx_log_debug0 (NGX_LOG_DEBUG_HTTP, pc->log, 0, 
            "zmauth: fall back to round-robin");
        return zmp->get_rr_peer (pc, &zmp->rrp);
    }
    else
    {
        now = ngx_time();
        pc->cached = 0;
        pc->connection = NULL;
        hash = zmp->hash;
        for (;;)
        {
            /* use all four octets of ipv4 address, 
               plus two bytes of ipv4 port, 
               for computation of ip-hash
               this ensures better distribution
             */

            for (i=0; i<4; ++i) {
                hash = (hash*113 + zmp->addr[i]) % 6271;
            }
            hash = (hash*113 + zmp->porth) % 6271;
            hash = (hash*113 + zmp->portl) % 6271;

            zmp->hash = hash;

            p = hash % zmp->rrp.peers->number;
            n = p/(8 * sizeof(uintptr_t));
            m = 1 << p % (8 * sizeof(uintptr_t));

            if (!(zmp->rrp.tried[n] & m)) {

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                               "get ip hash peer, hash: %ui %04XA", p, m);

                peer = &zmp->rrp.peers->peer[p];

                /* ngx_lock_mutex(iphp->rrp.peers->mutex); */

                if (!peer->down) {

                    if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
                        break;
                    }

                    if (now - peer->accessed > peer->fail_timeout) {
                        peer->fails = 0;
                        break;
                    }
                }

                zmp->rrp.tried[n] |= m;

                /* ngx_unlock_mutex(iphp->rrp.peers->mutex); */

                pc->tries--;
            }

            if (++zmp->tries >= 20) {
                ngx_log_debug0 (NGX_LOG_DEBUG_HTTP, pc->log, 0, 
                    "zmauth: iphash tries>20, fallback to round robin");
                return zmp->get_rr_peer(pc, &zmp->rrp) == NGX_OK ? NGX_OK :
                    zmp->get_rr_peer(pc, &zmp->rrp);
            }
        }

        pc->sockaddr = peer->sockaddr;
        pc->socklen = peer->socklen;
        pc->name = &peer->name;

        ngx_log_debug1 (NGX_LOG_DEBUG_HTTP, pc->log, 0, 
            "zmauth: %V elected by iphash", &peer->name);

        /* ngx_unlock_mutex(zmp->rrp.peers->mutex); */

        zmp->rrp.tried[n] |= m;
        zmp->hash = hash;

        return NGX_OK;
    }
}

/* examine a single request cookie for ZM_AUTH_TOKEN
   if present, fill in peer with the ip:port of the decoded mailhost (true)
   else return false
 */
#ifdef unused
static ngx_flag_t ngx_http_upstream_zmserver_from_cookie 
    (ngx_log_t *log, ngx_pool_t *pool, ngx_table_elt_t *cookie, ngx_addr_t *peer)
{
    ngx_str_t           *cv = &cookie->value;
    u_char              *p, *q, *start, *end;
    ngx_int_t            z;
    ngx_str_t            enc_token, enc_zmdata, dec_zmdata, ip, line;
    ngx_int_t            part1, part2, part3;
    size_t               i,j,qlen;
    ngx_flag_t           ret;
    u_char              *ZM_AUTH_TOKEN = (u_char *)"ZM_AUTH_TOKEN";
    const size_t         ZMLEN = sizeof("ZM_AUTH_TOKEN")-1;

    ret = 0;

    start = cv->data;
    end = start + cv->len;
    p = start;

    /* cv will be of the form name=value; name=value; name=value; ... */
    while (p < end)
    {
        line.data = p;
        line.len = end - p;

        /* The latter part of the loop will ensure that at this point, `p'
           points to the start of a "NAME=VALUE" string
         */

        z = ngx_memn2cmp (p, ZM_AUTH_TOKEN, (size_t)(end-p) > ZMLEN ? ZMLEN : (size_t)(end-p), ZMLEN);

        if (z == 0)
        {
            /* match found
               the value against zm_auth_token is
               X_YYY_ZZZZZZZZZZ
               the X and Y parts must be ignored, and the Z part is hex-encoded
               after decoding the Z part, we can get a string like:
               id=36:cc00ce85-8c0b-49eb-8e08-a8aab43ce836;exp=13:1196504658160;type=6:zimbra;mailhost=14:127.0.0.1:7070;
             */

            p = p + ZMLEN;

            if (p < end)
            {
                /* There is some value against ZM_AUTH_TOKEN

                   TODO: research the RFC on the cookie header and see if spaces
                   are allowed between [NAME=VALUE], as in [NAME = VALUE]
                 */
                if (*p == '=')
                {
                    ++p;

                    /* p is at (ZMAUTH_TOKEN=)VALUE
                                              ^
                       build up enc_token containing the entire value
                     */

                    enc_token.data = p;

                    part2 = part3 = -1;
                    part1 = 0;

                    while (p < end && *p != ';' && !isspace(*p)) {
                        if (*p == '_') { 
                            if (part2 < 0) { part2 = (p-enc_token.data) +1; }
                            else if (part3 < 0) { part3 = (p-enc_token.data) +1; }
                        }
                        ++p;
                    }

                    if (part3 < 0) { part3 = 0; }

                    enc_token.len = p - enc_token.data;

                    /* enc_token contains the entire hex-encoded auth-token,
                       we are interested in only the part after the second 
                       underscore 
                     */

                    enc_zmdata.data = enc_token.data + part3;
                    enc_zmdata.len = enc_token.len - part3;

                    /* now enc_zmdata contains the hex-encoded auth-token */
                    if (enc_zmdata.len % 2 == 1) {
                        ngx_log_error (NGX_LOG_ERR, log, 0, 
                            "zmauth: odd bytes in hex-encoded zmauth: enc=[%V], len=[%d]",
                            &enc_zmdata, enc_zmdata.len
                        );
                    } else {
                        /* now hex-decode the thingy */
                        dec_zmdata.data = ngx_palloc (pool, enc_zmdata.len/2 +1); // +1 for null
                        dec_zmdata.len = enc_zmdata.len/2;

                        for (i =0, j=0; i<enc_zmdata.len; i=i+2, j=j+1) {
                            if (enc_zmdata.data[i] >= '0' && enc_zmdata.data[i] <= '9') {
                                dec_zmdata.data[j] = enc_zmdata.data[i] - '0';
                            } else {
                                dec_zmdata.data[j] = 10 + tolower (enc_zmdata.data[i]) - 'a';
                            }
                            dec_zmdata.data[j] <<= 4;
                            if (enc_zmdata.data[i+1] >= '0' && enc_zmdata.data[i+1] <= '9') {
                                dec_zmdata.data[j] += (enc_zmdata.data[i+1] - '0');
                            } else {
                                dec_zmdata.data[j] += 10 + tolower (enc_zmdata.data[i+1]) - 'a';
                            }
                        }

                        dec_zmdata.data[j] =0;

                        /* The decoded data looks like (on a single line) -

                           id=36:cc00ce85-8c0b-49eb-8e08-a8aab43ce836;
                           exp=13:1196504658160;
                           type=6:zimbra;
                           mailhost=14:127.0.0.1:7070;

                           semicolon separated list of strings of the form
                           field=len:value

                         */

                        ngx_log_debug1 (NGX_LOG_DEBUG_HTTP, log, 0,
                            "zmauth: decode(ZM_AUTH_TOKEN):[%V]", &dec_zmdata
                        );

                        /* now we set up a loop to locate the mailhost */
                        q = (u_char *) ngx_strstr (dec_zmdata.data, "mailhost=");

                        if (q != NULL) {
                            q += sizeof("mailhost=") -1;
                            // now q will point to the length: portion of the ipaddress:port
                            qlen = 0;
                            while (*q != ':') {     // XXX: no bounds check - too far in
                                qlen = (qlen*10) + (*q-'0');
                                ++q;
                            }
                            ++q;        // consume ':'
                            ip.data = q;
                            ip.len = qlen;

                            /* now ip contains the ip-address:port of the upstream */
                            ngx_log_debug1 (NGX_LOG_DEBUG_HTTP, log, 0,
                                "zmauth: mailhost(ZM_AUTH_TOKEN):[%V]", &ip
                            );

                            *peer = *deserialize_peer_ipv4 (ip.data, ip.len, pool);
                            ret=1;
                        }
                    }
                }
            }

        } else {
            while (p < end && *p!=';') { ++p; }
            if (p < end) {
                ++p;    // consume `;'
                while (p < end && isspace (*p)) { ++p; }
            } else {
                /* we have reached the end of the cookie string */
                continue;
            }
        }
    }

    return ret;
}
#endif

static ngx_flag_t ngx_get_cookie_value
    (
        ngx_log_t        *log,
        ngx_table_elt_t **cookies,
        ngx_uint_t        ncookies,
        ngx_str_t        *name,
        ngx_str_t        *value
    )
{
    ngx_table_elt_t     **c;
    u_char               *s,*p,*e;
    ngx_str_t             V,n,v;
    ngx_flag_t            f;

    for (c=cookies,f=0;c<cookies+ncookies && f==0;++c) {
        V = (*c)->value;
        /* v is of the form "name=value; name=value;" */
        s=V.data;
        e=s+V.len;
        p=s;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP,log,0,
            "zmauth: examining cookie value:%V",&V);

        while (p<e) {
            n.data=p;
            while(p<e && *p!='=') { ++p; }
            if (p==e) { break; }
            n.len=p-n.data;
            ++p;        // consume =
            v.data=p;
            while(p<e && *p!=';') { ++p; }
            v.len=p-v.data;
            if (n.len == name->len &&
                ngx_memcmp(n.data,name->data,n.len) == 0
               ) {
                *value=v;
                f=1;
                break;
            }
            if (p==e) { break; }
            ++p;        // consume ;
            while(p<e && (*p==' ' || *p=='\t')) { ++p; }
        }
    }

    return f;
}

static ngx_flag_t ngx_get_query_string_arg
    (
        ngx_log_t       *log,
        ngx_str_t       *args,
        ngx_str_t       *name,
        ngx_str_t       *value
    )
{
    ngx_flag_t      f=0;
    u_char          *f1,*f2,*v1,*v2,*s,*e,*p;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP,log,0,
        "zmauth: examing query-string %V for field:%V", args, name);

    s = args->data;
    e = s+args->len;

    for (p=s; p<e; )
    {
        f1 = f2 = v1 = v2 = p;

        /* we are at the start of name=value */

        while (*p != '=' && p < e) {
            ++p;
        }

        f2=p;
        if (p == e) { break; }
        ++p;

        v1 = p; v2 = v1;
        if (p == e) { break; }

        while (*p != '&' && p < e) {
            ++p;
        }

        v2 = p;

        if (f2 == f1 + name->len && ngx_memcmp(f1,name->data,f2-f1) == 0)
        {
            value->data = v1;
            value->len = v2-v1;
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP,log,0,
                "zmauth: found value:%V against arg:%V in query-string:%V",
                value,name,args);
            f=1;
            break;
        }

        if (p == e) { break; }

        ++p;
    }

    return f;
}



/* extract a field from ZM_AUTH_TOKEN */
static ngx_flag_t ngx_field_from_zmauthtoken
    (ngx_log_t  *log,
     ngx_pool_t *pool,
     ngx_str_t  *authtoken,
     ngx_str_t  *field,
     ngx_str_t  *value
    )
{
    ngx_str_t    T2,t2;
    u_char      *p,*s,*e;
    ngx_uint_t   t;
    ngx_flag_t   f;
    ngx_str_t    F,V;
    ngx_uint_t   i,j,l;

    s=authtoken->data;
    e=s+authtoken->len;

    p=s;

    for (p=s,t=0,f=0;p<e && f==0;++p) {
        if(*p == '_') {
            if (t == 1) {
                T2.data=p+1;
                T2.len=e-T2.data;
                f=1;
            } else {
                ++t;
            }
        }
    }

    if (f==0) {
        ngx_log_error(NGX_LOG_INFO,log,0,
            "zmauth: auth-token:%V does not contain 3 fields",
            authtoken);

        return 0;
    }

    /* hex-decode T2 to t2 */

    if (T2.len % 2 != 0) {
        ngx_log_error(NGX_LOG_INFO,log,0,
            "zmauth: auth-token(#2):%V is invalid hex",
            &T2);

        return 0;
    }

    t2.len = T2.len/2;
    t2.data = ngx_palloc(pool,t2.len);

    if (t2.data == NULL) {
        /* nomem */
        return 0;
    }

    for(i=0,j=0; i<T2.len; i=i+2,j=j+1) {
        if (T2.data[i] >= '0' && T2.data[i] <= '9') {
            t2.data[j] = T2.data[i]-'0';
        } else {
            t2.data[j] = 10 + tolower(T2.data[i]) - 'a';
        }
        t2.data[j] <<= 4;
        if (T2.data[i+1] >= '0' && T2.data[i+1] <= '9') {
            t2.data[j] += (T2.data[i+1]-'0');
        } else {
            t2.data[j] += (10 + tolower(T2.data[i+1]) - 'a');
        }
    }

    /* t2 now contains the entire decoded portion #2 of the auth token */

    ngx_log_error(NGX_LOG_DEBUG,log,0,
        "zmauth: decoded(auth-token(#2)): %V",
        &t2);

    /* now we need to search for the named field 
       the decoded portion of the authtoken(#2) looks like
       field=len:value;field=len:value;...
     */

    s=t2.data;
    e=s+t2.len;
    f=0;
    p=s;

    while(p<e) {
        F.data=p;
        while(p<e && *p!='=') {
            ++p;
        }
        if(p==e) { break; }
        F.len=p-F.data;
        l=0;
        ++p;    // consume =
        while(p<e && (*p >= '0' && *p <= '9')) {
            l = (l * 10) + (*p-'0');
            ++p;
        }
        if(p==e) { break; }
        if(*p!=':') { break; }
        ++p;    // consume :
        V.data=p;
        while(p<e && p<V.data+l) {
            ++p;
        }
        if (p!=V.data+l) { break; }
        V.len=l;

        if(F.len == field->len &&
           ngx_memcmp(field->data,F.data,F.len) == 0) {
            f=1;
            *value=V;
            ngx_log_error(NGX_LOG_DEBUG,log,0,
                "zmauth: auth-token(field=%V,len=%d,value=%V)",
                &F,V.len,&V);
            break;
        }

        if(p<e) { ++p; }    // consume ;
    }

    return f;
}

static void *
ngx_http_upstream_zmauth_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_zmauth_srv_conf_t    *zscf;

    zscf = ngx_pcalloc(cf->pool,sizeof(ngx_http_upstream_zmauth_srv_conf_t));
    if (zscf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&zscf->rh,cf->pool,4,
        sizeof(ngx_http_upstream_zmauth_routehandler_t)) != NGX_OK) {
        return NULL;
    }

    zscf->rhtimeout = NGX_CONF_UNSET_MSEC;

    return zscf;
}

static char *
ngx_http_upstream_zmauth_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_upstream_zmauth_srv_conf_t    *prev = parent;
    ngx_http_upstream_zmauth_srv_conf_t    *conf = child;

    if(conf->rh.nelts == 0) {
        conf->rh = prev->rh;
    }

    conf->rhseed = prev->rhseed = 0;
    ngx_conf_merge_msec_value(conf->rhtimeout,prev->rhtimeout,5000);

    return NGX_CONF_OK;
}

static char *
ngx_http_upstream_zmroute(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_zmauth_srv_conf_t             *zscf = conf;
    ngx_http_upstream_zmauth_routehandler_t         *rhp;
    ngx_url_t                                        u;
    ngx_uint_t                                       i;

    /* parse each url specified against zmroutehandlers */
    for(i=1; i<cf->args->nelts; ++i)
    {
        rhp = ngx_array_push(&zscf->rh);
        if (rhp == NULL) {
            return NGX_CONF_ERROR;
        }
        rhp->peer = NULL;
        rhp->hh.len = sizeof("localhost")-1;
        rhp->hh.data = (u_char *)"localhost";
        rhp->uri.len = sizeof("/")-1;
        rhp->uri.data = (u_char *)"/";

        ngx_memzero(&u,sizeof(ngx_url_t));
        u.url = ((ngx_str_t*)cf->args->elts)[i];
        u.default_port = 80;
        u.uri_part = 1;
        u.one_addr = 1;

        if (ngx_parse_url(cf->pool,&u) != NGX_OK) {
            if (u.err) {
                ngx_conf_log_error(NGX_LOG_EMERG,cf,0,
                    "%s in zmroutehandlers \"%V\"",u.err,&u.url);
            }
            continue;
        }

        rhp->peer = u.addrs;
        rhp->hh = u.host;
        rhp->uri = u.uri;

        if (rhp->uri.len == 0) {
            rhp->uri.len = sizeof("/")-1;
            rhp->uri.data = (u_char*)"/";
        }
    }

    if (zscf->rh.nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG,cf,0,
            "zero valid zmauth route handlers");
        return NGX_CONF_ERROR;
    }

    zscf->rhseed = 0;

    return NGX_CONF_OK;
}

static ngx_flag_t elect_routehandler
(ngx_http_upstream_zmauth_ctx_t *ctx, ngx_http_upstream_zmauth_srv_conf_t *zscf)
{
    ngx_flag_t e;

    if (zscf->rh.nelts == 0) {
        e=0;
    } else if (ctx->tries == 0) {
        ctx->seed = zscf->rhseed;
        zscf->rhseed = (zscf->rhseed+1)%zscf->rh.nelts;
        ctx->tries ++;
        e=1;
        ctx->rh = ((ngx_http_upstream_zmauth_routehandler_t*)zscf->rh.elts) + ctx->seed;
    } else {
        if (ctx->tries >= zscf->rh.nelts) {
            e=0;
        } else {
            ctx->seed = (ctx->seed + 1) % zscf->rh.nelts;
            ctx->tries ++;
            e=1;
            ctx->rh = ((ngx_http_upstream_zmauth_routehandler_t*)zscf->rh.elts) + ctx->seed;
        }
    }

    return e;
}

/* free all context (by transition, all data-structures pertinent to route lookup
   also set module context slot to null to avoid double free
 */
static void zmauth_dispose_context(ngx_http_request_t *r)
{
    ngx_http_upstream_zmauth_ctx_t      *ctx;
    ngx_pool_t                          *pool;

    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    if (ctx != NULL) {
        pool = ctx->pool;
        ngx_destroy_pool(pool);
        ngx_http_set_ctx(r,NULL,ngx_http_upstream_zmauth_module);
    }
}

static void zmauth_error(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP,r->connection->log,0,
        "zmauth:error while proxying for zimbra, failing HTTP request");
    ngx_http_finalize_request(r,NGX_HTTP_INTERNAL_SERVER_ERROR);
}

/* examine the request uri for zimbra REST patterns
   currently supported patterns -

   /home/user/content
   /home/~/content
   /home/~user/content
   /service/home/user/content
   /service/home/~/content
   /service/home/~user/content

   return true(1) if indeed the request URI matches a REST pattern
   also fill in usr with the correct usr if so

   usr is blanked out before processing begins
   refer ZimbraServer/docs/rest.txt for details
 */
static ngx_flag_t zmauth_check_rest(ngx_http_request_t *r,void **extra)
{
    ngx_flag_t      f;
    u_char         *p;
    ngx_log_t      *log;
    ngx_pool_t     *pool;
    ngx_str_t       ausr, *usr;

    f = 0;
    pool = r->pool;
    log = r->connection->log;

    ausr.data = (u_char*)"";
    ausr.len = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP,log,0,
        "zmauth: examining uri:%V for REST", &r->uri);

    if (r->uri.len >= sizeof("/home/~/")-1 && 
       ngx_memcmp(r->uri.data,"/home/~/",sizeof("/home/~/")-1) == 0)
    {
        f=0;    /* for /home/~/ route will be discovered from the zm_auth_token */
    }
    else if (r->uri.len >= sizeof("/home/~")-1 && 
       ngx_memcmp(r->uri.data,"/home/~",sizeof("/home/~")-1) == 0)
    {
        ausr.data = r->uri.data+(sizeof("/home/~")-1);
        for(p=ausr.data;p<r->uri.data+r->uri.len;++p) {
            if (*p == '/') {
                f=1; break;
            }
        }
        ausr.len = p-ausr.data;
    }
    else if (r->uri.len >= sizeof("/home/")-1 && 
       ngx_memcmp(r->uri.data,"/home/",sizeof("/home/")-1) == 0)
    {
        ausr.data = r->uri.data+(sizeof("/home/")-1);
        for(p=ausr.data;p<r->uri.data+r->uri.len;++p) {
            if (*p == '/') {
                f=1; break;
            }
        }
        ausr.len = p-ausr.data;
    }
    else if (r->uri.len >= sizeof("/service/home/~/")-1 && 
       ngx_memcmp(r->uri.data,"/service/home/~/",sizeof("/service/home/~/")-1) == 0)
    {
        f=0;    /* for /service/home/~/ route will be discovered from the zm_auth_token */
    }
    else if (r->uri.len >= sizeof("/service/home/~")-1 && 
       ngx_memcmp(r->uri.data,"/service/home/~",sizeof("/service/home/~")-1) == 0)
    {
        ausr.data = r->uri.data+(sizeof("/service/home/~")-1);
        for(p=ausr.data;p<r->uri.data+r->uri.len;++p) {
            if (*p == '/') {
                f=1; break;
            }
        }
        ausr.len = p-ausr.data;
    }
    else if (r->uri.len >= sizeof("/service/home/")-1 && 
       ngx_memcmp(r->uri.data,"/service/home/",sizeof("/service/home/")-1) == 0)
    {
        ausr.data = r->uri.data+(sizeof("/service/home/")-1);
        for(p=ausr.data;p<r->uri.data+r->uri.len;++p) {
            if (*p == '/') {
                f=1; break;
            }
        }
        ausr.len = p-ausr.data;
    }

    if (f) {
        if (ausr.len == 0) { f = 0; }
    }

    if (f) {
        usr = ngx_palloc(pool,sizeof(ngx_str_t));
        if (usr == NULL) {
            f=0;
        } else {
            *usr = ausr;
            *extra = usr;
        }
    }

    if (f) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP,log,0,
            "uri:%V matched a REST pattern, user:%V", &r->uri, &ausr);
    }

    return f;
}

static ngx_flag_t zmauth_check_activesync(ngx_http_request_t *r,void **extra)
{
    ngx_log_t           *log;
    ngx_pool_t          *pool;
    ngx_str_t            authval,cred64,cred,credusr,*usr;
    u_char              *p;
    ngx_flag_t           rc;
    ngx_str_t            userArg = ngx_string("User");

    rc = 0;
    log = r->connection->log;
    pool = r->pool;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP,log,0,
        "zmauth: examining uri:%V for ActiveSync", &r->uri);

    if (r->uri.len >= sizeof("/Microsoft-Server-ActiveSync")-1 &&
        ngx_memcmp(r->uri.data,"/Microsoft-Server-ActiveSync",sizeof("/Microsoft-Server-ActiveSync")-1)==0)
    {
        if (r->headers_in.authorization != NULL &&
            r->headers_in.authorization->value.data != NULL)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP,log,0,
                "ActiveSync: Found RFC 2617 authorization header: %V",
                &r->headers_in.authorization->value);
            authval = r->headers_in.authorization->value;
            if (authval.len >= sizeof("Basic ")-1 &&
                ngx_memcmp(authval.data,"Basic ",sizeof("Basic ")-1) == 0) {
                cred64 = authval;
                cred64.data += (sizeof("Basic ")-1);
                cred64.len -= (sizeof("Basic ")-1);
                cred.len = ngx_base64_decoded_length(cred64.len);
                cred.data = ngx_palloc(pool,cred.len);
                if (cred.data != NULL)
                {
                    if(ngx_decode_base64(&cred,&cred64) == NGX_OK)
                    {
                        ngx_log_debug1(NGX_LOG_DEBUG_HTTP,log,0,
                            "ActiveSync: found auth basic credentials: %V",
                            &cred);

                /* (RFC 2617) 

                    basic-credentials = base64-user-pass
                    base64-user-pass  = <base64 [4] encoding of user-pass,
                                         except not limited to 76 char/line>
                    user-pass   = userid ":" password
                    userid      = *<TEXT excluding ":">
                    password    = *TEXT
                 */

                        credusr.data = cred.data;
                        p = cred.data;
                        while (p<cred.data+cred.len && *p != ':') { ++p; }
                        credusr.len = p-cred.data;
                        usr = ngx_palloc(pool,sizeof(ngx_str_t));

                        if (usr != NULL)
                        {
                            zmauth_translate_activesync_usr(pool,&credusr,usr);
                            ngx_log_debug2(NGX_LOG_DEBUG_HTTP,log,0,
                                "ActiveSync: user:%V translated to user:%V for route discovery",
                                &credusr,usr);

                            *extra = usr;
                            rc = 1;
                        }
                    }
                }
            }

        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP,log,0, 
                "ActiveSync: No authorization header, examine args: [%V]",
                &r->args);

            usr = ngx_palloc(pool,sizeof(ngx_str_t));
            if(usr != NULL && 
               zmauth_find_arg(&r->args,&userArg,usr) != 0
              )
            {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP,log,0,
                    "ActiveSync: fallback to HTTP argument User1:%V",
                    usr);

                *extra = usr;
                rc = 1;
            }
        }
    }

    return rc;
}

static ngx_flag_t zmauth_check_caldav(ngx_http_request_t *r,void **extra)
{
    ngx_log_t           *log;
    ngx_pool_t          *pool;
    ngx_str_t            *usr,ausr=ngx_string("");
    u_char              *p;
    ngx_flag_t           f;

    f = 0;
    log = r->connection->log;
    pool = r->pool;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP,log,0,
        "zmauth: examining uri:%V for caldav", &r->uri);

    if (r->uri.len >= sizeof("/dav/")-1 &&
        ngx_memcmp(r->uri.data,"/dav/",sizeof("/dav/")-1)==0)
    {
        ausr.data = r->uri.data+(sizeof("/dav/")-1);
        for(p=ausr.data;p<r->uri.data+r->uri.len;++p) {
            if (*p == '/') {
                f=1;
                break;
            }
        }
        ausr.len = p-ausr.data;
    }
    else if (r->uri.len >= sizeof("/principals/users/")-1 &&
        ngx_memcmp(r->uri.data,"/principals/users/",sizeof("/principals/users/")-1)==0)
    {
        ausr.data = r->uri.data+(sizeof("/principals/users/")-1);
        for(p=ausr.data;p<r->uri.data+r->uri.len;++p) {
            if (*p == '/') {
                f=1;
                break;
            }
        }
        ausr.len = p-ausr.data;
    }

    if (f) {
        if (ausr.len == 0) { f=0; }
    }

    if (f) {
        usr = ngx_palloc(pool,sizeof(ngx_str_t));
        if (usr == NULL) {
            f=0;
        } else {
            *usr = ausr;
            *extra = usr;
        }
    }

    if (f) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP,log,0,
            "uri:%V matched caldav, user:%V", &r->uri,&ausr);
    }

    return f;
}

/* examine request cookies for ZM_AUTH_TOKEN and extract route if so */
static ngx_flag_t zmauth_check_authtoken(ngx_http_request_t *r, void **extra)
{
    ngx_pool_t             *pool;
    ngx_log_t              *log;
    ngx_str_t               token,id,*pid;
    ngx_flag_t              f;

    pool = r->pool;
    log = r->connection->log;

    ngx_log_debug0 (NGX_LOG_DEBUG_HTTP, log, 0,
        "zmauth: search for ZM_AUTH_TOKEN");

    /* look for auth token in the request cookie(s) */
    f = ngx_get_cookie_value(
            log,
            (ngx_table_elt_t **)r->headers_in.cookies.elts,
            r->headers_in.cookies.nelts,
            &NGX_ZMAUTHTOKEN,
            &token
            );

    if (!f) {
        /* if not found, then look in the zauthtoken= query string arg */
        f = ngx_get_query_string_arg (log,&r->args,&NGX_ZAUTHTOKEN,&token);
    }

    if (f) {
        ngx_log_debug1 (NGX_LOG_DEBUG_HTTP, log, 0,
            "zmauth: found ZM_AUTH_TOKEN:%V",
            &token);

        f = ngx_field_from_zmauthtoken (
                log,
                pool,
                &token,
                &NGX_ZMAUTHTOKEN_ID,
                &id
            );

        if (f) {
            ngx_log_debug1 (NGX_LOG_DEBUG_HTTP, log, 0,
                "zmauth: got id:%V from ZM_AUTH_TOKEN",
                &id);
            if (id.len>0) {
                pid = ngx_palloc(pool,sizeof(ngx_str_t));
                if (pid == NULL) {
                    f=0;
                } else {
                    pid->data = ngx_pstrdup(pool,&id); /* TODO: shallowcopy? */
                    if (pid->data == NULL) {
                        f=0;
                    } else {
                        pid->len = id.len;
                        *((ngx_str_t**)extra) = pid;
                    }
                }
            } else {
                f=0;
            }
        } else {
            ngx_log_debug0 (NGX_LOG_DEBUG_HTTP, log, 0,
                "zmauth: no id in ZM_AUTH_TOKEN"
                );
        }

    } else {
        ngx_log_debug1 (NGX_LOG_DEBUG_HTTP, log, 0,
            "zmauth: no ZM_AUTH_TOKEN",
            &token);
    }

    return f;
}

static zmroutetype_t zmauth_check_uri(ngx_http_request_t *r, void **extra)
{
    zmroutetype_t       rtype;

    rtype = zmroutetype_fallback;
    if (zmauth_check_rest(r,extra)) {
        rtype = zmroutetype_rest;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,r->connection->log,0,
            "zmauth: routing for REST");
    } else if (zmauth_check_activesync(r,extra)) {
        rtype = zmroutetype_activesync;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,r->connection->log,0,
            "zmauth: routing for ActiveSync");
    } else if (zmauth_check_caldav(r,extra)) {
        rtype = zmroutetype_caldav;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,r->connection->log,0,
            "zmauth: routing for caldav");
    } else if (zmauth_check_authtoken(r,extra)) {
        rtype = zmroutetype_authtoken;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,r->connection->log,0,
            "zmauth: routing by ZM_AUTH_TOKEN");
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,r->connection->log,0,
            "zmauth: routing by iphash");
    }
    return rtype;
}

/* translate an activesync user rep to zimbra user rep
   domain\user becomes user@domain
   others remain identical
 */
static void zmauth_translate_activesync_usr
    (ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *tgt)
{
    u_char      *p,*q;

    tgt->data = ngx_pstrdup(pool,src);
    if (tgt->data == NULL) {
        *tgt = *src;
        return;
    }

    tgt->len = src->len;
    p = src->data;

    while (p<src->data + src->len) {
        if (*p == '\\') {
            q = ngx_cpymem(tgt->data,p+1,src->len-(p-src->data)-1);
            *q++ = '@';
            q = ngx_cpymem(q,src->data,p-src->data);
            break;
        }
        ++p;
    }

    return;
}

/* extract an argument from query string args of the form n1=v1&n2=v2&n3=v3 */
static ngx_flag_t zmauth_find_arg
    (/* const */ ngx_str_t *args, /* const */ ngx_str_t *arg, ngx_str_t *val)
{
    ngx_flag_t          rc;
    u_char             *p,*s,*e;
    ngx_str_t           n,v;

    rc = 0;
    s = args->data;
    e = s + args->len;
    p = s;

    while (p < e)
    {
        n.data =p;
        while (p < e && *p != '=') {
            ++p;
        }
        if (p == e) { break; }
        n.len = p-n.data;

        ++p;
        v.data = p;

        while (p < e && *p != '&') {
            ++p;
        }
        if (p == e) { break; }

        v.len = p-v.data;
        ++p;

        if (n.len == arg->len && 
            ngx_memcmp(n.data,arg->data,n.len) == 0) {
            *val = v;
            rc = 1;
            break;
        }
    }

    return rc;
}

/* cache the username mapping as reported by lookup servlet (Auth-User) */
static void mcr_cachealias
    (ngx_http_request_t *r, ngx_str_t usr, ngx_str_t qusr)
{
    mc_work_t                                w;
    ngx_http_upstream_zmauth_ctx_t          *ctx;
    ngx_http_upstream_zmauth_peer_data_t    *zmp;
    ngx_memcache_conf_t                     *mcf;
    ngx_str_t                                vhost,k,pdu;
    size_t                                   l,ttl,ttld,qusrd;
    u_char                                  *p;
    ngx_pool_t                              *pool = NULL;
    ngx_log_t                               *log;

    ctx = ngx_http_get_module_ctx(r,ngx_http_upstream_zmauth_module);
    zmp = ctx->zmp;
    mcf = ngx_memcache_get_conf();

    log = ngx_cycle->log;
    vhost = r->headers_in.host->value;

    if (zmp->zmroutetype == zmroutetype_authtoken) {
        /* no aliases are supported for authtoken:id */
        goto done;
    }

    if (usr.len == qusr.len &&
        ngx_memcmp(usr.data,qusr.data,usr.len) == 0
       ) {
        /* if the original user(usr) is same as the new user (qusr)
           then there is no need to cache the alias mapping */
        goto done;
    }

    pool = ngx_create_pool(1024,ngx_cycle->log);

    if (pool == NULL) {
        goto done;
    }

    k = ngx_memcache_get_http_alias_key(pool, log, usr, vhost);

    if (k.len == 0) {   /* NOMEM */
        goto err;
    }

    ttl = mcf->ttl/1000;
    if (mcf->ttl%1000 != 0) {
        ++ttl;
    }
    ttld = serialize_number(NULL,ttl);
    qusrd = serialize_number(NULL,qusr.len);

    l = sizeof("add ")-1 +
        k.len +
        sizeof(" ")-1 +
        sizeof("0 ")-1 +
        ttld +
        sizeof(" ")-1 +
        qusrd +
        sizeof(CRLF)-1 +
        qusr.len +
        sizeof(CRLF)-1;

    pdu.data = ngx_palloc(pool,l);

    if (pdu.data == NULL) {   /* NOMEM */
        goto err;
    }

    p = pdu.data;
    p = ngx_cpymem(p, "add ", sizeof("add ")-1);
    p = ngx_cpymem(p, k.data, k.len);
    *p++ = ' ';
    *p++ = '0';
    *p++ = ' ';
    p += serialize_number(p, ttl);
    *p++ = ' ';
    p += serialize_number(p, qusr.len);
    *p++ = CR;
    *p++ = LF;
    p = ngx_cpymem(p, qusr.data, qusr.len);
    *p++ = CR;
    *p++ = LF;

    pdu.len = p-pdu.data;

    w.ctx = pool;
    w.request_code = mcreq_add;
    w.response_code = mcres_unknown;
    w.on_success = mch_destroy_http_pool;
    w.on_failure = mch_destroy_http_pool;

    ngx_memcache_post(&w,k,pdu,NULL,log);
    return;

err:
    if (pool != NULL) {
        ngx_destroy_pool(pool);
    }

done:
    return;
}

/* cache the http route of a user, and destroy the context pool afterwards */
static void mcr_cacheroute
    (ngx_http_request_t *r, ngx_str_t usr, ngx_str_t route)
{
    mc_work_t                                w;
    ngx_http_upstream_zmauth_ctx_t          *ctx;
    ngx_http_upstream_zmauth_peer_data_t    *zmp;
    ngx_memcache_conf_t                     *mcf;
    size_t                                   l,ttl,ttld,routed;
    u_char                                  *p;
    ngx_pool_t                              *pool = NULL;
    ngx_log_t                               *log;
    ngx_str_t                                k,pdu;

    ctx = ngx_http_get_module_ctx(r, ngx_http_upstream_zmauth_module);
    zmp = ctx->zmp;
    mcf = ngx_memcache_get_conf();

    log = ngx_cycle->log;

    pool = ngx_create_pool (1024, log);
    if (pool == NULL) {
        goto done;
    }

    if (zmp->zmroutetype == zmroutetype_authtoken) {
        k = ngx_memcache_get_http_id_route_key(pool, log, usr);
    } else {
        k = ngx_memcache_get_http_route_key(pool, log, usr);
    }

    if (k.len == 0) {   /* NOMEM */
        goto err;
    }

    ttl = mcf->ttl/1000;
    if (mcf->ttl%1000 != 0) {
        ++ttl;
    }
    ttld = serialize_number(NULL,ttl);
    routed = serialize_number(NULL,route.len);

    l = sizeof("add ") - 1 +
        k.len +
        sizeof(" ") - 1 +
        sizeof("0 ") - 1 +
        ttld +
        sizeof(" ") - 1 +
        routed +
        sizeof(CRLF) - 1 +
        route.len +
        sizeof(CRLF) - 1;

    pdu.data = ngx_palloc(pool,l);

    if (pdu.data == NULL) {   /* NOMEM */
        goto err;
    }

    p = pdu.data;
    p = ngx_cpymem(p, "add ", sizeof("add ") - 1);
    p = ngx_cpymem(p, k.data, k.len);
    *p++ = ' ';
    *p++ = '0';
    *p++ = ' ';
    p += serialize_number(p, ttl);
    *p++ = ' ';
    p += serialize_number(p, route.len);
    *p++ = CR;
    *p++ = LF;
    p = ngx_cpymem(p, route.data, route.len);
    *p++ = CR;
    *p++ = LF;

    pdu.len = p - pdu.data;

    w.ctx = pool;
    w.request_code = mcreq_add;
    w.response_code = mcres_unknown;
    w.on_success = mch_destroy_http_pool;
    w.on_failure = mch_destroy_http_pool;

    ngx_memcache_post(&w, k, pdu, NULL, log);
    return;

err:
    if (pool != NULL) {
        ngx_destroy_pool(pool);
    }
done:
    return;
}

static void mch_destroy_http_pool (mc_work_t *w)
{
    ngx_pool_t  *pool = (ngx_pool_t *)w->ctx;
    ngx_destroy_pool(pool);
}



/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_mail.h>
#include <ngx_mail_auth_http_module.h>
#include <ngx_memcache.h>
#include <ngx_serialize.h>

extern ngx_module_t ngx_memcache_module;

/* Email proxy handlers */
static void ngx_mail_routelookup_request_handler
    (ngx_mail_session_t *s, ngx_mail_auth_http_ctx_t *ctx);
static void ngx_mail_auth_http_write_handler(ngx_event_t *wev);
static void ngx_mail_auth_http_read_handler(ngx_event_t *rev);
static void ngx_mail_auth_http_ignore_status_line(ngx_mail_session_t *s, 
    ngx_mail_auth_http_ctx_t *ctx);
static void ngx_mail_auth_http_process_headers(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx);
static void ngx_mail_routelookup_connect_handler(ngx_event_t *ev);
static void ngx_mail_auth_sleep_handler(ngx_event_t *rev);
static ngx_int_t ngx_mail_auth_http_parse_header_line(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx);
static void ngx_mail_auth_http_block_read(ngx_event_t *rev);
static void ngx_mail_auth_http_dummy_handler(ngx_event_t *ev);
static ngx_buf_t * ngx_mail_auth_http_create_request(ngx_mail_session_t *s,
    ngx_pool_t *pool, ngx_mail_auth_http_conf_t *ahcf, ngx_mail_auth_http_ctx_t *ctx);
static ngx_int_t ngx_mail_auth_http_escape(ngx_pool_t *pool, ngx_str_t *text,
    ngx_str_t *escaped);

/* Configuration management routines */
static void *ngx_mail_auth_http_create_conf(ngx_conf_t *cf);
static char *ngx_mail_auth_http_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_mail_auth_http(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_mail_auth_http_header(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* HTTP Routing Lookup Handler election routines */
static void elect_auth_server_RR
    (ngx_mail_auth_http_ctx_t *ctx, ngx_mail_auth_http_conf_t *cnf);
static void reelect_auth_server
    (ngx_mail_auth_http_ctx_t *ctx, ngx_mail_auth_http_conf_t *cnf);
static inline ngx_addr_t *elected_peer
    (ngx_mail_auth_http_ctx_t *ctx, ngx_mail_auth_http_conf_t *cnf);
static inline ngx_str_t elected_uri
    (ngx_mail_auth_http_ctx_t *ctx, ngx_mail_auth_http_conf_t *cnf);
static inline ngx_str_t elected_host_header
    (ngx_mail_auth_http_ctx_t *ctx, ngx_mail_auth_http_conf_t *cnf);

/* Route discovery and storage routines */
static void ngx_mail_routelookup_cache
    (ngx_mail_session_t *s, ngx_mail_auth_http_ctx_t *ctx);
static void ngx_mail_routelookup
    (ngx_mail_session_t *s, ngx_mail_auth_http_ctx_t *ctx);
static void ngx_mail_aliaslookup_cache
    (ngx_mail_session_t *s, ngx_mail_auth_http_ctx_t *ctx);
static void ngx_mail_initiateproxy
    (ngx_mail_session_t *s, ngx_mail_auth_http_ctx_t *ctx, ngx_str_t route);

/* Utility functions */
static ngx_flag_t is_login_qualified (ngx_str_t l);

/* memcache operation callback handlers */
static void mch_peerlookup (mc_work_t *w);
static void mch_initiateproxy (mc_work_t *w);
static void mch_freepool (mc_work_t *w);
static void mch_alias_route_void (mc_work_t *w);
static void mch_alias_routelookup (mc_work_t *w);
static void mch_noalias_routelookup (mc_work_t *w);

/* route and alias caching routines (upper and bottom halves) */
static ngx_flag_t ngx_mail_routecache_uh (
    ngx_mail_session_t          *s,         /* mail session */
    ngx_str_t                    user,      /* user name */
    ngx_addr_t                  *route,     /* route */
    ngx_pool_t                  *pool,      /* "the" pool */
    ngx_log_t                   *log,       /* log */
    mc_work_t                   *wp,        /* cache request pt */
    ngx_str_t                   *kp,        /* cache key pt */
    ngx_str_t                   *pdup       /* cache protocol pdu pt */
);
static void ngx_mail_routecache_bh
(
    mc_work_t       *w,
    ngx_str_t       *k,
    ngx_str_t       *pdu,
    ngx_log_t       *log
);
static ngx_flag_t ngx_mail_aliascache_uh
(
    ngx_mail_session_t  *s,
    ngx_str_t            user,
    ngx_str_t            alias,
    ngx_pool_t          *pool,
    ngx_log_t           *log,
    mc_work_t           *wp,
    ngx_str_t           *kp,
    ngx_str_t           *pdup
);
static void ngx_mail_aliascache_bh
(
    mc_work_t       *w,
    ngx_str_t       *k,
    ngx_str_t       *pdu,
    ngx_log_t       *log
);


static ngx_command_t  ngx_mail_auth_http_commands[] = {

    { ngx_string("auth_http"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_mail_auth_http,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_http_timeout"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_auth_http_conf_t, timeout),
      NULL },

    { ngx_string("auth_http_timeout_cache"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_auth_http_conf_t, timeout_cache),
      NULL },

    { ngx_string("auth_http_header"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE2,
      ngx_mail_auth_http_header,
      NGX_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_auth_http_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_auth_http_create_conf,        /* create server configuration */
    ngx_mail_auth_http_merge_conf          /* merge server configuration */
};


ngx_module_t  ngx_mail_auth_http_module = {
    NGX_MODULE_V1,
    &ngx_mail_auth_http_module_ctx,        /* module context */
    ngx_mail_auth_http_commands,           /* module directives */
    NGX_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_str_t   ngx_mail_proto [] = {
    ngx_string("pop3"),
    ngx_string("imap"),
    ngx_string("smtp")
};
static char       *ngx_mail_auth_http_protocol[] = { "pop3", "imap", "smtp" };
static ngx_str_t   ngx_mail_auth_http_method[] = {
    ngx_string("passwd"),           /* NGX_MAIL_AUTH_PASSWD */
    ngx_string("plain"),            /* NGX_MAIL_AUTH_PLAIN */
    ngx_string("plain"),            /* NGX_MAIL_AUTH_PLAIN_IR */
    ngx_string("login"),            /* NGX_MAIL_AUTH_LOGIN */
    ngx_string("login"),            /* NGX_MAIL_AUTH_LOGIN_USERNAME */
    ngx_string("apop"),             /* NGX_MAIL_AUTH_APOP */
    ngx_string("cram-md5"),         /* NGX_MAIL_AUTH_CRAM_MD5 */
    ngx_string("gssapi"),           /* NGX_MAIL_AUTH_GSSAPI */
    ngx_string("gssapi"),           /* NGX_MAIL_AUTH_GSSAPI_IR */
    ngx_string("none")              /* NOT TAKE AUTH */
};

static ngx_str_t   ngx_mail_smtp_errcode = ngx_string("535 5.7.0");
static const char *ngx_auth_http_password = "_password_"; /* the password place holder for password */
static size_t ngx_auth_http_password_len = sizeof("_password_") - 1;

/* BEGIN ROUTE DISCOVERY
 *
 * Initiate the process of discovering the upstream server
 * First look in memcache
 * On failure, fetch route from lookup servlet (and then cache it)
 *
 */
void
ngx_mail_auth_http_init(ngx_mail_session_t *s)
{
    ngx_pool_t                 *pool;
    ngx_mail_auth_http_ctx_t   *ctx;
    ngx_mail_core_srv_conf_t   *cscf;

    s->connection->log->action = "in http auth state";

    /* Per-worker memcache initialization (if necessary) */
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    /* create pool and module context */
    pool = ngx_create_pool(2048, s->connection->log);
    if (pool == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_mail_auth_http_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ctx->pool = pool;
    ngx_mail_set_ctx(s, ctx, ngx_mail_auth_http_module);

    s->connection->read->handler = ngx_mail_auth_http_block_read;
    s->qlogin = s->login;

    /* attempt to fetch the cached alias, if any */
    if (s->vlogin) {
        /* alias has already been looked up */
        ngx_mail_routelookup_cache (s, ctx);
    } else {
        ngx_mail_aliaslookup_cache (s, ctx);
    }
}

/*
 * remove route and alias cache from memcached after auth failure
 */
void
ngx_mail_auth_http_void(ngx_mail_session_t *s)
{
    ngx_pool_t                 *pool;
    ngx_mail_auth_http_ctx_t   *ctx;
    mc_work_t                   w;
    ngx_str_t                   pdu;
    ngx_log_t                  *log;
    size_t                      l;
    u_char                     *p;

    if (s->key_alias.len == 0)
        return;
    pool = ngx_create_pool(4096, s->connection->log);
    if (pool == NULL)
        return;
    ctx = ngx_pcalloc(pool, sizeof(ngx_mail_auth_http_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        return;
    }

    ctx->pool = pool;
    ngx_mail_set_ctx(s, ctx, ngx_mail_auth_http_module);

    log = ngx_cycle->log;

    w.ctx = ctx;
    w.request_code = mcreq_delete;
    w.response_code = mcres_unknown;
    w.on_success = mch_alias_route_void;
    w.on_failure = mch_alias_route_void;

    ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, log, 0,
        "delete cached alias, user:%V, key:%V", &s->login, &s->key_alias);

    l = sizeof("delete ") - 1 + s->key_alias.len + sizeof(CRLF) - 1;

    pdu.data = ngx_palloc(pool, l);
    if (pdu.data == NULL) {
        ngx_destroy_pool (pool);
        return;
    }

    p = pdu.data;
    p = ngx_cpymem(p,"delete ", sizeof("delete ") - 1);
    p = ngx_cpymem(p, s->key_alias.data, s->key_alias.len);
    *p++ = CR;
    *p++ = LF;
    pdu.len = p - pdu.data;
    ngx_memcache_post(&w, s->key_alias, pdu, /* pool */ NULL, log);
 
    ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, log, 0, 
        "delete cached route, login:%V, key:%V", &s->login, &s->key_route);

    l = sizeof("delete ") - 1 + s->key_route.len + sizeof(CRLF) - 1;

    pdu.data = ngx_palloc (pool, l);
    if (pdu.data == NULL) {
        ctx->state++;
        return;
    }

    p = pdu.data;
    p = ngx_cpymem (p, "delete ", sizeof("delete ") - 1);
    p = ngx_cpymem (p, s->key_route.data, s->key_route.len);
    p = ngx_cpymem (p, CRLF, sizeof(CRLF) - 1);
    pdu.len = p - pdu.data;
    ngx_memcache_post (&w, s->key_route, pdu, /* pool */ NULL, log);
}

/* Initiate the proxy connection to upstream
   (route is made available - either from cache, or from servlet)
 */
static void ngx_mail_initiateproxy
    (ngx_mail_session_t *s, ngx_mail_auth_http_ctx_t *ctx, ngx_str_t route)
{
    ngx_addr_t     *peer;

    ngx_log_error (NGX_LOG_DEBUG, s->connection->log, 0,
        "initiating proxy to discovered route:%V for login:%V",
        &route, &s->login);

    if (s->usedauth && s->qualifydauth) {
        /* if auth-plain style is being used, and if the authc was
           the same as authz, then in this case, we should consider 
           any name translation on authz to affect authc as well
         */
        s->dusr = s->login;
    }

    /* note how we use s->connection->pool instead of ctx->pool
       that is because upstream proxying will use the connection pool, and 
       not the context pool
       on the other hand, we need to get rid of the context pool when the 
       scope of this module ends
     */
    peer = deserialize_peer_ipv4 (route.data, route.len, s->connection->pool);

    ngx_destroy_pool (ctx->pool);
    ngx_mail_proxy_init (s, peer);
}

/* look-up a user's alias based on login name and IP address */
static void ngx_mail_aliaslookup_cache
    (ngx_mail_session_t *s, ngx_mail_auth_http_ctx_t *ctx)
{
    mc_work_t           w;
    ngx_str_t           pdu;
    ngx_log_t          *log;
    ngx_pool_t         *pool;
    size_t              l;
    u_char             *p;
    ngx_str_t           proxyip;

    log = ngx_cycle->log;
    pool = ctx->pool;

    w.ctx = s;
    w.request_code = mcreq_get;
    w.response_code = mcres_unknown;
    w.on_success = mch_alias_routelookup;
    w.on_failure = mch_noalias_routelookup;

    /* GSSAPI workaround: don't use cached aliases for GSSAPI */
    if (s->auth_method == NGX_MAIL_AUTH_GSSAPI) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL,log,0,
            "ignoring any cached alias for auth=gssapi");
        w.on_failure(&w);
        return;
    }

    /* first stringify the proxy-ip address */
    proxyip = ngx_mail_get_local_addr4 (pool,s->connection->fd);

    s->key_alias = ngx_memcache_get_alias_key(
            s->connection->pool,
            log,
            s->login,
            proxyip
        );

    if (s->key_alias.len == 0) {
        ngx_mail_routelookup_cache(s,ctx);  /* TODO: ?? bail out ?? */
        return;
    }

    ngx_log_debug2 (NGX_LOG_DEBUG_MAIL,log,0,
        "look-up cached alias, user:%V, key:%V", &s->login, &s->key_alias);

    l = sizeof("get ") - 1 + s->key_alias.len + sizeof(CRLF) - 1;

    pdu.data = ngx_palloc(pool,l);

    if (pdu.data == NULL) {
        ngx_mail_routelookup_cache(s,ctx);  /* TODO: ?? bail out ?? */
        return;
    }

    p = pdu.data;
    p = ngx_cpymem(p, "get ", sizeof("get ")-1);
    p = ngx_cpymem(p, s->key_alias.data, s->key_alias.len);
    *p++ = CR;
    *p++ = LF;

    pdu.len = p-pdu.data;

    ngx_memcache_post (&w, s->key_alias, pdu, /* pool */ NULL, log);
    return;
}

/* Fetch route information from memcache, else fall back to lookup servlet */
static void ngx_mail_routelookup_cache
    (ngx_mail_session_t *s, ngx_mail_auth_http_ctx_t *ctx)
{
    mc_work_t       w;
    ngx_str_t       pdu;
    size_t          l;
    ngx_log_t      *log;
    ngx_pool_t     *pool;
    u_char         *p;
    ngx_str_t       proxyip;
    ngx_mail_core_srv_conf_t        *cscf;
    ngx_memcache_conf_t     *mcf;

    log = ngx_cycle->log;
    pool = ctx->pool;
    cscf = ngx_mail_get_module_srv_conf(s,ngx_mail_core_module);
    mcf = (ngx_memcache_conf_t *)ngx_get_conf(ngx_cycle->conf_ctx,ngx_memcache_module);

    /* fill in the memcache work structure */
    w.ctx = s;
    w.request_code = mcreq_get;
    w.response_code = mcres_unknown;
    w.on_success = mch_initiateproxy;
    w.on_failure = mch_peerlookup;

    /* GSSAPI workaround: don't use cached routes for GSSAPI */
    if (s->auth_method == NGX_MAIL_AUTH_GSSAPI) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL,log,0,
            "ignoring any cached route for auth=gssapi");
        w.on_failure(&w);
        return;
    }

    /* first stringify the proxy-ip address */
    proxyip = ngx_mail_get_local_addr4 (pool,s->connection->fd);

    /* prepare the key for the cached route */
    s->key_route = ngx_memcache_get_route_key(
            s->connection->pool,
            log,
            ngx_mail_proto[s->protocol],
            s->qlogin,
            proxyip,
            is_login_qualified(s->qlogin),
            mcf->allow_unqualified
        );

    if (s->vlogin == 1 && !mcf->allow_unqualified &&
    		!is_login_qualified(s->qlogin)) {
    	ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, log, 0,
    			"skip cached route lookup for uncached alias, login:%V, key:%V",
    			&s->qlogin, &s->key_route);
        w.on_failure(&w);
        return;
    }

    ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, log, 0, 
        "look-up cached route, login:%V, key:%V",
        &s->qlogin, &s->key_route);

    l = sizeof("get ") - 1 + s->key_route.len + sizeof(CRLF) - 1;

    pdu.data = ngx_palloc (pool, l);

    if (pdu.data == NULL) {
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL,log,0,
            "no memory to fetch cached route");
        ngx_mail_routelookup (s, ctx);
        return;
    }

    p = pdu.data;
    p = ngx_cpymem (p,"get ", sizeof("get ") - 1);
    p = ngx_cpymem (p, s->key_route.data, s->key_route.len);
    p = ngx_cpymem (p, CRLF, sizeof(CRLF) - 1);
    pdu.len = p-pdu.data;

    ngx_memcache_post (&w, s->key_route, pdu, /* pool */ NULL, log);
    return;
}

/*  cache a user route (upper half)
    prepare the cache request work
    prepare the cache request pdu
    prepare the cache route key

    do NOT post the request on memcache
 */

static ngx_flag_t ngx_mail_routecache_uh (
    ngx_mail_session_t          *s,         /* mail session */
    ngx_str_t                    user,      /* user name */
    ngx_addr_t                  *route,     /* route */
    ngx_pool_t                  *pool,      /* "the" pool */
    ngx_log_t                   *log,       /* log */
    mc_work_t                   *wp,        /* cache request pt */
    ngx_str_t                   *kp,        /* cache key pt */
    ngx_str_t                   *pdup       /* cache protocol pdu pt */
)
{
    ngx_mail_core_srv_conf_t        *cscf;
    ngx_mail_auth_http_ctx_t        *ctx;
    ngx_memcache_conf_t             *mcf;
    ngx_str_t                        pdu;
    mc_work_t                        w;
    u_char                          *p;
    size_t                           l,rsiz,rnum,ttl,ttld;
    ngx_str_t                        proxyip;

    ctx     = ngx_mail_get_module_ctx (s, ngx_mail_auth_http_module);
    cscf    = ngx_mail_get_module_srv_conf (s, ngx_mail_core_module);
    mcf     = (ngx_memcache_conf_t *)
              ngx_get_conf (ngx_cycle->conf_ctx,ngx_memcache_module);

    /* set up the work-queue entry to be posted */
    w.ctx           = pool;
    w.request_code  = mcreq_add;
    w.response_code = mcres_unknown;
    w.on_success    = mch_freepool;
    w.on_failure    = mch_freepool;

    /* recompute route key because login may have changed due to an alias */
    proxyip = ngx_mail_get_local_addr4 (pool,s->connection->fd);

    /* prepare the key for the cached route */
    s->key_route = ngx_memcache_get_route_key(
            s->connection->pool,
            log,
            ngx_mail_proto[s->protocol],
            s->login,
            proxyip,
            is_login_qualified(s->login),
            mcf->allow_unqualified
        );

    ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, log, 0,
        "caching route, login:%V, key:%V", &user, &s->key_route);

    rsiz = serialize_peer_ipv4 (NULL,route);        // len(stringified route)
    rnum = serialize_number (NULL, rsiz);           // len(itoa(rsiz))
    ttl = mcf->ttl/1000;            // in seconds
    if (mcf->ttl%1000 != 0) {
        ++ttl;                                      // round up to nearest sec
    }
    ttld = serialize_number (NULL,ttl);

    /* pdu will look like
       add [POP3|IMAP|SMTP]:k 0 ttl rsiz CRLF route CRLF
     */
    l = sizeof("add ") - 1 +
        s->key_route.len +
        sizeof(" ") - 1 + sizeof("0 ") - 1 + ttld + sizeof(" ") - 1 +
        rnum + sizeof(CRLF) - 1 + rsiz + sizeof(CRLF) - 1;

    pdu.data = ngx_palloc(pool,l);

    if (pdu.data == NULL) {
        w.on_failure (&w);
        return 0;
    }

    p = pdu.data;
    p = ngx_cpymem(p, "add ", sizeof("add ") - 1);
    p = ngx_cpymem(p, s->key_route.data, s->key_route.len);
    *p++ = ' ';
    *p++ = '0';
    *p++ = ' ';
    p += serialize_number(p,ttl);
    *p++ = ' ';
    p += serialize_number(p,rsiz);
    *p++ = CR;
    *p++ = LF;
    p += serialize_peer_ipv4(p,route);
    *p++ = CR;
    *p++ = LF;
    pdu.len = p-pdu.data;

    *wp = w;
    *kp = s->key_route;
    *pdup = pdu;

    return 1;
}

/*  cache a user route (bottom half)
    post the request on memcache
 */
static void ngx_mail_routecache_bh
(
    mc_work_t       *w,
    ngx_str_t       *k,
    ngx_str_t       *pdu,
    ngx_log_t       *log
)
{
    ngx_memcache_post (w, *k, *pdu, NULL, log);
    return;
}

/*  cache a user alias (upper half)
    prepare the cache request work
    prepare the cache request pdu
    prepare the cache route key

    do NOT post the request on memcache
 */
static ngx_flag_t ngx_mail_aliascache_uh
(
    ngx_mail_session_t  *s,
    ngx_str_t            user,
    ngx_str_t            alias,
    ngx_pool_t          *pool,
    ngx_log_t           *log,
    mc_work_t           *wp,
    ngx_str_t           *kp,
    ngx_str_t           *pdup
)
{
    ngx_str_t                    pdu;
    mc_work_t                    w;
    size_t                       l,ttl,ttld,newl,newd;
    u_char                      *p;

    ngx_mail_auth_http_ctx_t    *ctx;
    ngx_mail_core_srv_conf_t    *cscf;
    ngx_memcache_conf_t         *mcf;

    ctx     = ngx_mail_get_module_ctx (s, ngx_mail_auth_http_module);
    cscf    = ngx_mail_get_module_srv_conf (s, ngx_mail_core_module);
    mcf     = (ngx_memcache_conf_t *)
              ngx_get_conf (ngx_cycle->conf_ctx,ngx_memcache_module);

    w.ctx           = pool;
    w.request_code  = mcreq_add;
    w.response_code = mcres_unknown;
    w.on_success    = mch_freepool;
    w.on_failure    = mch_freepool;

    if ((user.len == alias.len) &&
        (ngx_memcmp(user.data,alias.data,user.len)==0)
       )
    {
        /* no need to cache if user is same as alias */
        w.on_failure (&w);
        return 0;
    }

    if (s->key_alias.len == 0) {
        ngx_log_error (NGX_LOG_ERR,log,0, 
            "cannot cache user-alias: {%V,%V}", &user, &alias);
        w.on_failure (&w);
        return 0;
    }

    ttl = mcf->ttl/1000;
    if (mcf->ttl%1000 != 0) {
        ++ttl;
    }

    ttld = serialize_number(NULL,ttl);

    ngx_log_debug2 (NGX_LOG_DEBUG_MAIL,log,0, 
        "caching user-alias: {%V,%V}", &s->key_alias, &alias);

    newl = alias.len;
    newd = serialize_number(NULL,newl);

    l = sizeof("add ")-1 +
        s->key_alias.len +
        sizeof(" ")-1 +
        sizeof("0")-1 +
        sizeof(" ")-1 +
        ttld +
        sizeof(" ")-1 +
        newd +
        sizeof(CRLF)-1 +
        newl +
        sizeof(CRLF)-1;

    pdu.data = ngx_palloc(pool,l);

    if (pdu.data == NULL) {
        w.on_failure(&w);
        return 0;
    }

    p = pdu.data;
    p = ngx_cpymem(p, "add ", sizeof("add ") - 1);
    p = ngx_cpymem(p, s->key_alias.data, s->key_alias.len);
    *p++ = ' ';
    *p++ = '0';
    *p++ = ' ';
    p += serialize_number(p,ttl);
    *p++ = ' ';
    p += serialize_number(p,newl);
    *p++ = CR;
    *p++ = LF;
    p = ngx_cpymem(p,alias.data,newl);
    *p++ = CR;
    *p++ = LF;

    pdu.len = p-pdu.data;

    *wp = w;
    *kp = s->key_alias;
    *pdup = pdu;

    return 1;
}

/*  cache a user alias (bottom half)
    post the request on memcache
 */
static void ngx_mail_aliascache_bh
(
    mc_work_t       *w,
    ngx_str_t       *k,
    ngx_str_t       *pdu,
    ngx_log_t       *log
)
{
    ngx_memcache_post (w, *k, *pdu, NULL, log);
    return;
}


/* Fetch route from http lookup handler, then cache for future use */
static void ngx_mail_routelookup
    (ngx_mail_session_t *s, ngx_mail_auth_http_ctx_t *ctx)
{
    ngx_mail_auth_http_conf_t   *ahcf;
    ngx_int_t                   rc;
    ngx_uint_t                  *peer_failurep;
    ngx_uint_t                  start = (ngx_uint_t)time(NULL);

    ahcf = ngx_mail_get_module_srv_conf(s, ngx_mail_auth_http_module);

    /* elect a lookup servlet via round-robin */
    do {
        if (ctx->url_attempts == ahcf->peers.nelts) {
            ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                "all %d routing lookup handlers attempted, cannot proxy now",
                ctx->url_attempts);
            ngx_destroy_pool(ctx->pool);
            ngx_mail_session_internal_server_error(s);
            return;
        }
        if (ctx->url_attempts == 0) {
            elect_auth_server_RR (ctx, ahcf);
        } else {
            reelect_auth_server (ctx, ahcf);
        }
        ctx->url_attempts ++;
        peer_failurep = &((ngx_uint_t *)ahcf->peer_failures.elts)[ctx->url_index];
        if (*peer_failurep > 0) {
            if (start < *peer_failurep || start - *peer_failurep <
                ahcf->timeout_cache / 1000) {
                ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                    "skipping down routing handler %d", ctx->url_index);
            } else {
                *peer_failurep = 0;
                ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                    "retrying down routing handler %d", ctx->url_index);
            }
        }
    } while (*peer_failurep > 0);

    ctx->url_health_checked = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0, 
        "elected routing lookup handler at [%V]",
        &elected_peer(ctx, ahcf)->name);

    ctx->peer.sockaddr      = elected_peer(ctx, ahcf)->sockaddr;
    ctx->peer.socklen       = elected_peer(ctx, ahcf)->socklen;
    ctx->peer.name          = &elected_peer(ctx, ahcf)->name;
    ctx->peer.get           = ngx_event_get_peer;
    ctx->peer.log           = s->connection->log;
    ctx->peer.log_error     = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
	*peer_failurep = start;
        if (ctx->peer.connection) {
            ngx_close_connection(ctx->peer.connection);
        }

        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ctx->peer.connection->data = s;
    ctx->peer.connection->pool = s->connection->pool;

    s->connection->read->handler = ngx_mail_auth_http_block_read;
    ctx->peer.connection->read->handler = ngx_mail_routelookup_connect_handler;
    ctx->peer.connection->write->handler = ngx_mail_routelookup_connect_handler;
    ngx_add_timer(ctx->peer.connection->read, ahcf->timeout);
    ngx_add_timer(ctx->peer.connection->write, ahcf->timeout);

    return;
}

/* callback event to indicate that route may be looked up from
   http lookup handler
 */
static void
ngx_mail_routelookup_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t            *c;
    ngx_mail_session_t          *s;
    ngx_mail_auth_http_ctx_t    *ctx;
    int                         socket_error;
    socklen_t                   error_len;

    c = ev->data;
    s = c->data;
    ctx = ngx_mail_get_module_ctx (s, ngx_mail_auth_http_module);

    if (ctx->url_health_checked) {
        return;
    } else {
        ctx->url_health_checked = 1;
    }

    socket_error = 0;
    error_len = sizeof (socket_error);

    /* TODO check for timeout errors */

    getsockopt (c->fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len);

    if (socket_error == EINPROGRESS) {
        /* UN*X kernel shouldn't signal us till the connection is fully
           established (or it fails). So we don't expect to land here,
           but even if we do, the correct thing to do is to just return,
           and we should get invoked again (and again)
         */
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, ev->log, 0,
            "connection to route lookup handler still in progress");

    } else if (socket_error != 0) {
        /* There was an error in the connection, so we will have to re-elect
           another http routing lookup (HRL) handler
         */
        ngx_mail_auth_http_conf_t   *ahcf;
        ngx_uint_t                  *peer_failurep;

        ahcf = ngx_mail_get_module_srv_conf(s, ngx_mail_auth_http_module);
        peer_failurep = &((ngx_uint_t *)ahcf->peer_failures.elts)[ctx->url_index];
        *peer_failurep = (ngx_uint_t)time(NULL);
        ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, ev->log, 0,
            "cannot connect to route lookup handler [err:%d], need to re-elect",
            socket_error
            );

        ngx_close_connection (c);
        ngx_mail_routelookup (s, ctx);
    } else {
        /* There was no error, the connection to the http routing lookup
           handler has been established, and we can continue
         */
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, ev->log, 0,
            "connected to route lookup handler");

        ngx_mail_routelookup_request_handler (s, ctx);
    }

    return;
}

/* callback event to indicate that http request may be constructed in order
   to send to the route lookup handler 
 */
static void ngx_mail_routelookup_request_handler
    (ngx_mail_session_t *s, ngx_mail_auth_http_ctx_t *ctx)
{
    ngx_mail_auth_http_conf_t   *ahcf;

    ahcf = ngx_mail_get_module_srv_conf(s, ngx_mail_auth_http_module);

    ctx->request = ngx_mail_auth_http_create_request(s, ctx->pool, ahcf, ctx);
    if (ctx->request == NULL) {
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ctx->peer.connection->read->handler = ngx_mail_auth_http_read_handler;
    ctx->peer.connection->write->handler = ngx_mail_auth_http_write_handler;

    ctx->handler = ngx_mail_auth_http_ignore_status_line;

    /* ngx_add_timer(ctx->peer.connection->read, ahcf->timeout);
    ngx_add_timer(ctx->peer.connection->write, ahcf->timeout); */

    ngx_mail_auth_http_write_handler(ctx->peer.connection->write);
    return;
}


static void
ngx_mail_auth_http_write_handler(ngx_event_t *wev)
{
    ssize_t                     n, size;
    ngx_connection_t           *c;
    ngx_mail_session_t         *s;
    ngx_mail_auth_http_ctx_t   *ctx;
    ngx_mail_auth_http_conf_t  *ahcf;

    c = wev->data;
    s = c->data;

    ctx = ngx_mail_get_module_ctx(s, ngx_mail_auth_http_module);

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, wev->log, 0,
                   "mail auth http write handler");

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        ngx_close_connection(c);
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = ngx_send(c, ctx->request->pos, size);

    if (n == NGX_ERROR) {
        ngx_close_connection(c);
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = ngx_mail_auth_http_dummy_handler;

            if (wev->timer_set) {
                ngx_del_timer(wev);
            }

            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_close_connection(c);
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
            }

            return;
        }
    }

    if (!wev->timer_set) {
        ahcf = ngx_mail_get_module_srv_conf(s, ngx_mail_auth_http_module);
        ngx_add_timer(wev, ahcf->timeout);
    }
}


static void
ngx_mail_auth_http_read_handler(ngx_event_t *rev)
{
    ssize_t                     n, size;
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_auth_http_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail auth http read handler");

    ctx = ngx_mail_get_module_ctx(s, ngx_mail_auth_http_module);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        ngx_close_connection(c);
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = ngx_create_temp_buf(ctx->pool, 1024);
        if (ctx->response == NULL) {
            ngx_close_connection(c);
            ngx_destroy_pool(ctx->pool);
            ngx_mail_session_internal_server_error(s);
            return;
        }
    }

    size = ctx->response->end - ctx->response->last;

    n = ngx_recv(c, ctx->response->pos, size);

    if (n > 0) {
        ctx->response->last += n;

        ctx->handler(s, ctx);
        return;
    }

    if (n == NGX_AGAIN) {
        return;
    }

    ngx_close_connection(c);
    ngx_destroy_pool(ctx->pool);
    ngx_mail_session_internal_server_error(s);
}


static void
ngx_mail_auth_http_ignore_status_line(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx)
{
    u_char  *p, ch;
    enum  {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_skip,
        sw_almost_done
    } state;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http process status line");

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
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

            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "auth http server &V sent invalid response",
                          ctx->peer.name);
            ngx_close_connection(ctx->peer.connection);
            ngx_destroy_pool(ctx->pool);
            ngx_mail_session_internal_server_error(s);
            return;
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return;

next:

    p = ctx->response->start - 1;

done:

    ctx->response->pos = p + 1;
    ctx->state = 0;
    ctx->handler = ngx_mail_auth_http_process_headers;
    ctx->handler(s, ctx);
}


static void
ngx_mail_auth_http_process_headers(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx)
{
    u_char                      *p;
    time_t                      timer;
    size_t                       len, size;
    ngx_int_t                    rc, port, n;
    ngx_addr_t                  *peer;
    struct sockaddr_in          *sin;
    ngx_mail_auth_http_conf_t   *ahcf;
    ngx_str_t                    user = s->login; /* keep original login */
    mc_work_t                    w1, w2;
    ngx_str_t                    k1, k2;
    ngx_str_t                    pdu1, pdu2;
    ngx_flag_t                   docache1, docache2;
    ngx_pool_t                  *pool1, *pool2;

    ahcf = ngx_mail_get_module_srv_conf(s, ngx_mail_auth_http_module);

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http process headers");

    for ( ;; ) {
        rc = ngx_mail_auth_http_parse_header_line(s, ctx);

        if (rc == NGX_OK) {

#if (NGX_DEBUG)
            ngx_str_t  key, value;

            key.len = ctx->header_name_end - ctx->header_name_start;
            key.data = ctx->header_name_start;
            value.len = ctx->header_end - ctx->header_start;
            value.data = ctx->header_start;

            ngx_log_debug2(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                           "mail auth http header: \"%V: %V\"",
                           &key, &value);
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
                    s->auth_wait = 1;
                    continue;
                }

                ctx->errmsg.len = len;
                ctx->errmsg.data = ctx->header_start;

                switch (s->protocol) {

                case NGX_MAIL_POP3_PROTOCOL:
                    size = sizeof("-ERR ") - 1 + len + sizeof(CRLF) - 1;
                    break;

                case NGX_MAIL_IMAP_PROTOCOL:
                    size = s->tag.len + sizeof("NO ") - 1 + len
                           + sizeof(CRLF) - 1;
                    break;

                default: /* NGX_MAIL_SMTP_PROTOCOL */
                    ctx->err = ctx->errmsg;
                    continue;
                }

                p = ngx_pnalloc(s->connection->pool, size);
                if (p == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ctx->err.data = p;

                switch (s->protocol) {

                case NGX_MAIL_POP3_PROTOCOL:
                    *p++ = '-'; *p++ = 'E'; *p++ = 'R'; *p++ = 'R'; *p++ = ' ';
                    break;

                case NGX_MAIL_IMAP_PROTOCOL:
                    p = ngx_cpymem(p, s->tag.data, s->tag.len);
                    *p++ = 'N'; *p++ = 'O'; *p++ = ' ';
                    break;

                default: /* NGX_MAIL_SMTP_PROTOCOL */
                    break;
                }

                p = ngx_cpymem(p, ctx->header_start, len);
                *p++ = CR; *p++ = LF;

                ctx->err.len = p - ctx->err.data;

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
                s->login.len = ctx->header_end - ctx->header_start;

                s->login.data = ngx_pnalloc(s->connection->pool, s->login.len);
                if (s->login.data == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->login.data, ctx->header_start, s->login.len);

                continue;
            }

            if (len == sizeof("Auth-Pass") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Pass",
                                   sizeof("Auth-Pass") - 1)
                   == 0)
            {
                s->passwd.len = ctx->header_end - ctx->header_start;

                s->passwd.data = ngx_pnalloc(s->connection->pool,
                                             s->passwd.len);
                if (s->passwd.data == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->passwd.data, ctx->header_start, s->passwd.len);

                /* For GSSAPI, we will use a variant of auth-plain (x-zimbra) to log in
                   to upstream. Therefore, we must make a copy of the passwd in dpasswd,
                   because dusr/dpasswd are the so called "delegated" credentials
                 */

                if (s->auth_method == NGX_MAIL_AUTH_GSSAPI) {
                    s->dpasswd = s->passwd;
                }

                continue;
            }

            /* For GSSAPI authentication, the overridden authenticating id is returned */
            if (len == sizeof("Auth-Id") -1
                && ngx_strncasecmp(ctx->header_name_start,
                        (u_char *)"Auth-Id",
                        sizeof("Auth-Id")-1)
                   == 0
               )
            {
                s->dusr.len = ctx->header_end - ctx->header_start;
                s->dusr.data = ngx_palloc(s->connection->pool, s->dusr.len);
                if (s->dusr.data == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->dusr.data,ctx->header_start,s->dusr.len);
                continue;
            }

            if (len == sizeof("Auth-Wait") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Wait",
                                   sizeof("Auth-Wait") - 1)
                   == 0)
            {
                n = ngx_atoi(ctx->header_start,
                             ctx->header_end - ctx->header_start);

                if (n != NGX_ERROR) {
                    ctx->sleep = n;
                }

                continue;
            }

            if (len == sizeof("Auth-Error-Code") - 1
                && ngx_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Error-Code",
                                   sizeof("Auth-Error-Code") - 1)
                   == 0)
            {
                ctx->errcode.len = ctx->header_end - ctx->header_start;

                ctx->errcode.data = ngx_pnalloc(s->connection->pool,
                                                ctx->errcode.len);
                if (ctx->errcode.data == NULL) {
                    ngx_close_connection(ctx->peer.connection);
                    ngx_destroy_pool(ctx->pool);
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(ctx->errcode.data, ctx->header_start,
                           ctx->errcode.len);

                continue;
            }

            /* ignore other headers */

            continue;
        }

        if (rc == NGX_DONE) {
            ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                           "mail auth http header done");

            ngx_close_connection(ctx->peer.connection);

            if (ctx->err.len) {

                ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                              "client login failed: \"%V\"", &ctx->errmsg);

                if (s->protocol == NGX_MAIL_SMTP_PROTOCOL) {

                    if (ctx->errcode.len == 0) {
                        ctx->errcode = ngx_mail_smtp_errcode;
                    }

                    ctx->err.len = ctx->errcode.len + ctx->errmsg.len
                                   + sizeof(" " CRLF) - 1;

                    p = ngx_pnalloc(s->connection->pool, ctx->err.len);
                    if (p == NULL) {
                        ngx_close_connection(ctx->peer.connection);
                        ngx_destroy_pool(ctx->pool);
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                    ctx->err.data = p;

                    p = ngx_cpymem(p, ctx->errcode.data, ctx->errcode.len);
                    *p++ = ' ';
                    p = ngx_cpymem(p, ctx->errmsg.data, ctx->errmsg.len);
                    *p++ = CR; *p = LF;
                }

                s->out = ctx->err;
                timer = ctx->sleep;

                ngx_destroy_pool(ctx->pool);

                if (timer == 0) {
                    s->quit = 1;
                    ngx_mail_send(s->connection->write);
                    return;
                }

                ngx_add_timer(s->connection->read, (ngx_msec_t) (timer * 1000));

                s->connection->read->handler = ngx_mail_auth_sleep_handler;

                return;
            }

            if (s->auth_wait) {
                timer = ctx->sleep;

                ngx_destroy_pool(ctx->pool);

                if (timer == 0) {
                    ngx_mail_auth_http_init(s);
                    return;
                }

                ngx_add_timer(s->connection->read, (ngx_msec_t) (timer * 1000));

                s->connection->read->handler = ngx_mail_auth_sleep_handler;

                return;
            }

            if (ctx->addr.len == 0 || ctx->port.len == 0) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send server or port",
                              ctx->peer.name);
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            if (s->passwd.data == NULL
                && s->protocol != NGX_MAIL_SMTP_PROTOCOL)
            {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send password",
                              ctx->peer.name);
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            peer = ngx_pcalloc(s->connection->pool, sizeof(ngx_addr_t));
            if (peer == NULL) {
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            /* AF_INET only */

            sin = ngx_pcalloc(s->connection->pool, sizeof(struct sockaddr_in));
            if (sin == NULL) {
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            sin->sin_family = AF_INET;

            port = ngx_atoi(ctx->port.data, ctx->port.len);
            if (port == NGX_ERROR || port < 1 || port > 65536) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "port:\"%V\"",
                              ctx->peer.name, &ctx->port);
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            sin->sin_port = htons((in_port_t) port);

            sin->sin_addr.s_addr = ngx_inet_addr(ctx->addr.data, ctx->addr.len);
            if (sin->sin_addr.s_addr == INADDR_NONE) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "address:\"%V\"",
                              ctx->peer.name, &ctx->addr);
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            peer->sockaddr = (struct sockaddr *) sin;
            peer->socklen = sizeof(struct sockaddr_in);

            len = ctx->addr.len + 1 + ctx->port.len;

            peer->name.len = len;

            peer->name.data = ngx_pnalloc(s->connection->pool, len);
            if (peer->name.data == NULL) {
                ngx_destroy_pool(ctx->pool);
                ngx_mail_session_internal_server_error(s);
                return;
            }

            len = ctx->addr.len;

            ngx_memcpy(peer->name.data, ctx->addr.data, len);

            peer->name.data[len++] = ':';

            ngx_memcpy(peer->name.data + len, ctx->port.data, ctx->port.len);


            /* "peer" contains the route at this point */

            pool1 = ngx_create_pool (1024,ngx_cycle->log);
            pool2 = ngx_create_pool (1024,ngx_cycle->log);

            docache1 = 0;
            docache2 = 0;

            if (pool1 != NULL) {
                docache1 = 1;
            }

            if (pool2 != NULL) {
                docache2 = 1;
            }

            if (s->auth_method == NGX_MAIL_AUTH_GSSAPI)
            {
                /* no caching routes or aliases for gssapi */
                docache1 = 0;
                docache2 = 0;
            }

            if (docache1) {
                if (!ngx_mail_routecache_uh
                     (
                     s,
                     s->login,
                     peer,
                     pool1,
                     ngx_cycle->log,
                     &w1,
                     &k1,
                     &pdu1
                     )
                ) {
                    docache1 = 0;
                    pool1 = NULL;
                }
            }

            if (docache2) {
                if (!ngx_mail_aliascache_uh
                     (
                      s,
                      user,
                      s->login,
                      pool2,
                      ngx_cycle->log,
                      &w2,
                      &k2,
                      &pdu2
                     )
                ) {
                    docache2 = 0;
                    pool2 = NULL;
                }
            }

            ngx_mail_proxy_init (s,peer);

            if (docache1) {
                ngx_mail_routecache_bh (&w1, &k1, &pdu1, ngx_cycle->log);
            } else {
                if (pool1 != NULL) {
                    ngx_destroy_pool (pool1);
                }
            }

            if (docache2) {
                ngx_mail_aliascache_bh (&w2, &k2, &pdu2, ngx_cycle->log);
            } else {
                if (pool2 != NULL) {
                    ngx_destroy_pool (pool2);
                }
            }

            /* now it is really safe to destroy ctx->pool :) */
            ngx_destroy_pool (ctx->pool);
            return;
        }

        if (rc == NGX_AGAIN) {
            return;
        }

        /* rc == NGX_ERROR */

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "auth http server %V sent invalid header in response",
                      ctx->peer.name);
        ngx_close_connection(ctx->peer.connection);
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);

        return;
    }
}


static void
ngx_mail_auth_sleep_handler(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail auth sleep handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        /* we need to close the connection immediately */
        s->quit = 0;
        ngx_mail_send(c->write);
        ngx_mail_end_session(s);

        return;
    }

    if (rev->active) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_mail_close_connection(c);
        }
    }
}


static ngx_int_t
ngx_mail_auth_http_parse_header_line(ngx_mail_session_t *s,
    ngx_mail_auth_http_ctx_t *ctx)
{
    u_char      c, ch, *p;
    ngx_uint_t  hash;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    state = ctx->state;
    hash = ctx->hash;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
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
                    hash = c;
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    hash = ch;
                    break;
                }

                return NGX_ERROR;
            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                hash += c;
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                hash += ch;
                break;
            }

            if (ch >= '0' && ch <= '9') {
                hash += ch;
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

    ctx->response->pos = p;
    ctx->state = state;
    ctx->hash = hash;

    return NGX_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;
    ctx->hash = hash;

    return NGX_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return NGX_DONE;
}


static void
ngx_mail_auth_http_block_read(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_auth_http_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail auth http block read");

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ctx = ngx_mail_get_module_ctx(s, ngx_mail_auth_http_module);

        ngx_close_connection(ctx->peer.connection);
        ngx_destroy_pool(ctx->pool);
        ngx_mail_session_internal_server_error(s);
    }
}


static void
ngx_mail_auth_http_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail auth http dummy handler");
}

/* Create the HTTP request that is to be sent to the routing lookup handler.
   Note that we additionally also send the X-Proxy-IP header containing
   the IP address of proxy's network interface to which the client connected
 */
static ngx_buf_t *
ngx_mail_auth_http_create_request(ngx_mail_session_t *s, ngx_pool_t *pool,
    ngx_mail_auth_http_conf_t *ahcf, ngx_mail_auth_http_ctx_t *ctx)
{
    size_t      len;
    ngx_buf_t  *b;
    ngx_str_t   login;

    struct sockaddr_in  server_addr;
    socklen_t           addr_len;

    ngx_mail_core_srv_conf_t    *cscf;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
    addr_len = sizeof (server_addr);
    ngx_memzero(&server_addr, addr_len);
    getsockname(s->connection->fd, (struct sockaddr *)&server_addr, &addr_len);

    ngx_log_debug4(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
        "server interface address is %d.%d.%d.%d",
        *(((u_char*) &server_addr.sin_addr.s_addr) + 0),
        *(((u_char*) &server_addr.sin_addr.s_addr) + 1),
        *(((u_char*) &server_addr.sin_addr.s_addr) + 2),
        *(((u_char*) &server_addr.sin_addr.s_addr) + 3)
        );

    if (ngx_mail_auth_http_escape(pool, &s->login, &login) != NGX_OK) {
        return NULL;
    }

    len = sizeof("GET ") - 1 + elected_uri(ctx, ahcf).len + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + elected_host_header(ctx, ahcf).len + sizeof(CRLF) - 1
          + sizeof("Auth-Method: ") - 1
                + ngx_mail_auth_http_method[s->auth_method].len
                + sizeof(CRLF) - 1
          + sizeof("Auth-User: ") - 1 + login.len + sizeof(CRLF) - 1
          + sizeof("Auth-Pass: ") - 1 + ngx_auth_http_password_len + sizeof(CRLF) - 1
          + sizeof("Auth-Salt: ") - 1 + s->salt.len
          + sizeof("Auth-Protocol: imap" CRLF) - 1
          + sizeof("Auth-Login-Attempt: ") - 1 + NGX_INT_T_LEN
                + sizeof(CRLF) - 1
          + sizeof("Client-IP: ") - 1 + s->connection->addr_text.len
                + sizeof(CRLF) - 1
          + sizeof("X-Proxy-IP: ") - 1 + sizeof ("255.255.255.255") - 1
                + sizeof(CRLF) - 1
          + ahcf->header.len
          + sizeof(CRLF) - 1;

    /* For GSSAPI, we also need to send the authenticating id (principal) */
    if (s->auth_method == NGX_MAIL_AUTH_GSSAPI) {
        len += (sizeof("Auth-Id: ")-1 + s->authid.len + sizeof(CRLF)-1);
        len += (sizeof("Auth-Admin-User: ")-1 + cscf->master_auth_username.len + sizeof(CRLF)-1);
        len += (sizeof("Auth-Admin-Pass: ")-1 + cscf->master_auth_password.len + sizeof(CRLF)-1);
    }

    b = ngx_create_temp_buf(pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = ngx_cpymem(b->last, "GET ", sizeof("GET ") - 1);
    b->last = ngx_copy(b->last, elected_uri(ctx, ahcf).data, elected_uri(ctx, ahcf).len);
    b->last = ngx_cpymem(b->last, " HTTP/1.0" CRLF,
                         sizeof(" HTTP/1.0" CRLF) - 1);

    b->last = ngx_cpymem(b->last, "Host: ", sizeof("Host: ") - 1);
    b->last = ngx_copy(b->last, elected_host_header(ctx, ahcf).data,
                         elected_host_header(ctx, ahcf).len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Auth-Method: ",
                         sizeof("Auth-Method: ") - 1);
    b->last = ngx_cpymem(b->last,
                         ngx_mail_auth_http_method[s->auth_method].data,
                         ngx_mail_auth_http_method[s->auth_method].len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "Auth-User: ", sizeof("Auth-User: ") - 1);
    b->last = ngx_copy(b->last, login.data, login.len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->auth_method == NGX_MAIL_AUTH_GSSAPI) {
        b->last = ngx_cpymem(b->last, "Auth-Id: ", sizeof("Auth-Id: ") - 1);
        b->last = ngx_copy(b->last, s->authid.data, s->authid.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = ngx_cpymem(b->last, "Auth-Admin-User: ", sizeof("Auth-Admin-User: ") - 1);
        b->last = ngx_copy(b->last, cscf->master_auth_username.data, cscf->master_auth_username.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = ngx_cpymem(b->last, "Auth-Admin-Pass: ", sizeof("Auth-Admin-Pass: ") - 1);
        b->last = ngx_copy(b->last, cscf->master_auth_password.data, cscf->master_auth_password.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    b->last = ngx_cpymem(b->last, "Auth-Pass: ", sizeof("Auth-Pass: ") - 1);
    b->last = ngx_copy(b->last, ngx_auth_http_password, ngx_auth_http_password_len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->auth_method != NGX_MAIL_AUTH_PLAIN && s->salt.len) {
        b->last = ngx_cpymem(b->last, "Auth-Salt: ", sizeof("Auth-Salt: ") - 1);
        b->last = ngx_copy(b->last, s->salt.data, s->salt.len);

       // s->passwd.data = NULL;
    }

    b->last = ngx_cpymem(b->last, "Auth-Protocol: ",
                         sizeof("Auth-Protocol: ") - 1);
    b->last = ngx_cpymem(b->last, ngx_mail_auth_http_protocol[s->protocol],
                         sizeof("imap") - 1);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_sprintf(b->last, "Auth-Login-Attempt: %ui" CRLF,
                          s->login_attempt);

    b->last = ngx_cpymem(b->last, "Client-IP: ", sizeof("Client-IP: ") - 1);
    b->last = ngx_copy(b->last, s->connection->addr_text.data,
                         s->connection->addr_text.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = ngx_cpymem(b->last, "X-Proxy-IP: ", sizeof("X-Proxy-IP: ") - 1);
    b->last += serialize_number (b->last, 
            *(((u_char*) &server_addr.sin_addr.s_addr) + 0));
    *b->last++ = '.';
    b->last += serialize_number (b->last,
            *(((u_char*) &server_addr.sin_addr.s_addr) + 1));
    *b->last++ = '.';
    b->last += serialize_number (b->last,
            *(((u_char*) &server_addr.sin_addr.s_addr) + 2));
    *b->last++ = '.';
    b->last += serialize_number (b->last,
            *(((u_char*) &server_addr.sin_addr.s_addr) + 3));
    *b->last++ = CR; *b->last++ = LF;

    if (ahcf->header.len) {
        b->last = ngx_copy(b->last, ahcf->header.data, ahcf->header.len);
    }

    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

#if (NGX_DEBUG_MAIL_PASSWD)
    {
    ngx_str_t  l;

    l.len = b->last - b->pos;
    l.data = b->pos;
    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http hea"
                   "der:\n\"%V\"", &l);
    }
#endif

    return b;
}


static ngx_int_t
ngx_mail_auth_http_escape(ngx_pool_t *pool, ngx_str_t *text, ngx_str_t *escaped)
{
    u_char     *p;
    uintptr_t   n;

    n = ngx_escape_uri(NULL, text->data, text->len, NGX_ESCAPE_MAIL_AUTH);

    if (n == 0) {
        *escaped = *text;
        return NGX_OK;
    }

    escaped->len = text->len + n * 2;

    p = ngx_pnalloc(pool, escaped->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_escape_uri(p, text->data, text->len, NGX_ESCAPE_MAIL_AUTH);

    escaped->data = p;

    return NGX_OK;
}


static void *
ngx_mail_auth_http_create_conf(ngx_conf_t *cf)
{
    ngx_mail_auth_http_conf_t  *ahcf;

    ahcf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_auth_http_conf_t));
    if (ahcf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init (&ahcf->peers, cf->pool, 4, sizeof (ngx_addr_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init (&ahcf->peer_failures, cf->pool, 4, sizeof (ngx_uint_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init (&ahcf->host_headers, cf->pool, 4, sizeof (ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init (&ahcf->uris, cf->pool, 4, sizeof (ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    ahcf->timeout = NGX_CONF_UNSET_MSEC;
    ahcf->timeout_cache = NGX_CONF_UNSET_MSEC;
    ahcf->file = cf->conf_file->file.name.data;
    ahcf->line = cf->conf_file->line;

    return ahcf;
}


static char *
ngx_mail_auth_http_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_auth_http_conf_t *prev = parent;
    ngx_mail_auth_http_conf_t *conf = child;

    u_char           *p;
    size_t            len;
    ngx_uint_t        i;
    ngx_table_elt_t  *header;

    if (conf->peers.nelts == 0)
    {
        conf->peers = prev->peers;
    }

    if (conf->peer_failures.nelts == 0)
    {
        conf->peer_failures = prev->peer_failures;
    }

    if (conf->host_headers.nelts == 0)
    {
        conf->host_headers = prev->host_headers;
    }

    if (conf->uris.nelts == 0)
    {
        conf->uris = prev->uris;
    }

    conf->url_seed = prev->url_seed;
    conf->url_max = prev->url_max;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 15000);
    ngx_conf_merge_msec_value(conf->timeout_cache, prev->timeout_cache, 60000);

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
        conf->header = prev->header;
    }

    if (conf->headers && conf->header.len == 0) {
        len = 0;
        header = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {
            len += header[i].key.len + 2 + header[i].value.len + 2;
        }

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        conf->header.len = len;
        conf->header.data = p;

        for (i = 0; i < conf->headers->nelts; i++) {
            p = ngx_cpymem(p, header[i].key.data, header[i].key.len);
            *p++ = ':'; *p++ = ' ';
            p = ngx_cpymem(p, header[i].value.data, header[i].value.len);
            *p++ = CR; *p++ = LF;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_mail_auth_http(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_auth_http_conf_t *ahcf = conf;

    ngx_addr_t         **peerpp;
    ngx_uint_t          *peer_failurep;
    ngx_str_t           *hhp;
    ngx_str_t           *urip;
    ngx_url_t           u;
    ngx_uint_t          i;

    /* Parse each URL specified against http_auth */

    for (i = 1; i < cf->args->nelts; ++i)
    {
        /* Make space for one (ngx_addr_t *) */

        peerpp = ngx_array_push (&ahcf->peers);

        if (peerpp == NULL) {
            return NGX_CONF_ERROR;
        }

        *peerpp = NULL;

        /* Make space for one (ngx_uint_t) */

        peer_failurep = ngx_array_push (&ahcf->peer_failures);

        if (peer_failurep == NULL) {
            return NGX_CONF_ERROR;
        }

        *peer_failurep = 0;

        /* Make space for one (ngx_str_t) */

        hhp = ngx_array_push (&ahcf->host_headers);

        if (hhp == NULL) {
            return NGX_CONF_ERROR;
        }

        hhp->len = sizeof ("localhost") - 1;
        hhp->data = (u_char *) "localhost";

        urip = ngx_array_push (&ahcf->uris);

        if (urip == NULL) {
            return NGX_CONF_ERROR;
        }

        urip->len = sizeof ("/") - 1;
        urip->data = (u_char *) "/";

        ngx_memzero(&u, sizeof(ngx_url_t));
        u.url = ((ngx_str_t *)cf->args->elts)[i];
        u.default_port = 80;
        u.uri_part = 1;
        u.one_addr = 1;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                   "%s in auth_http \"%V\"", u.err, &u.url);
            }

            continue;
        }

        *peerpp = u.addrs;
        *hhp = u.host;
        *urip = u.uri;

        if (urip->len == 0)
        {
            urip->len = sizeof ("/") - 1;
            urip->data = (u_char *) "/";
        }
    }

    ahcf->url_seed = 0;
    ahcf->url_max = ahcf->peers.nelts;

    return NGX_CONF_OK;
}


static char *
ngx_mail_auth_http_header(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_auth_http_conf_t *ahcf = conf;

    ngx_str_t        *value;
    ngx_table_elt_t  *header;

    if (ahcf->headers == NULL) {
        ahcf->headers = ngx_array_create(cf->pool, 1, sizeof(ngx_table_elt_t));
        if (ahcf->headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    header = ngx_array_push(ahcf->headers);
    if (header == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    header->key = value[1];
    header->value = value[2];

    return NGX_CONF_OK;
}

/* Elects a server to which the auth-http will be made. Round-robin */
static void 
elect_auth_server_RR (ngx_mail_auth_http_ctx_t *ctx, ngx_mail_auth_http_conf_t *cnf)
{
    ctx->url_index = cnf->url_seed;
    cnf->url_seed = (cnf->url_seed + 1) % (cnf->url_max);
}

static void
reelect_auth_server (ngx_mail_auth_http_ctx_t *ctx, ngx_mail_auth_http_conf_t *cnf)
{
    ctx->url_index = (ctx->url_index + 1) % (cnf->url_max);
}

static inline ngx_addr_t *
elected_peer (ngx_mail_auth_http_ctx_t *ctx, ngx_mail_auth_http_conf_t *cnf)
{
    return ((ngx_addr_t **)cnf->peers.elts)[ctx->url_index];
}

static inline ngx_str_t
elected_uri (ngx_mail_auth_http_ctx_t *ctx, ngx_mail_auth_http_conf_t *cnf)
{
    return ((ngx_str_t *)cnf->uris.elts)[ctx->url_index];
}

static inline ngx_str_t elected_host_header
(ngx_mail_auth_http_ctx_t *ctx, ngx_mail_auth_http_conf_t *cnf)
{
    return ((ngx_str_t *)cnf->host_headers.elts)[ctx->url_index];
}

/* Utility function to check whether a login name is fully qualified 
   Return value is boolean (ngx_flag_t for portability)
 */
static ngx_flag_t is_login_qualified (ngx_str_t l)
{
    /* we cannot use the crt strchr because l is not 0 terminated
     */

    size_t      i;
    ngx_flag_t  q;

    q = 0;

    for (i = 0; i < l.len; ++i) {
        if (l.data[i] == '@') { q = 1; break; }
    }

    return q;
}

/* MEMCACHE HANDLERS */

/* memcache handler (cache-miss for a user's route)
   proceeds with route lookup from servlet
 */
static void mch_peerlookup (mc_work_t *w)
{
    ngx_mail_session_t          *s;
    ngx_mail_auth_http_ctx_t    *ctx;

    s = (ngx_mail_session_t *) w->ctx;
    ctx = ngx_mail_get_module_ctx (s, ngx_mail_auth_http_module);

    ngx_mail_routelookup (s,ctx);
}

/* memcache handler (cache-hit for user's route)
   directly initiates proxy session with upstream (route)
 */
static void mch_initiateproxy (mc_work_t *w)
{
    ngx_mail_session_t          *s;
    ngx_mail_auth_http_ctx_t    *ctx;
    ngx_str_t                    route;

    s = (ngx_mail_session_t *) w->ctx;
    ctx = ngx_mail_get_module_ctx (s, ngx_mail_auth_http_module);

    /* deep-copy w->payload to route (on pool s->connection->pool) */
    route.data = ngx_pstrdup(s->connection->pool,&w->payload);

    if (route.data == NULL) {
        /* enomem -- proceed with servlet route lookup */
        ngx_mail_routelookup (s,ctx);
    } else {
        route.len = w->payload.len;
        ngx_mail_initiateproxy (s,ctx,route);
    }
}

/* memcache handler (free a pool)
 */
static void mch_freepool (mc_work_t *w)
{
    ngx_pool_t      *pool = (ngx_pool_t *)w->ctx;
    ngx_destroy_pool (pool);
}

/* memcache handler (cache-hit for user's alias)
 */
static void mch_alias_routelookup (mc_work_t *w)
{
    ngx_mail_session_t          *s;
    ngx_mail_auth_http_ctx_t    *ctx;
    ngx_str_t                    login;

    s = (ngx_mail_session_t *)w->ctx;
    ctx = ngx_mail_get_module_ctx(s,ngx_mail_auth_http_module);

    /* deep-copy w->payload onto s->login (on pool s->connection->pool) */

    login.data = ngx_pstrdup(s->connection->pool,&w->payload);

    if (login.data != NULL) {
        login.len = w->payload.len;
        s->qlogin = login;
        s->vlogin = 2;
    }

    ngx_mail_routelookup_cache(s,ctx);
}

/* memcache handler (cache-miss for user's alias)
 */
static void mch_noalias_routelookup (mc_work_t *w)
{
    ngx_mail_session_t          *s;
    ngx_mail_auth_http_ctx_t    *ctx;

    s = (ngx_mail_session_t *)w->ctx;
    ctx = ngx_mail_get_module_ctx(s,ngx_mail_auth_http_module);

    s->vlogin = 1;  /* avoid duplicate alias lookups */
    ngx_mail_routelookup_cache(s,ctx);
}

static void mch_alias_route_void (mc_work_t *w)
{
    ngx_mail_auth_http_ctx_t    *ctx;

    ctx = (ngx_mail_auth_http_ctx_t *)w->ctx;
    if (ctx->state) {
        ngx_destroy_pool (ctx->pool);
    } else {
        ctx->state++;
    }
}

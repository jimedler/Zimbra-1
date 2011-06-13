
/*
 * Copyright (C) Igor Sysoev
 */

/*
 * Portions Copyright (c) VMware, Inc. [1998-2011]. All Rights Reserved.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <sasl/sasl.h>
#include <ngx_memcache.h>
#include <ngx_mail_throttle_module.h>

#include <ngx_serialize.h>

static void ngx_mail_init_session(ngx_connection_t *c);
static void ngx_mail_choke_session(throttle_callback_t *cb);
static void ngx_mail_allow_session(throttle_callback_t *cb);
static void ngx_mail_init_protocol(ngx_event_t *rev);
static ngx_int_t ngx_mail_decode_auth_plain(ngx_mail_session_t *s,
    ngx_str_t *encoded);
static void ngx_mail_do_auth(ngx_mail_session_t *s);
static ngx_int_t ngx_mail_read_command(ngx_mail_session_t *s);
static u_char *ngx_mail_log_error(ngx_log_t *log, u_char *buf, size_t len);

#if (NGX_MAIL_SSL)
static void ngx_mail_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c);
static void ngx_mail_ssl_handshake_handler(ngx_connection_t *c);
#endif

static void ngx_mail_dispose_sasl_context (ngx_mail_session_t *s);

static ngx_str_t  internal_server_errors[] = {
   ngx_string("-ERR internal server error" CRLF),
   ngx_string("* BAD internal server error" CRLF),
   ngx_string("451 4.3.2 Internal server error" CRLF),
};

static ngx_str_t  quitmsgs[] = {
   ngx_string(""),
   ngx_string("* BYE Zimbra IMAP server terminating connection" CRLF),
   ngx_string(""),
};

static u_char  pop3_ok[] = "+OK" CRLF;
static u_char  pop3_next[] = "+ " CRLF;
static u_char  pop3_username[] = "+ VXNlcm5hbWU6" CRLF;
static u_char  pop3_password[] = "+ UGFzc3dvcmQ6" CRLF;
static u_char  pop3_invalid_command[] = "-ERR invalid command" CRLF;
static u_char  pop3_unsupported_mech[] = "-ERR mechanism not supported" CRLF;
static u_char  pop3_nocleartext[] = "-ERR cleartext logins disabled" CRLF;
static u_char  pop3_authaborted[] = "-ERR authentication aborted" CRLF;

static u_char  imap_star[] = "* ";
static u_char  imap_ok[] = "OK completed" CRLF;
static u_char  imap_next[] = "+ " CRLF;
static u_char  imap_bye[] = "* BYE Zimbra IMAP server terminating connection" CRLF;
static u_char  imap_invalid_command[] = "BAD invalid command" CRLF;
static u_char  imap_unsupported_mech[] = "NO mechanism not supported" CRLF;
static u_char  imap_nocleartext[] = "NO cleartext logins disabled" CRLF;
static u_char  imap_authaborted[] = "BAD AUTHENTICATE aborted" CRLF; 

static u_char  smtp_ok[] = "250 2.0.0 OK" CRLF;
static u_char  smtp_bye[] = "221 2.0.0 Bye" CRLF;
static u_char  smtp_starttls[] = "220 2.0.0 Start TLS" CRLF;
static u_char  smtp_next[] = "334 " CRLF;
static u_char  smtp_username[] = "334 VXNlcm5hbWU6" CRLF;
static u_char  smtp_password[] = "334 UGFzc3dvcmQ6" CRLF;
static u_char  smtp_invalid_command[] = "500 5.5.1 Invalid command" CRLF;
static u_char  smtp_invalid_argument[] = "501 5.5.4 Invalid argument" CRLF;
static u_char  smtp_auth_required[] = "530 5.7.1 Authentication required" CRLF;

static ngx_str_t    krb5_cooked_password = ngx_string("KKK");

static ngx_flag_t sasl_initialized = 0;

void
ngx_mail_init_connection(ngx_connection_t *c)
{
    in_addr_t             in_addr;
    socklen_t             len;
    ngx_uint_t            i;
    struct sockaddr_in    sin;
    ngx_mail_log_ctx_t   *ctx;
    ngx_mail_in_port_t   *imip;
    ngx_mail_in_addr_t   *imia;
    ngx_mail_session_t   *s;
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t  *sslcf;
#endif


    /* find the server configuration for the address:port */

    /* AF_INET only */

    imip = c->listening->servers;
    imia = imip->addrs;

    i = 0;

    if (imip->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

#if (NGX_WIN32)
        if (c->local_sockaddr) {
            in_addr =
                   ((struct sockaddr_in *) c->local_sockaddr)->sin_addr.s_addr;

        } else
#endif
        {
            len = sizeof(struct sockaddr_in);
            if (getsockname(c->fd, (struct sockaddr *) &sin, &len) == -1) {
                ngx_connection_error(c, ngx_socket_errno,
                                     "getsockname() failed");
                ngx_mail_close_connection(c);
                return;
            }

            in_addr = sin.sin_addr.s_addr;
        }

        /* the last address is "*" */

        for ( /* void */ ; i < imip->naddrs - 1; i++) {
            if (in_addr == imia[i].addr) {
                break;
            }
        }
    }


    s = ngx_pcalloc(c->pool, sizeof(ngx_mail_session_t));
    if (s == NULL) {
        ngx_mail_close_connection(c);
        return;
    }

    s->main_conf = imia[i].ctx->main_conf;
    s->srv_conf = imia[i].ctx->srv_conf;

    s->addr_text = &imia[i].addr_text;

    c->data = s;
    s->connection = c;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V",
                  c->number, &c->addr_text, s->addr_text);

    ctx = ngx_palloc(c->pool, sizeof(ngx_mail_log_ctx_t));
    if (ctx == NULL) {
        ngx_mail_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_mail_log_error;
    c->log->data = ctx;
    c->log->action = "sending client greeting line";

    c->log_error = NGX_ERROR_INFO;

#if (NGX_MAIL_SSL)

    sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

    if (sslcf->enable) {
        ngx_mail_ssl_init_connection(&sslcf->ssl, c);
        return;
    }

#endif

    ngx_mail_init_session(c);
}


#if (NGX_MAIL_SSL)

void
ngx_mail_starttls_handler(ngx_event_t *rev)
{
    ngx_connection_t     *c;
    ngx_mail_session_t   *s;
    ngx_mail_ssl_conf_t  *sslcf;

    c = rev->data;
    s = c->data;
    s->starttls = 1;

    c->log->action = "in starttls state";

    sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

    ngx_mail_ssl_init_connection(&sslcf->ssl, c);
}


static void
ngx_mail_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c)
{
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;

    if (ngx_ssl_create_connection(ssl, c, 0) == NGX_ERROR) {
        ngx_mail_close_connection(c);
        return;
    }

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {

        s = c->data;

        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

        ngx_add_timer(c->read, cscf->timeout);

        c->ssl->handler = ngx_mail_ssl_handshake_handler;

        return;
    }

    ngx_mail_ssl_handshake_handler(c);
}


static void
ngx_mail_ssl_handshake_handler(ngx_connection_t *c)
{
    ngx_mail_session_t  *s;

    if (c->ssl->handshaked) {

        s = c->data;

        if (s->starttls) {
            c->read->handler = ngx_mail_init_protocol;
            c->write->handler = ngx_mail_send;

            ngx_mail_init_protocol(c->read);

            return;
        }

        ngx_mail_init_session(c);
        return;
    }

    ngx_mail_close_connection(c);
}

#endif


static void
ngx_mail_init_session(ngx_connection_t *c)
{
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t *cscf;
    ngx_mail_throttle_srv_conf_t *tscf;
    throttle_callback_t       *cb;

    c->read->handler = ngx_mail_init_protocol;
    c->write->handler = ngx_mail_send;

    s = c->data;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
    tscf = ngx_mail_get_module_srv_conf(s, ngx_mail_throttle_module);

    s->protocol = cscf->protocol;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_mail_max_module);
    if (s->ctx == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    s->cleanup = NULL;

    /* throttle */
    cb = ngx_pcalloc(c->pool,sizeof(throttle_callback_t));
    if(cb==NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ngx_memset(cb,0,sizeof(throttle_callback_t));
    cb->session = s;
    cb->connection = c;
    cb->log = ngx_cycle->log;
    cb->pool = c->pool;
    cb->on_allow = ngx_mail_allow_session;
    cb->on_deny = ngx_mail_choke_session;

    if (tscf->mail_login_ip_max == 0) {
        cb->on_allow(cb); //unlimited, direct allow session
    } else {
        ngx_mail_throttle_ip(c->addr_text, cb);
    }
}

static void
ngx_mail_choke_session(throttle_callback_t *cb)
{
    ngx_connection_t             *c;
    ngx_mail_session_t           *s;
    ngx_mail_throttle_srv_conf_t *tscf;
    ngx_str_t                     bye, msg;
    u_char                       *p;

    c = (ngx_connection_t *)cb->connection;
    s = c->data;
    tscf = ngx_mail_get_module_srv_conf(s, ngx_mail_throttle_module);
    msg = tscf->mail_login_ip_rejectmsg;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log,0,
        "ip throttle:%V choking mail session", &c->addr_text);

    if(s->protocol == NGX_MAIL_IMAP_PROTOCOL) {
        bye.data = 
        ngx_palloc(c->pool,
            sizeof("* BYE ")-1+
            msg.len+
            sizeof(CRLF)-1
            );
        if (bye.data == NULL) {
            bye.data = (u_char*)("* BYE" CRLF);
            bye.len = sizeof("* BYE" CRLF)-1;
        } else {
            p = bye.data;
            p = ngx_cpymem(p,"* BYE ",sizeof("* BYE ")-1);
            p = ngx_cpymem(p,msg.data,msg.len);
            *p++ = CR;
            *p++ = LF;
            bye.len = p-bye.data;
        }
    } else if(s->protocol == NGX_MAIL_POP3_PROTOCOL) {
        bye.data = 
        ngx_palloc(c->pool,
        sizeof("-ERR ")-1+msg.len+sizeof(CRLF)-1);
        if (bye.data == NULL) {
            bye.data = (u_char*)("-ERR" CRLF);
            bye.len = sizeof("-ERR" CRLF)-1;
        } else {
            p = bye.data;
            p = ngx_cpymem(p,"-ERR ",sizeof("-ERR ") - 1);
            p = ngx_cpymem(p,msg.data,msg.len);
            *p++ = CR;
            *p++ = LF;
            bye.len = p-bye.data;
        }
    } else {
        /* TODO SMTP is not (yet) relevant for zimbra, but how do we reject it ? */
        bye.data = (u_char*)("");
        bye.len = 0;
    }

    s->out = bye;
    s->quit = 1;

    ngx_mail_send(c->write);

    return;
}

static void
ngx_mail_allow_session(throttle_callback_t *cb)
{
    ngx_connection_t            *c;
    ngx_mail_session_t          *s;
    ngx_mail_core_srv_conf_t    *cscf;
    u_char                      *p;

    c = (ngx_connection_t*)cb->connection;
    s = c->data;
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    s->out = cscf->greetings[s->protocol];

    if ((s->protocol == NGX_MAIL_POP3_PROTOCOL
         && (cscf->pop3_auth_methods
             & (NGX_MAIL_AUTH_APOP_ENABLED|NGX_MAIL_AUTH_CRAM_MD5_ENABLED)))

        || (s->protocol == NGX_MAIL_SMTP_PROTOCOL
           && (cscf->smtp_auth_methods & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)))
    {
        s->salt.data = ngx_palloc(c->pool,
                                 sizeof(" <18446744073709551616.@>" CRLF) - 1
                                 + NGX_TIME_T_LEN
                                 + cscf->server_name.len);
        if (s->salt.data == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        s->salt.len = ngx_sprintf(s->salt.data, "<%ul.%T@%V>" CRLF,
                                  ngx_random(), ngx_time(), &cscf->server_name)
                     - s->salt.data;

        if (s->protocol == NGX_MAIL_POP3_PROTOCOL) {
            s->out.data = ngx_palloc(c->pool,
                cscf->greetings[NGX_MAIL_POP3_PROTOCOL].len + 1 + s->salt.len);
            if (s->out.data == NULL) {
                ngx_mail_session_internal_server_error(s);
                return;
            }

            p = ngx_cpymem(s->out.data,
                           cscf->greetings[NGX_MAIL_POP3_PROTOCOL].data,
                           cscf->greetings[NGX_MAIL_POP3_PROTOCOL].len - 2);
            *p++ = ' ';
            p = ngx_cpymem(p, s->salt.data, s->salt.len);

            s->out.len = p - s->out.data;
        }
    }

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
        ngx_mail_close_connection(c);
    }

    ngx_mail_send(c->write);
}

static void
ngx_mail_choke_userauth(throttle_callback_t *cb)
{
    ngx_connection_t             *c;
    ngx_mail_session_t           *s;
    ngx_mail_throttle_srv_conf_t *tscf;
    ngx_str_t                     bye, msg, umsg;
    size_t                        l;
    u_char                       *p;

    c = (ngx_connection_t *)cb->connection;
    s = c->data;
    tscf = ngx_mail_get_module_srv_conf(s, ngx_mail_throttle_module);
    msg = tscf->mail_login_user_rejectmsg;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
        "user throttle:%V choking mail session", &s->login);

    if(s->protocol == NGX_MAIL_IMAP_PROTOCOL)
    {
        bye.data = 
        ngx_palloc(c->pool,
        sizeof("* BYE ") - 1  +msg.len + sizeof(CRLF) - 1);
        if (bye.data == NULL) {
            bye.data = (u_char*)("* BYE" CRLF);
            bye.len = sizeof("* BYE" CRLF) - 1;
        } else {
            p = bye.data;
            p = ngx_cpymem(p, "* BYE ", sizeof("* BYE ") - 1);
            p = ngx_cpymem(p, msg.data, msg.len);
            *p++ = CR;
            *p++ = LF;
            bye.len = p - bye.data;
        }
        s->out = bye;
        s->quit = 0;            /* don't quit just yet */
        ngx_mail_send(c->write);

        /* for IMAP, we also want to send back a tagged NO response */
        l = s->tag.len + 
            sizeof("NO ") - 1 +
            sizeof(" failed") - 1 +       /* ?? "failed" or "rejected" ?? */
            sizeof(CRLF) - 1;

        if (s->command == NGX_IMAP_LOGIN) {
            l += (sizeof("LOGIN ") - 1);
        } else if (s->command == NGX_IMAP_AUTH) {
            l += (sizeof("AUTHENTICATE ") - 1);
        }

        umsg.data = ngx_palloc(c->pool,l);

        if (umsg.data == NULL) {
            umsg.data = (u_char*)"";
            umsg.len = 0;
        } else {
            p = umsg.data;
            p = ngx_cpymem(p, s->tag.data, s->tag.len);
            p = ngx_cpymem(p,"NO ", sizeof("NO ") - 1);
            if (s->command == NGX_IMAP_LOGIN) {
                p = ngx_cpymem(p,"LOGIN ", sizeof("LOGIN ") - 1);
            } else if (s->command == NGX_IMAP_AUTH) {
                p = ngx_cpymem(p,"AUTHENTICATE ", sizeof("AUTHENTICATE ") - 1);
            }
            p = ngx_cpymem(p, "failed", sizeof("failed") - 1);
            *p++ = CR;
            *p++ = LF;
            umsg.len = p - umsg.data;
        }

        s->out = umsg;
        s->quit = 1;
        ngx_mail_send(c->write);

        return;
    }
    else if(s->protocol == NGX_MAIL_POP3_PROTOCOL)
    {
        bye.data = 
        ngx_palloc(c->pool,
        sizeof("-ERR ")-1+msg.len+sizeof(CRLF)-1);
        if (bye.data == NULL) {
            bye.data = (u_char*)("-ERR" CRLF);
            bye.len = sizeof("-ERR" CRLF)-1;
        } else {
            p = bye.data;
            p = ngx_cpymem(p,"-ERR ",sizeof("-ERR ")-1);
            p = ngx_cpymem(p,msg.data,msg.len);
            *p++ = CR;
            *p++ = LF;
            bye.len = p-bye.data;
        }
        s->out = bye;
        s->quit = 1;
        ngx_mail_send(c->write);
        return;
    }
    else
    {
        /* TODO SMTP is not (yet) relevant for zimbra, but how do we reject it ? */
        bye.data = (u_char*)("");
        bye.len = 0;
        s->out = bye;
        s->quit = 1;
        ngx_mail_send(c->write);
        return;
    }
}

static void
ngx_mail_allow_userauth(throttle_callback_t *cb)
{
    ngx_connection_t            *c;
    ngx_mail_session_t          *s;

    c = (ngx_connection_t *)cb->connection;
    s = c->data;

    /* remainder code is the erstwhile ngx_mail_do_auth(s);*/
    s->args.nelts = 0;
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;
    s->state = 0;

    if (s->connection->read->timer_set) {
        ngx_del_timer(s->connection->read);
    }

    s->login_attempt++;
    ngx_mail_auth_http_init(s);
}

#if (NGX_MAIL_SSL)

ngx_int_t
ngx_mail_starttls_only(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_mail_ssl_conf_t  *sslcf;

    if (c->ssl) {
        return 0;
    }

    sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

    if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
        return 1;
    }

    return 0;
}

#endif

void
ngx_mail_send(ngx_event_t *wev)
{
    ngx_int_t                  n;
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;

    c = wev->data;
    s = c->data;

    if (s->out.len == 0) {
        if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
            ngx_mail_close_connection(c);
        }

        return;
    }

    n = c->send(c, s->out.data, s->out.len);

    if (n > 0) {
        s->out.len -= n;

        if (wev->timer_set) {
            ngx_del_timer(wev);
        }

        if (s->quit) {
            ngx_mail_close_connection(c);
            return;
        }

        if (s->blocked) {
            c->read->handler(c->read);
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_mail_close_connection(c);
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    /* n == NGX_AGAIN */

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    ngx_add_timer(c->write, cscf->timeout);

    if (ngx_handle_write_event(c->write, 0) == NGX_ERROR) {
        ngx_mail_close_connection(c);
        return;
    }
}


static void
ngx_mail_init_protocol(ngx_event_t *rev)
{
    size_t                     size;
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;

    c = rev->data;

    c->log->action = "in auth state";

    /* generic timeout abort code removed, because each protocol handler
       takes care of it separately - if(rev->timedout) { ... }
     */

    s = c->data;

    switch (s->protocol) {

    case NGX_MAIL_POP3_PROTOCOL:
        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
        size = cscf->pop3_client_buffer_size;
        s->mail_state = ngx_pop3_start;
        c->read->handler = ngx_pop3_auth_state;
        break;

    case NGX_MAIL_IMAP_PROTOCOL:
        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);
        size = cscf->imap_client_buffer_size;
        s->mail_state = ngx_imap_start;
        c->read->handler = ngx_imap_auth_state;
        break;

    default: /* NGX_MAIL_SMTP_PROTOCOL */
        size = 512;
        s->mail_state = ngx_smtp_start;
        c->read->handler = ngx_smtp_auth_state;
        break;
    }

    if (s->buffer == NULL) {
        if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t))
            == NGX_ERROR)
        {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        s->buffer = ngx_create_temp_buf(c->pool, size);
        if (s->buffer == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }
    }

    c->read->handler(rev);
}

/* Perform a once-per-process initialization of the sasl library */
static int ngx_mail_initialize_sasl (ngx_connection_t *c)
{
    ngx_mail_session_t          *s;
    ngx_mail_core_srv_conf_t    *cscf;
    int                          rc = SASL_OK;
    char                        *app;

    if (!sasl_initialized)
    {
        s = c->data;
        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

        app = ngx_palloc(c->pool, cscf->sasl_app_name.len + 1);

        if (app == NULL) { return SASL_FAIL; }

        ngx_memcpy (app, cscf->sasl_app_name.data, cscf->sasl_app_name.len);
        ngx_memcpy (app + cscf->sasl_app_name.len, "\x0", 1);

        ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "Initializing SASL library, app:%s", app);

        rc = sasl_server_init (NULL, app);

        if (rc != SASL_OK)
        {
            ngx_log_error (NGX_LOG_ERR, c->log, 0,
                "Cannot initialize SASL library: err:%d, %s",
                rc, sasl_errstring(rc,NULL,NULL)
            );
        }
        else
        {
            ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                "Initialized SASL library");
            sasl_initialized = 1;
        }
    }

    return rc;
}

static int ngx_mail_canonicalize_user (
    sasl_conn_t *conn,
    void *context,
    const char *in,
    unsigned inlen,
    unsigned flags,
    const char *realm,
    char *out,
    unsigned out_max,
    unsigned *out_len
)
{
    ngx_connection_t            *c = context;
    ngx_mail_session_t          *s = c->data;
    ngx_mail_core_srv_conf_t    *cscf = 
        ngx_mail_get_module_srv_conf(s,ngx_mail_core_module);
    ngx_str_t            v,R;

    ngx_log_debug0 (NGX_LOG_DEBUG_MAIL,c->log,0,
        "sasl: canonicalizing user name(s)");

    if (realm == NULL) {
        ngx_log_debug1 (NGX_LOG_DEBUG_MAIL,c->log,0,
            "sasl: SASL layer did not provide realm, will use:%V",
            &cscf->default_realm);
        R = cscf->default_realm;
    } else {
        ngx_log_debug1 (NGX_LOG_DEBUG_MAIL,c->log,0,
            "sasl: will use realm:%s", realm);
        R.data = (u_char *)realm;
        R.len = strlen(realm);
    }

    if (((flags & SASL_CU_AUTHID) != 0) || ((flags & SASL_CU_AUTHZID) != 0))
    {
        v.data = (u_char *)in;
        v.len = inlen;

        if ((flags & SASL_CU_AUTHID) == 0) {
            ngx_log_debug1 (NGX_LOG_DEBUG_MAIL,c->log,0,
                "sasl: canonicalizing authzid:%V", &v);
        } else if ((flags & SASL_CU_AUTHZID) == 0) {
            ngx_log_debug1 (NGX_LOG_DEBUG_MAIL,c->log,0,
                "sasl: canonicalizing authcid:%V", &v);
        } else {
            ngx_log_debug2 (NGX_LOG_DEBUG_MAIL,c->log,0,
                "sasl: canonicalizing authzid:%V, authcid:%V", &v, &v);
        }

        if (R.len == 0) {
            if (out_max >= inlen) {
                ngx_memcpy(out,in,inlen);
                *out_len = inlen;
                return SASL_OK;
            } else {
                return SASL_NOMEM;
            }
        } else {
            if (out_max >= (inlen+(sizeof("@")-1)+R.len)) {
                ngx_memcpy(out,in,inlen);
                ngx_memcpy(out+inlen,"@",sizeof("@")-1);
                ngx_memcpy(out+inlen+sizeof("@")-1,R.data,R.len);
                *out_len = inlen + sizeof("@")-1 + R.len;
                return SASL_OK;
            } else {
                return SASL_NOMEM;
            }
        }
    }

    return SASL_BADPARAM;
}

static int ngx_mail_sasl_pauthorize (sasl_conn_t *conn, void *context, const char *authz, unsigned authzlen, const char *authc, unsigned authclen, const char *realm, unsigned rlen, struct propctx *propctx)
{
    /* this function is called when we need to indicate whether the authz/authc 
       relationship should be allowed or not
       ie can authc access authz's mailbox
       since that decision must be made in the lookup servlet (which will happen later),
       we need to defer that decision to the route lookup phase, and simply 
       indicate our consent here
     */

    ngx_connection_t    *c = context;
    ngx_str_t            nauthz = ngx_string(""),
                         nauthc = ngx_string(""),
                         nrealm = ngx_string("");

    (void)c;
    if (authz != NULL && authzlen > 0) {
        nauthz.data = (u_char *)authz;
        nauthz.len = authzlen;
    }
    if (authc != NULL && authclen > 0) {
        nauthc.data = (u_char *)authc;
        nauthc.len = authclen;
    }
    if (realm != NULL && rlen > 0) {
        nrealm.data = (u_char *)realm;
        nrealm.len = rlen;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_MAIL,c->log,0,
        "sasl: indicating proxy policy ok, authz:%V,authc:%V,realm:%V",
        &nauthz,&nauthc,&nrealm
        );

    return SASL_OK;
}

static int ngx_mail_sasl_log (void *context, int level, const char *message)
{
    ngx_connection_t    *c = context;

    (void)c;
    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, c->log, 0,
        "%s", message == NULL ? "null" : message);

    return SASL_OK;
}


/* create a new SASL server authentication object (once per connection) */
static int ngx_mail_create_sasl_context (ngx_connection_t *c)
{
    ngx_mail_session_t          *s;
    ngx_mail_core_srv_conf_t    *cscf;
    char                        *service;
    int                          rc = SASL_OK;
    sasl_security_properties_t   rsec;
    sasl_callback_t             *callbacks;
    ngx_uint_t                   i;
    const char                  *fqdn = NULL;
    struct hostent              *host;
    struct sockaddr_in           sa;
    socklen_t                    salen;
    u_char                      *octets;

    s = c->data;
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    if (s->saslconn == NULL)
    {
        service = ngx_palloc (c->pool, cscf->sasl_service_name.len +1);
        if (service == NULL) {
            return SASL_FAIL;
        }

        callbacks = ngx_palloc(c->pool,sizeof(sasl_callback_t)*8);
        if (callbacks == NULL) {
            ngx_log_error (NGX_LOG_ERR, c->log, 0, 
                "cannot alloc memory for SASL callbacks"
                );
            return SASL_NOMEM;
        }

        i=0;
        // XXX using the canon callback is corrupting mem
        // callbacks[i].id = SASL_CB_CANON_USER;
        // callbacks[i].proc = ngx_mail_canonicalize_user;
        // callbacks[i].context = c;
        // ++i;
        callbacks[i].id = SASL_CB_LOG;
        callbacks[i].proc = ngx_mail_sasl_log;
        callbacks[i].context = c;
        ++i;

        callbacks[i].id = SASL_CB_PROXY_POLICY;
        callbacks[i].proc = ngx_mail_sasl_pauthorize;
        callbacks[i].context = c;
        ++i;

        callbacks[i].id = SASL_CB_LIST_END;
        callbacks[i].proc = NULL;
        callbacks[i].context = NULL;
        ++i;

        ngx_memcpy (service, cscf->sasl_service_name.data,
            cscf->sasl_service_name.len);
        service[cscf->sasl_service_name.len] = 0;

        /* The second argument to sasl_server_new is the FQDN of the server
           If the srvprinc_from_ip configuration parameter is true, then 
         */

        if (cscf->sasl_host_from_ip)
        {
            ngx_log_error (NGX_LOG_WARN, c->log, 0,
                "will use IP address to resolve service principal");

            salen = sizeof(sa);
            if (
                getsockname(s->connection->fd, (struct sockaddr*)&sa, &salen)
                == 0
               )
            {
                if (sa.sin_family != AF_INET || salen != sizeof(sa))
                {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "non-ipv4 local address of mail connection ignored");
                }
                else
                {
                    octets = (u_char *)&sa.sin_addr.s_addr;

                    ngx_log_error (NGX_LOG_WARN, c->log, 0,
                        "entering blocking network call (gethostbyaddr)");

                    host = gethostbyaddr(
                            &sa.sin_addr,
                            sizeof(sa.sin_addr),
                            AF_INET);

                    if (host == NULL)
                    {
                        ngx_log_error (NGX_LOG_ERR, c->log, 0,
                            "cannot lookup host by IP address, err:%d",
                            h_errno);
                    }
                    else
                    {
                        ngx_log_error (NGX_LOG_INFO, c->log, 0,
                            "resolved incoming IP %d.%d.%d.%d to host:%s",
                            octets[0],
                            octets[1],
                            octets[2],
                            octets[3],
                            host->h_name);

                        fqdn = host->h_name;
                    }
                }
            }
            else
            {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "cannot get local address of mail connection, err:%d",
                    ngx_errno);
            }
        }

        rc = sasl_server_new
                (
                    service,
                    fqdn,
                    NULL,
                    NULL,
                    NULL,
                    callbacks,
                    0,
                    &s->saslconn
                );

        if (rc != SASL_OK)
        {
            ngx_log_error (NGX_LOG_ERR, c->log, 0, 
                "cannot create SASL context (%V), err:%d,%s",
                &cscf->sasl_service_name,
                rc, sasl_errstring (rc,NULL,NULL)
                );
            s->saslconn = NULL;
        }
        else
        {
            ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, c->log, 0, 
                "created SASL context (%V), 0x%p",
                &cscf->sasl_service_name,
                s->saslconn
                );

            rsec.min_ssf = 0;
            rsec.max_ssf = 0;
            rsec.maxbufsize = 4096;
            rsec.property_names = NULL;
            rsec.property_values = NULL;
            rsec.security_flags = 0;
            // SASL_SEC_PASS_CREDENTIALS|SASL_SEC_MUTUAL_AUTH;

            rc = sasl_setprop(s->saslconn, SASL_SEC_PROPS, &rsec);
        }
    }

    return rc;
}

static void ngx_mail_dispose_sasl_context (ngx_mail_session_t *s)
{
    if (s->saslconn != NULL)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL,s->connection->log,0,
            "disposing SASL context:%p",s->saslconn);
        sasl_dispose(&s->saslconn);
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL,s->connection->log,0,
            "disposed SASL context:%p",s->saslconn);
        s->saslconn = NULL;
    }
    return;
}

/*  ngx_mail_sasl_startstep
 */
static int ngx_mail_sasl_startstep (
    ngx_connection_t *c,
    const char *mech,
    ngx_str_t  *responses,
    ngx_uint_t  nresp,
    ngx_str_t  *challenge
    )
{
    ngx_mail_session_t          *s;
    ngx_str_t                    r;
    int                          rc;
    const char                  *saslstr,*authc,*authz;
    unsigned                     sasls;
    ngx_str_t                    ch64, ch;
    ngx_mail_core_srv_conf_t    *cscf;
    u_char                      *p;
    ngx_flag_t                   inheritAuthZ, needRealm;
    size_t                       len;

    s = c->data;
    cscf = ngx_mail_get_module_srv_conf(s,ngx_mail_core_module);

    /* saslfr (fr = first response) indicates whether the client has
       issued at least one SASL response to the server
       saslfr starts out as 0, and is immediately set to 1 when the 
       server starts processing the client responses
     */
    if (!s->saslfr)
    {
        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "beginning SASL auth negotiation");

        if (nresp == 0)
        {
            ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                "using NULL client response");

            r.data = NULL;
            r.len = 0;
        }
        else
        {
             ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                "using last response of %d client responses", nresp);

             r.len = ngx_base64_decoded_length (responses[nresp-1].len);
             r.data = ngx_palloc (c->pool, r.len);

             if (r.data == NULL) {
                return SASL_FAIL;
             }

             if (ngx_decode_base64 (&r, &responses[nresp-1]) != NGX_OK)
             {
                ngx_log_error (NGX_LOG_ERR, c->log, 0,
                    "invalid base64 response sent by client");

                return SASL_FAIL;
             }
             else
             {
                ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                    "%d bytes of base64-challenge decoded to %d sasl-bytes",
                    responses[nresp-1].len, r.len);
             }
        }

        rc = sasl_server_start
                (
                    s->saslconn,
                    mech,
                    (char *)r.data,
                    r.len,
                    &saslstr,
                    &sasls
                );

        s->saslfr = 1;
    }
    else
    {
         ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "continuing SASL auth negotiation");

         r.len = ngx_base64_decoded_length (responses[nresp-1].len);
         r.data = ngx_palloc (c->pool, r.len);

         if (r.data == NULL) {
            return SASL_FAIL;
         }

         if (ngx_decode_base64 (&r, responses + nresp - 1) != NGX_OK)
         {
            ngx_log_error (NGX_LOG_ERR, c->log, 0,
                "invalid base64 response sent by client");

            return SASL_FAIL;
         }
 
        rc = sasl_server_step
                (
                    s->saslconn,
                    (char *)r.data,
                    r.len,
                    &saslstr,
                    &sasls
                );
    }

    if ((rc != SASL_OK) && (rc != SASL_CONTINUE))
    {
        ngx_log_error (NGX_LOG_ERR, c->log, 0,
            "SASL auth negotiation failed, err:%d (%s)",
            rc, sasl_errstring(rc,NULL,NULL));
    }
    else
    {
        /* construct the challenge depending upon the protocol */

        ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, c->log, 0,
            "constructing protocol specific response for %d bytes of challenge",
            sasls);

        if (saslstr == NULL || sasls == 0)
        {
            ch64.data = (u_char *)"";
            ch64.len = 0;
        }
        else
        {
            ch.len = sasls;
            ch.data = (u_char *)saslstr;

            ch64.len = ngx_base64_encoded_length(ch.len);
            ch64.data = ngx_palloc (c->pool, ch64.len);

            if (ch64.data == NULL) {
                return SASL_FAIL;
            }

            ngx_encode_base64 (&ch64, &ch);
        }

        if (rc == SASL_CONTINUE)
        {
            /* For IMAP/POP, we need to send "+" SP <challenge> CRLF */
            if (s->protocol == NGX_MAIL_IMAP_PROTOCOL
                ||
                s->protocol == NGX_MAIL_POP3_PROTOCOL
               )
            {
                challenge->len = sizeof("+ ") -1 + ch64.len + sizeof(CRLF) -1;
                challenge->data = ngx_palloc (c->pool,challenge->len);

                if (challenge->data == NULL) {
                    return SASL_FAIL;
                }

                memcpy (challenge->data,"+ ",sizeof("+ ") - 1);
                memcpy (challenge->data+sizeof("+ ")-1,ch64.data,ch64.len);
                memcpy (challenge->data+sizeof("+ ")-1+ch64.len,CRLF,
                        sizeof(CRLF)-1);
            }
            else
            {
                challenge->data = ch64.data;
                challenge->len = ch64.len;
            }
        }
        else  /* SASL_OK */
        {
            ngx_log_debug0 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                "SASL auth negotiation complete");

            authc = NULL;
            authz = NULL;

            sasl_getprop(s->saslconn,SASL_AUTHUSER,(const void **)&authc);
            sasl_getprop(s->saslconn,SASL_USERNAME,(const void **)&authz);

            ngx_log_debug2 (NGX_LOG_DEBUG_MAIL, c->log, 0,
                "sasl: authc=%s,authz=%s",
                authc == NULL ? "null" : authc,
                authz == NULL ? "null" : authz
            );

            /*  authc must always be present
                if authc doesn't end in @realm, then we append the default realm
                from the config file
             */

            /* s->login is authz if present, otherwise it is authc
             */

            if (authc == NULL)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_MAIL,c->log,0,
                    "sasl: cannot get authc, authentication will fail");
                rc = SASL_BADAUTH;
            }
            else
            {
                if (strrchr(authc,'@') == NULL) {
                    needRealm = 1;
                } else {
                    needRealm = 0;
                }

                if ((authz == NULL) || (ngx_strcmp(authc,authz) == 0)) {
                    inheritAuthZ = 1;
                } else {
                    inheritAuthZ = 0;
                }

                len = ngx_strlen(authc);

                if (needRealm) {
                    if (cscf->default_realm.len > 0) {
                        ngx_log_debug1(NGX_LOG_DEBUG_MAIL,c->log,0,
                            "No realm found in AUTHC, using config default %V", &cscf->default_realm);
                        len += (1 + cscf->default_realm.len);
                    } else {
                        ngx_log_error(NGX_LOG_ERR,c->log, 0,
                            "SASL realm required, but no realm found in authenticating principal");
                        ngx_log_error(NGX_LOG_ERR,c->log, 0,
                            "Authentication will fail. Set the `default_realm' variable to the default kerberos realm");
                    }
                }

                s->authid.data = ngx_palloc(c->pool,len);
                if (s->authid.data == NULL) {
                    s->authid.data = (u_char *)"";
                    s->authid.len = 0;
                    rc = SASL_NOMEM;
                } else {
                    s->authid.len = len;
                    p = s->authid.data;
                    p = ngx_cpymem (p,authc,strlen(authc));

                    if (needRealm) {
                        if (cscf->default_realm.len > 0) {
                            *p++ = '@';
                            p = ngx_cpymem (p,cscf->default_realm.data,cscf->default_realm.len);
                        }
                    }
                }

                if (inheritAuthZ) {
                    /* no separate authz was specified, or authz was same as authc
                       therefore the same changes made to authc must apply to authz
                     */
                    s->login.data = ngx_pstrdup(c->pool,&s->authid);
                    if (s->login.data == NULL) {
                        s->login.data = (u_char*)"";
                        s->login.len = 0;
                        rc = SASL_NOMEM;
                    } else {
                        s->login.len = s->authid.len;
                    }
                } else {
                    /* a separate authz was specified */
                    s->login.len  = ngx_strlen(authz);
                    s->login.data = ngx_palloc(c->pool,s->login.len);
                    if (s->login.data == NULL) {
                        s->login.data = (u_char*)"";
                        s->login.len = 0;
                        rc = SASL_NOMEM;
                    } else {
                        ngx_memcpy(s->login.data,authz,s->login.len);
                    }
                }
            }

            if(rc == SASL_OK)
            {
                ngx_log_debug2(NGX_LOG_DEBUG_MAIL,c->log,0,
                    "sasl: auth exchange completed, login:%V, authc:%V", 
                    &s->login, &s->authid);
            }

            /* we don't need the SASL object after authentication because
               we don't negotiate a security layer with any ssf 
             */

            ngx_mail_dispose_sasl_context(s);
        }
    }

    return rc;
}


void
ngx_pop3_auth_state(ngx_event_t *rev)
{
    u_char                    *p, *last, *text;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_str_t                 *arg, salt;
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t       *sslcf;
#endif
    ngx_uint_t                 narg;
    int                        saslrc;
    ngx_str_t                  pchall;

    c = rev->data;
    s = c->data;
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "pop3 auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "pop3 send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_mail_read_command(s);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    text = pop3_ok;
    size = sizeof(pop3_ok) - 1;

    if (rc == NGX_OK) {
        switch (s->mail_state) {

        case ngx_pop3_start:

            switch (s->command) {

            case NGX_POP3_USER:

#if (NGX_MAIL_SSL)
                if (c->ssl == NULL) {
                    sslcf = ngx_mail_get_module_srv_conf(s,ngx_mail_ssl_module);

                    if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY)
                    {
                        // rc = NGX_MAIL_PARSE_INVALID_COMMAND;

                        size = sizeof(pop3_nocleartext)-1;
                        text = pop3_nocleartext;
                        s->mail_state = ngx_pop3_start;
                        s->state = 0;
                        s->arg_start = NULL;    /* ?? redundant ?? */
                        break;
                    }
                }
#endif

                if (s->args.nelts == 1) {
                    s->mail_state = ngx_pop3_user;

                    arg = s->args.elts;
                    s->login.len = arg[0].len;
                    s->login.data = ngx_palloc(c->pool, s->login.len);
                    if (s->login.data == NULL) {
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                    ngx_memcpy(s->login.data, arg[0].data, s->login.len);

                    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                                   "pop3 login: \"%V\"", &s->login);

                    break;
                }

                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;

            case NGX_POP3_CAPA:
#if (NGX_MAIL_SSL)
                if (c->ssl == NULL) {
                    sslcf = ngx_mail_get_module_srv_conf(s,
                                                         ngx_mail_ssl_module);

                    if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
                        size = cscf->pop3_starttls_capability.len;
                        text = cscf->pop3_starttls_capability.data;
                        break;
                    }

                    if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
                        size = cscf->pop3_starttls_only_capability.len;
                        text = cscf->pop3_starttls_only_capability.data;
                        break;
                    }
                }
#endif
                size = cscf->pop3_capability.len;
                text = cscf->pop3_capability.data;
                break;

            case NGX_POP3_APOP:
#if (NGX_MAIL_SSL)
                if (c->ssl == NULL) {
                    sslcf = ngx_mail_get_module_srv_conf(s,
                                                         ngx_mail_ssl_module);

                    if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
                        rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                        break;
                    }
                }
#endif
                if ((cscf->pop3_auth_methods & NGX_MAIL_AUTH_APOP_ENABLED)
                    && s->args.nelts == 2)
                {
                    arg = s->args.elts;

                    s->login.len = arg[0].len;
                    s->login.data = ngx_palloc(c->pool, s->login.len);
                    if (s->login.data == NULL) {
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                    ngx_memcpy(s->login.data, arg[0].data, s->login.len);

                    s->passwd.len = arg[1].len;
                    s->passwd.data = ngx_palloc(c->pool, s->passwd.len);
                    if (s->passwd.data == NULL) {
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                    ngx_memcpy(s->passwd.data, arg[1].data, s->passwd.len);

                    ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
                                   "pop3 apop: \"%V\" \"%V\"",
                                   &s->login, &s->passwd);

                    s->auth_method = NGX_MAIL_AUTH_APOP;

                    s->usedauth = 0;
                    ngx_mail_do_auth(s);
                    return;
                }

                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;

            case NGX_POP3_AUTH:

                if (s->args.nelts == 0) {
                    rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                    break;
                }

                arg = s->args.elts;

                if (arg[0].len == 5) {

                    if (ngx_strncasecmp(arg[0].data, (u_char *) "LOGIN", 5)
                        == 0)
                    {

#if (NGX_MAIL_SSL)
                        if (c->ssl == NULL) {
                            sslcf = ngx_mail_get_module_srv_conf(s,
                                        ngx_mail_ssl_module);

                            if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY)
                            {
                                // rc = NGX_MAIL_PARSE_INVALID_COMMAND;

                                size = sizeof(pop3_nocleartext)-1;
                                text = pop3_nocleartext;
                                s->mail_state = ngx_pop3_start;
                                s->state = 0;
                                s->arg_start = NULL;    /* ?? redundant ?? */
                                break;
                            }
                        }
#endif

                        if (s->args.nelts != 1) {
                            rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                            break;
                        }

                        s->mail_state = ngx_pop3_auth_login_username;

                        size = sizeof(pop3_username) - 1;
                        text = pop3_username;

                        break;

                    }
                    else if(ngx_strncasecmp(arg[0].data,(u_char *)"PLAIN",5)==0)
                    {
                        if (!(cscf->pop3_auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED))
                        {
                            size = sizeof(pop3_unsupported_mech)-1;
                            text = pop3_unsupported_mech;
                            s->mail_state = ngx_pop3_start;
                            s->arg_start = NULL;        /* ?? redundant ?? */
                            s->state = 0;
                            break;
                        }

#if (NGX_MAIL_SSL)
                        if (c->ssl == NULL) {
                            sslcf = ngx_mail_get_module_srv_conf(s,
                                        ngx_mail_ssl_module);

                            if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY)
                            {
                                // rc = NGX_MAIL_PARSE_INVALID_COMMAND;

                                size = sizeof(pop3_nocleartext)-1;
                                text = pop3_nocleartext;
                                s->mail_state = ngx_pop3_start;
                                s->state = 0;
                                s->arg_start = NULL;    /* ?? redundant ?? */
                                break;
                            }
                        }
#endif

                        if (s->args.nelts == 1) {
                            s->mail_state = ngx_pop3_auth_plain;

                            size = sizeof(pop3_next) - 1;
                            text = pop3_next;

                            break;
                        }

                        if (s->args.nelts == 2) {

                            /*
                             * workaround for Eudora for Mac: it sends
                             *    AUTH PLAIN [base64 encoded]
                             */

                            if (arg[1].len == 1 && arg[1].data[0] == '*')
                            {
                                ngx_log_debug0 (NGX_LOG_DEBUG_MAIL,c->log,0,
                                    "auth:abort SASL PLAIN");

                                text = pop3_authaborted;
                                size = sizeof(pop3_authaborted)-1;
                                s->arg_start = NULL;
                                s->mail_state = ngx_pop3_start;
                                s->state = 0;
                                break;
                            }

                            rc = ngx_mail_decode_auth_plain(s, &arg[1]);

                            if (rc == NGX_OK) {
                                s->auth_method = NGX_MAIL_AUTH_PLAIN;
                                ngx_mail_do_auth(s);
                                return;
                            }

                            if (rc == NGX_ERROR) {
                                text = pop3_authaborted;
                                size = sizeof(pop3_authaborted)-1;
                                s->arg_start = NULL;
                                s->mail_state = ngx_pop3_start;
                                s->state = 0;
                                break;
                            }

                            /* rc == NGX_MAIL_PARSE_INVALID_COMMAND */

                            break;
                        }

                        rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                        break;
                    }
                    else
                    {
                        size = sizeof(pop3_unsupported_mech)-1;
                        text = pop3_unsupported_mech;
                        s->mail_state = ngx_pop3_start;
                        s->arg_start = NULL;
                        s->state = 0;
                        break;
                    }
                }
                else if (
                    arg[0].len == 6 &&
                    ngx_strncasecmp(arg[0].data,(u_char *)"GSSAPI",6) == 0
                )
                {
                    if (!(cscf->pop3_auth_methods & NGX_MAIL_AUTH_GSSAPI_ENABLED))
                    {
                        size = sizeof(pop3_unsupported_mech)-1;
                        text = pop3_unsupported_mech;
                        s->mail_state = ngx_pop3_start;
                        s->arg_start = NULL;        /* ?? redundant ?? */
                        s->state = 0;
                        break;
                    }

                    narg = s->args.nelts;

                    if (narg == 1)
                    {
                        s->mail_state = ngx_pop3_auth_gssapi;

                        size = sizeof(pop3_next) - 1;
                        text = pop3_next;

                        break;
                    }

                    /* check if the auth exchange is being aborted */
                    if (narg > 1 && 
                        arg[narg-1].len == 1 &&
                        arg[narg-1].data[0] == '*'
                       )
                    {
                        ngx_log_debug0 (NGX_LOG_DEBUG_MAIL,c->log,0,
                            "auth:abort SASL GSSAPI");

                        ngx_mail_dispose_sasl_context(s);

                        text = pop3_authaborted;
                        size = sizeof(pop3_authaborted)-1;
                        s->mail_state = ngx_pop3_start;
                        s->arg_start = NULL;
                        s->state = 0;
                        break;
                    }

                    saslrc = ngx_mail_initialize_sasl(c);

                    if (saslrc != SASL_OK) {
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                    saslrc = ngx_mail_create_sasl_context (c);

                    if (saslrc != SASL_OK) {
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                    saslrc = ngx_mail_sasl_startstep
                                (c,
                                 "gssapi",
                                 arg+1,
                                 narg-1,
                                 &pchall
                                );

                    if (saslrc == SASL_CONTINUE)
                    {
                        s->mail_state = ngx_pop3_auth_gssapi;
                        text = pchall.data;
                        size = pchall.len;
                        break;
                    }
                    else if (saslrc == SASL_OK)
                    {
                        s->dusr = cscf->master_auth_username;
                        s->dpasswd = cscf->master_auth_password;
                        s->auth_method = NGX_MAIL_AUTH_GSSAPI;
                        s->passwd = krb5_cooked_password;
                        s->usedauth = 1;
                        ngx_mail_do_auth(s);
                        return;
                    }
                    else
                    {
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                } else if (arg[0].len == 8
                           && ngx_strncasecmp(arg[0].data,
                                              (u_char *) "CRAM-MD5", 8)
                              == 0)
                {
                    if (!(cscf->pop3_auth_methods
                          & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)
                        || s->args.nelts != 1)
                    {
                        rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                        break;
                    }

                    s->mail_state = ngx_pop3_auth_cram_md5;

                    text = ngx_palloc(c->pool,
                                      sizeof("+ " CRLF) - 1
                                      + ngx_base64_encoded_length(s->salt.len));
                    if (text == NULL) {
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                    text[0] = '+'; text[1]= ' ';
                    salt.data = &text[2];
                    s->salt.len -= 2;

                    ngx_encode_base64(&salt, &s->salt);

                    s->salt.len += 2;
                    size = 2 + salt.len;
                    text[size++] = CR; text[size++] = LF;

                    break;
                } else {
                    size = sizeof(pop3_unsupported_mech)-1;
                    text = pop3_unsupported_mech;
                    s->mail_state = ngx_pop3_start;
                    s->arg_start = NULL;
                    s->state = 0;
                    break;
                }

                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;

            case NGX_POP3_QUIT:
                s->quit = 1;
                break;

            case NGX_POP3_NOOP:
                break;

#if (NGX_MAIL_SSL)

            case NGX_POP3_STLS:
                if (c->ssl == NULL) {
                    sslcf = ngx_mail_get_module_srv_conf(s,
                                                         ngx_mail_ssl_module);
                    if (sslcf->starttls) {
                        c->read->handler = ngx_mail_starttls_handler;
                        break;
                    }
                }

                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
#endif

            default:
                s->mail_state = ngx_pop3_start;
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case ngx_pop3_user:

            switch (s->command) {

            case NGX_POP3_PASS:
                if (s->args.nelts == 1) {
                    arg = s->args.elts;
                    s->passwd.len = arg[0].len;
                    s->passwd.data = ngx_palloc(c->pool, s->passwd.len);
                    if (s->passwd.data == NULL) {
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                    ngx_memcpy(s->passwd.data, arg[0].data, s->passwd.len);

#if (NGX_DEBUG_MAIL_PASSWD)
                    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                                   "pop3 passwd: \"%V\"", &s->passwd);
#endif

                    s->auth_method = NGX_MAIL_AUTH_PASSWD;
                    s->usedauth = 0;
                    ngx_mail_do_auth(s);
                    return;
                }

                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;

            case NGX_POP3_CAPA:
                size = cscf->pop3_capability.len;
                text = cscf->pop3_capability.data;
                break;

            case NGX_POP3_QUIT:
                s->quit = 1;
                break;

            case NGX_POP3_NOOP:
                break;

            default:
                s->mail_state = ngx_pop3_start;
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        /* suppress warinings */
        case ngx_pop3_passwd:
            break;

        case ngx_pop3_auth_login_username:
            arg = s->args.elts;
            s->mail_state = ngx_pop3_auth_login_password;

            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "pop3 auth login username: \"%V\"", &arg[0]);

            s->login.data = ngx_palloc(c->pool,
                                       ngx_base64_decoded_length(arg[0].len));
            if (s->login.data == NULL){
                ngx_mail_session_internal_server_error(s);
                return;
            }

            if (ngx_decode_base64(&s->login, &arg[0]) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid base64 encoding "
                              "in AUTH LOGIN command");
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "pop3 auth login username: \"%V\"", &s->login);

            size = sizeof(pop3_password) - 1;
            text = pop3_password;

            break;

        case ngx_pop3_auth_login_password:
            arg = s->args.elts;

#if (NGX_DEBUG_MAIL_PASSWD)
            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "pop3 auth login password: \"%V\"", &arg[0]);
#endif

            s->passwd.data = ngx_palloc(c->pool,
                                        ngx_base64_decoded_length(arg[0].len));
            if (s->passwd.data == NULL){
                ngx_mail_session_internal_server_error(s);
                return;
            }

            if (ngx_decode_base64(&s->passwd, &arg[0]) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid base64 encoding "
                              "in AUTH LOGIN command");
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

#if (NGX_DEBUG_MAIL_PASSWD)
            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "pop3 auth login password: \"%V\"", &s->passwd);
#endif

            s->auth_method = NGX_MAIL_AUTH_LOGIN;
            s->usedauth = 0;
            ngx_mail_do_auth(s);
            return;

        case ngx_pop3_auth_plain:
            arg = s->args.elts;

            if (arg[0].len == 1 && arg[0].data[0] == '*')
            {
                ngx_log_debug0 (NGX_LOG_DEBUG_MAIL,c->log,0,
                    "auth:abort SASL PLAIN");

                text = pop3_authaborted;
                size = sizeof(pop3_authaborted)-1;
                s->arg_start = NULL;
                s->mail_state = ngx_pop3_start;
                s->state = 0;
                break;
            }

            rc = ngx_mail_decode_auth_plain(s, &arg[0]);

            if (rc == NGX_OK) {
                s->auth_method = NGX_MAIL_AUTH_PLAIN;
                ngx_mail_do_auth(s);
                return;
            }

            if (rc == NGX_ERROR) {
                text = pop3_authaborted;
                size = sizeof(pop3_authaborted)-1;
                s->arg_start = NULL;
                s->mail_state = ngx_pop3_start;
                s->state = 0;
                break;
            }

            /* rc == NGX_MAIL_PARSE_INVALID_COMMAND */

            break;

        case ngx_pop3_auth_cram_md5:
            arg = s->args.elts;

            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "pop3 auth cram-md5: \"%V\"", &arg[0]);

            s->login.data = ngx_palloc(c->pool,
                                       ngx_base64_decoded_length(arg[0].len));
            if (s->login.data == NULL){
                ngx_mail_session_internal_server_error(s);
                return;
            }

            if (ngx_decode_base64(&s->login, &arg[0]) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid base64 encoding "
                              "in AUTH CRAM-MD5 command");
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            p = s->login.data;
            last = p + s->login.len;

            while (p < last) {
                if (*p++ == ' ') {
                    s->login.len = p - s->login.data - 1;
                    s->passwd.len = last - p;
                    s->passwd.data = p;
                    break;
                }
            }

            if (s->passwd.len != 32) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid CRAM-MD5 hash "
                              "in AUTH CRAM-MD5 command");
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "pop3 auth cram-md5: \"%V\" \"%V\"",
                           &s->login, &s->passwd);

            s->auth_method = NGX_MAIL_AUTH_CRAM_MD5;
            s->usedauth = 0;
            ngx_mail_do_auth(s);
            return;

        case ngx_pop3_auth_gssapi:
            arg = s->args.elts;
            narg = s->args.nelts;

            /* check if the auth exchange is being aborted */
            if (narg > 0 && 
                arg[narg-1].len == 1 &&
                arg[narg-1].data[0] == '*'
               )
            {
                ngx_log_debug0 (NGX_LOG_DEBUG_MAIL,c->log,0,
                    "auth:abort SASL GSSAPI");

                ngx_mail_dispose_sasl_context(s);

                text = pop3_authaborted;
                size = sizeof(pop3_authaborted)-1;
                s->mail_state = ngx_pop3_start;
                s->arg_start = NULL;
                s->state = 0;
                break;
            }

            /* Initialize SASL once per process */
            saslrc = ngx_mail_initialize_sasl (c);

            if (saslrc != SASL_OK) {
                ngx_mail_session_internal_server_error(s);
                return;
            }

            /* create one sasl authentication object per connection */
            saslrc = ngx_mail_create_sasl_context (c);

            if (saslrc != SASL_OK) {
                ngx_mail_session_internal_server_error(s);
                return;
            }

            saslrc = ngx_mail_sasl_startstep (c,"gssapi",arg,narg,&pchall);

            if (saslrc == SASL_CONTINUE)
            {
                s->mail_state = ngx_pop3_auth_gssapi;
                text = pchall.data;
                size = pchall.len;
                break;
            }
            else if (saslrc == SASL_OK)
            {
                s->dusr = cscf->master_auth_username;
                s->dpasswd = cscf->master_auth_password;
                s->auth_method = NGX_MAIL_AUTH_GSSAPI;
                s->passwd = krb5_cooked_password;
                s->usedauth = 1;
                ngx_mail_do_auth(s);
                return;
            }
            else
            {
                ngx_mail_session_internal_server_error(s);
                return;
            }

            break;
        }
    }

    if (rc == NGX_MAIL_PARSE_INVALID_COMMAND) {
        s->mail_state = ngx_pop3_start;
        s->state = 0;
        text = pop3_invalid_command;
        size = sizeof(pop3_invalid_command) - 1;
    }

    s->args.nelts = 0;
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    if (s->state) {
        s->arg_start = s->buffer->start;
    }

    s->out.data = text;
    s->out.len = size;

    ngx_mail_send(c->write);
}


void
ngx_imap_auth_state(ngx_event_t *rev)
{
    u_char                    *p, *last, *text, *dst, *src, *end;
    ssize_t                    text_len, last_len;
    ngx_str_t                 *arg;
    ngx_uint_t                 narg;
    ngx_int_t                  rc;
    ngx_uint_t                 tag, i;
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t       *sslcf;
#endif
    int                        saslrc;
    ngx_str_t                  pchall;

    c = rev->data;
    s = c->data;
    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "imap auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_end_session(s);    /* send IMAP BYE on timeout */
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "imap send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_mail_read_command(s);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    tag = 1;

    text = NULL;
    text_len = 0;

    last = imap_ok;
    last_len = sizeof(imap_ok) - 1;

    if (rc == NGX_OK) {

        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0, "imap auth command: %i",
                       s->command);

        if (s->backslash) {

            arg = s->args.elts;

            for (i = 0; i < s->args.nelts; i++) {
                dst = arg[i].data;
                end = dst + arg[i].len;

                for (src = dst; src < end; dst++) {
                    *dst = *src;
                    if (*src++ == '\\') {
                        *dst = *src++;
                    }
                }

                arg[i].len = dst - arg[i].data;
            }

            s->backslash = 0;
        }

        switch (s->command) {

        case NGX_IMAP_LOGIN:

#if (NGX_MAIL_SSL)

            if (c->ssl == NULL) {
                sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

                if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY)
                {
                    // rc = NGX_MAIL_PARSE_INVALID_COMMAND;

                    last = imap_nocleartext;
                    last_len = sizeof(imap_nocleartext)-1;
                    s->arg_start = NULL;
                    s->state = swi_start;

                    break;
                }
            }
#endif

            arg = s->args.elts;

            if (s->args.nelts == 2 && arg[0].len) {

                s->login.len = arg[0].len;
                s->login.data = ngx_palloc(c->pool, s->login.len);
                if (s->login.data == NULL) {
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->login.data, arg[0].data, s->login.len);

                s->passwd.len = arg[1].len;
                s->passwd.data = ngx_palloc(c->pool, s->passwd.len);
                if (s->passwd.data == NULL) {
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->passwd.data, arg[1].data, s->passwd.len);

#if (NGX_DEBUG_MAIL_PASSWD)
                ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
                               "imap login:\"%V\" passwd:\"%V\"",
                               &s->login, &s->passwd);
#else
                ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                               "imap login:\"%V\"", &s->login);
#endif

                s->auth_method = NGX_MAIL_AUTH_PASSWD;
                s->usedauth = 0;
                ngx_mail_do_auth(s);
                return;
            }

            rc = NGX_MAIL_PARSE_INVALID_COMMAND;
            break;

        case NGX_IMAP_CAPABILITY:
#if (NGX_MAIL_SSL)
            if (c->ssl == NULL) {
                sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

                if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
                    text_len = cscf->imap_starttls_capability.len;
                    text = cscf->imap_starttls_capability.data;
                    break;
                }

                if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
                    text_len = cscf->imap_starttls_only_capability.len;
                    text = cscf->imap_starttls_only_capability.data;
                    break;
                }
            }
#endif
            text_len = cscf->imap_capability.len;
            text = cscf->imap_capability.data;
            break;

        case NGX_IMAP_LOGOUT:
            s->quit = 1;
            text = imap_bye;
            text_len = sizeof(imap_bye) - 1;
            break;

        case NGX_IMAP_NOOP:
            break;

        case NGX_IMAP_ID:
            ngx_log_debug1 (NGX_LOG_DEBUG_MAIL,s->connection->log,0,
                "imap id received %d parameters from client",
                s->args.nelts);
            if (s->args.nelts) {
                ngx_log_debug1 (NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                    "client ID params [%d pair(s)]",
                    s->args.nelts/2);
                for (i=0;i<s->args.nelts/2;++i) {
                    ngx_log_debug3 (NGX_LOG_DEBUG_MAIL,
                        s->connection->log, 0,
                        "[pair %d] field:'%V' value:'%V'",
                        i+1,
                        (ngx_str_t*)s->args.elts +2*i,
                        (ngx_str_t*)s->args.elts +2*i+1
                        );
                }
            }
            text = cscf->imap_id.data;
            text_len = cscf->imap_id.len;
            break;

#if (NGX_MAIL_SSL)

        case NGX_IMAP_STARTTLS:
            if (c->ssl == NULL) {
                sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
                if (sslcf->starttls) {
                    c->read->handler = ngx_mail_starttls_handler;
                    break;
                }
            }

            rc = NGX_MAIL_PARSE_INVALID_COMMAND;
            break;
#endif

        case NGX_IMAP_AUTH:
            arg = s->args.elts;
            narg = s->args.nelts;

            if (s->authmech == ngx_auth_plain && 
                cscf->imap_auth_methods & NGX_MAIL_AUTH_PLAIN_ENABLED
               )
            {
                /* disallow AUTH PLAIN unless cleartext logins are enabled
                   or if we are in TLS/SSL
                 */

#if (NGX_MAIL_SSL)
                if (c->ssl == NULL)
                {
                    sslcf = ngx_mail_get_module_srv_conf(s,ngx_mail_ssl_module);
                    if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY)
                    {
                        last = imap_nocleartext;
                        last_len = sizeof(imap_nocleartext)-1;
                        s->arg_start = NULL;
                        s->state = swi_start;
                        break;
                    }
                }
#endif

                if (narg < 1)
                {
                    tag = 0;
                    rc = NGX_IMAP_NEXT;
                    last = imap_next;
                    last_len = sizeof(imap_next) -1;
                    s->arg_start = s->buffer->pos +1;
                    s->state = swi_saslclientresponse;
                    break;
                }
                else if (arg[0].len == 1 && arg[0].data[0] == '*')
                {
                    ngx_log_debug0 (NGX_LOG_DEBUG_MAIL,c->log,0,
                        "auth:abort SASL PLAIN");
                    last = imap_authaborted;
                    last_len = sizeof(imap_authaborted)-1;
                    s->arg_start = NULL;
                    s->state = swi_start;
                    break;
                }
                else
                {
                    ngx_log_debug1 (NGX_LOG_DEBUG_MAIL,c->log,0,
                        "decoding auth plain response (%d bytes)",
                        arg[0].len);
                    rc = ngx_mail_decode_auth_plain (s, &arg[0]);
                    if (rc == NGX_OK) {
                        s->auth_method = NGX_MAIL_AUTH_PLAIN;
                        ngx_mail_do_auth(s);
                        return;
                    } else {
                        last = imap_authaborted;
                        last_len = sizeof(imap_authaborted)-1;
                        s->arg_start = NULL;
                        s->state = swi_start;
                        rc = NGX_ERROR;
                        break;
                    }
                }
            }
            else if (s->authmech == ngx_auth_gssapi &&
                     cscf->imap_auth_methods & NGX_MAIL_AUTH_GSSAPI_ENABLED
                    )
            {
                /* check if the auth exchange is being aborted */
                if (narg > 0 && 
                    arg[narg-1].len == 1 &&
                    arg[narg-1].data[0] == '*'
                   )
                {
                    ngx_log_debug0 (NGX_LOG_DEBUG_MAIL,c->log,0,
                        "auth:abort SASL GSSAPI");
                    ngx_mail_dispose_sasl_context(s);
                    last = imap_authaborted;
                    last_len = sizeof(imap_authaborted)-1;
                    s->arg_start = NULL;
                    s->state = swi_start;
                    break;
                }


                /* Initialize SASL once per process */
                if (ngx_mail_initialize_sasl(c) != SASL_OK)
                {
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                /* create one sasl authentication object per connection */
                if (ngx_mail_create_sasl_context(c) != SASL_OK)
                {
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                saslrc = ngx_mail_sasl_startstep (c,"gssapi",arg,narg,&pchall);

                if (saslrc == SASL_CONTINUE)
                {
                    last = pchall.data;
                    last_len = pchall.len;
                    tag = 0;
                    s->arg_start = s->buffer->pos;
                    s->state = swi_saslclientresponse;
                    rc = NGX_IMAP_NEXT;
                    break;
                }
                else if (saslrc == SASL_OK)
                {
                    /* start the proxy now */
                    s->dusr = cscf->master_auth_username;
                    s->dpasswd = cscf->master_auth_password;
                    s->auth_method = NGX_MAIL_AUTH_GSSAPI;
                    s->passwd = krb5_cooked_password;
                    s->usedauth = 1;
                    ngx_mail_do_auth(s);
                    return;
                }
                else
                {
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

            }
            else /* fall through */
            {
                ngx_log_debug0 (NGX_LOG_DEBUG_MAIL,c->log,0,
                    "unsupported IMAP auth mechanism");
                last = imap_unsupported_mech;
                last_len = sizeof(imap_unsupported_mech) -1;
                break;
            }

            break;

 
        default:
            rc = NGX_MAIL_PARSE_INVALID_COMMAND;
            break;
        }

    } else if (rc == NGX_IMAP_NEXT) {
        last = imap_next;
        last_len = sizeof(imap_next) - 1;
        tag = 0;
    }

    if (rc == NGX_MAIL_PARSE_INVALID_COMMAND) {
        last = imap_invalid_command;
        last_len = sizeof(imap_invalid_command) - 1;
    }

    if (tag) {
        if (s->tag.len == 0) {
            s->tag.len = sizeof(imap_star) - 1;
            s->tag.data = (u_char *) imap_star;
        }

        if (s->tagged_line.len < s->tag.len + text_len + last_len) {
            s->tagged_line.len = s->tag.len + text_len + last_len;
            s->tagged_line.data = ngx_palloc(c->pool, s->tagged_line.len);
            if (s->tagged_line.data == NULL) {
                ngx_mail_close_connection(c);
                return;
            }
        }

        s->out.data = s->tagged_line.data;
        s->out.len = s->tag.len + text_len + last_len;

        p = s->out.data;

        if (text) {
            p = ngx_cpymem(p, text, text_len);
        }
        p = ngx_cpymem(p, s->tag.data, s->tag.len);
        ngx_memcpy(p, last, last_len);


    } else {
        s->out.data = last;
        s->out.len = last_len;
    }

    if (rc != NGX_IMAP_NEXT) {
        s->args.nelts = 0;
        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;
        s->tag.len = 0;
    }

    ngx_mail_send(c->write);
}


void
ngx_smtp_auth_state(ngx_event_t *rev)
{
    u_char                    *p, *last, *text, ch;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_str_t                 *arg, salt, l;
    ngx_uint_t                 i;
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_core_srv_conf_t  *cscf;
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t       *sslcf;
#endif

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_mail_read_command(s);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    text = NULL;
    size = 0;

    if (rc == NGX_OK) {
        switch (s->mail_state) {

        case ngx_smtp_start:

            switch (s->command) {

            case NGX_SMTP_HELO:
            case NGX_SMTP_EHLO:
                cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

                if (s->args.nelts != 1) {
                    text = smtp_invalid_argument;
                    size = sizeof(smtp_invalid_argument) - 1;
                    s->state = 0;
                    break;
                }

                arg = s->args.elts;

                s->smtp_helo.len = arg[0].len;

                s->smtp_helo.data = ngx_palloc(c->pool, arg[0].len);
                if (s->smtp_helo.data == NULL) {
                    ngx_mail_session_internal_server_error(s);
                    return;
                }

                ngx_memcpy(s->smtp_helo.data, arg[0].data, arg[0].len);

                if (s->command == NGX_SMTP_HELO) {
                    size = cscf->smtp_server_name.len;
                    text = cscf->smtp_server_name.data;

                } else {
                    s->esmtp = 1;
                    size = cscf->smtp_capability.len;
                    text = cscf->smtp_capability.data;
#if (NGX_MAIL_SSL)
                    if (c->ssl == NULL) {
                        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

                        if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
                            size = cscf->smtp_starttls_capability.len;
                            text = cscf->smtp_starttls_capability.data;
                        }

                        if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
                            size = cscf->smtp_starttls_only_capability.len;
                            text = cscf->smtp_starttls_only_capability.data;
                        }
                    }
#endif
                }

                break;

            case NGX_SMTP_AUTH:

#if (NGX_MAIL_SSL)
                if (ngx_mail_starttls_only(s, c)) {
                    rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                    break;
                }
#endif
                if (s->args.nelts == 0) {
                    text = smtp_invalid_argument;
                    size = sizeof(smtp_invalid_argument) - 1;
                    s->state = 0;
                    break;
                }

                arg = s->args.elts;

                if (arg[0].len == 5) {

                    if (ngx_strncasecmp(arg[0].data, (u_char *) "LOGIN", 5)
                        == 0)
                    {

                        if (s->args.nelts != 1) {
                            rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                            break;
                        }

                        s->mail_state = ngx_smtp_auth_login_username;

                        size = sizeof(smtp_username) - 1;
                        text = smtp_username;

                        break;

                    } else if (ngx_strncasecmp(arg[0].data, (u_char *) "PLAIN",
                                               5)
                               == 0)
                    {
                        if (s->args.nelts == 1) {
                            s->mail_state = ngx_smtp_auth_plain;

                            size = sizeof(smtp_next) - 1;
                            text = smtp_next;

                            break;
                        }

                        if (s->args.nelts == 2) {

                            rc = ngx_mail_decode_auth_plain(s, &arg[1]);

                            if (rc == NGX_OK) {
                                s->auth_method = NGX_MAIL_AUTH_PLAIN;
                                ngx_mail_do_auth(s);
                                return;
                            }

                            if (rc == NGX_ERROR) {
                                text = smtp_invalid_argument;
                                size = sizeof(smtp_invalid_argument)-1;
                                s->arg_start = NULL;
                                s->mail_state = ngx_smtp_start;
                                s->state = 0;
                                break;
                            }

                            /* rc == NGX_MAIL_PARSE_INVALID_COMMAND */

                            break;
                        }

                        rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                        break;
                    }

                } else if (arg[0].len == 8
                           && ngx_strncasecmp(arg[0].data,
                                              (u_char *) "CRAM-MD5", 8)
                              == 0)
                {
                    cscf = ngx_mail_get_module_srv_conf(s,
                                                        ngx_mail_core_module);

                    if (!(cscf->smtp_auth_methods
                          & NGX_MAIL_AUTH_CRAM_MD5_ENABLED)
                        || s->args.nelts != 1)
                    {
                        rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                        break;
                    }

                    s->mail_state = ngx_smtp_auth_cram_md5;

                    text = ngx_palloc(c->pool,
                                      sizeof("334 " CRLF) - 1
                                      + ngx_base64_encoded_length(s->salt.len));
                    if (text == NULL) {
                        ngx_mail_session_internal_server_error(s);
                        return;
                    }

                    text[0] = '3'; text[1]= '3'; text[2] = '4'; text[3]= ' ';
                    salt.data = &text[4];
                    s->salt.len -= 2;

                    ngx_encode_base64(&salt, &s->salt);

                    s->salt.len += 2;
                    size = 4 + salt.len;
                    text[size++] = CR; text[size++] = LF;

                    break;
                }

                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;

            case NGX_SMTP_QUIT:
                s->quit = 1;
                text = smtp_bye;
                size = sizeof(smtp_bye) - 1;
                break;

            case NGX_SMTP_MAIL:

                if (s->connection->log->log_level >= NGX_LOG_INFO) {
                    l.len = s->buffer->last - s->buffer->start;
                    l.data = s->buffer->start;

                    for (i = 0; i < l.len; i++) {
                        ch = l.data[i];

                        if (ch != CR && ch != LF) {
                            continue;
                        }

                        l.data[i] = ' ';
                    }

                    while (i) {
                        if (l.data[i - 1] != ' ') {
                            break;
                        }

                        i--;
                    }

                    l.len = i;

                    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                                  "client was rejected: \"%V\"", &l);
                }

                text = smtp_auth_required;
                size = sizeof(smtp_auth_required) - 1;
                break;

            case NGX_SMTP_NOOP:
            case NGX_SMTP_RSET:
                text = smtp_ok;
                size = sizeof(smtp_ok) - 1;
                break;

            case NGX_SMTP_STARTTLS:
#if (NGX_MAIL_SSL)
                if (c->ssl == NULL) {
                    ngx_mail_ssl_conf_t  *sslcf;

                    sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
                    if (sslcf->starttls) {

                        /*
                         * RFC3207 requires us to discard any knowledge
                         * obtained from client before STARTTLS.
                         */

                        s->smtp_helo.len = 0;
                        s->smtp_helo.data = NULL;

                        c->read->handler = ngx_mail_starttls_handler;
                    }
                }

                text = smtp_starttls;
                size = sizeof(smtp_starttls) - 1;
#else
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
#endif
                break;
            }

            break;

        case ngx_smtp_auth_login_username:
            arg = s->args.elts;
            s->mail_state = ngx_smtp_auth_login_password;

            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "smtp auth login username: \"%V\"", &arg[0]);

            s->login.data = ngx_palloc(c->pool,
                                       ngx_base64_decoded_length(arg[0].len));
            if (s->login.data == NULL){
                ngx_mail_session_internal_server_error(s);
                return;
            }

            if (ngx_decode_base64(&s->login, &arg[0]) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid base64 encoding "
                              "in AUTH LOGIN command");
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "smtp auth login username: \"%V\"", &s->login);

            size = sizeof(smtp_password) - 1;
            text = smtp_password;

            break;

        case ngx_smtp_auth_login_password:
            arg = s->args.elts;

#if (NGX_DEBUG_MAIL_PASSWD)
            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "smtp auth login password: \"%V\"", &arg[0]);
#endif

            s->passwd.data = ngx_palloc(c->pool,
                                        ngx_base64_decoded_length(arg[0].len));
            if (s->passwd.data == NULL){
                ngx_mail_session_internal_server_error(s);
                return;
            }

            if (ngx_decode_base64(&s->passwd, &arg[0]) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid base64 encoding "
                              "in AUTH LOGIN command");
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

#if (NGX_DEBUG_MAIL_PASSWD)
            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "smtp auth login password: \"%V\"", &s->passwd);
#endif

            s->auth_method = NGX_MAIL_AUTH_LOGIN;
            s->usedauth = 0;
            ngx_mail_do_auth(s);
            return;

        case ngx_smtp_auth_plain:
            arg = s->args.elts;

            rc = ngx_mail_decode_auth_plain(s, &arg[0]);

            if (rc == NGX_OK) {
                s->auth_method = NGX_MAIL_AUTH_PLAIN;
                ngx_mail_do_auth(s);
                return;
            }

            if (rc == NGX_ERROR) {
                text = smtp_invalid_argument;
                size = sizeof(smtp_invalid_argument)-1;
                s->arg_start = NULL;
                s->mail_state = ngx_smtp_start;
                s->state = 0;
                break;
            }

            /* rc == NGX_MAIL_PARSE_INVALID_COMMAND */

            break;

        case ngx_smtp_auth_cram_md5:
            arg = s->args.elts;

            ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "smtp auth cram-md5: \"%V\"", &arg[0]);

            s->login.data = ngx_palloc(c->pool,
                                       ngx_base64_decoded_length(arg[0].len));
            if (s->login.data == NULL){
                ngx_mail_session_internal_server_error(s);
                return;
            }

            if (ngx_decode_base64(&s->login, &arg[0]) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid base64 encoding "
                              "in AUTH CRAM-MD5 command");
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            p = s->login.data;
            last = p + s->login.len;

            while (p < last) {
                if (*p++ == ' ') {
                    s->login.len = p - s->login.data - 1;
                    s->passwd.len = last - p;
                    s->passwd.data = p;
                    break;
                }
            }

            if (s->passwd.len != 32) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid CRAM-MD5 hash "
                              "in AUTH CRAM-MD5 command");
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
                           "smtp auth cram-md5: \"%V\" \"%V\"",
                           &s->login, &s->passwd);

            s->auth_method = NGX_MAIL_AUTH_CRAM_MD5;

            s->usedauth = 0;
            ngx_mail_do_auth(s);
            return;
        }
    }

    if (rc == NGX_MAIL_PARSE_INVALID_COMMAND) {
        s->mail_state = ngx_smtp_start;
        s->state = 0;
        text = smtp_invalid_command;
        size = sizeof(smtp_invalid_command) - 1;
    }

    s->args.nelts = 0;
    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    if (s->state) {
        s->arg_start = s->buffer->start;
    }

    s->out.data = text;
    s->out.len = size;

    ngx_mail_send(c->write);
}

/* Decode an SASL PLAIN challenge (RFC 4616)
   If AUTHZ is empty:
    set s->usedauth = 0, 
    set s->login = AUTHC
   If AUTHZ is present:
    set s->usedauth = 1
    set s->dusr = AUTHC
    set s->login = AUTHZ
 */
static ngx_int_t
ngx_mail_decode_auth_plain(ngx_mail_session_t *s, ngx_str_t *encoded)
{
    u_char     *p, *last;
    ngx_str_t   plain, temp;

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth plain: \"%V\"", encoded);
#endif

    plain.data = ngx_palloc(s->connection->pool,
                            ngx_base64_decoded_length(encoded->len));
    if (plain.data == NULL){
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&plain, encoded) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "client sent invalid base64 encoding "
                      "in AUTH PLAIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    p = plain.data;
    last = p + plain.len;

    while (p < last && *p++) { /* void */ }

    if (p == last) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "client sent invalid login in AUTH PLAIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    s->dusr.data = plain.data;
    s->dusr.len = p - plain.data - 1;

    s->login.data = p;

    while (p < last && *p) { p++; }

    if (p == last) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "client sent invalid password in AUTH PLAIN command");
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = p++ - s->login.data;

    s->passwd.len = last - p;
    s->passwd.data = p;

#if (NGX_DEBUG_MAIL_PASSWD)
    ngx_log_debug2(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth plain: \"%V\" \"%V\"",
                   &s->login, &s->passwd);
#endif

    if (s->dusr.len == 0) {
        /* s->dusr = s->login; */
        s->usedauth = 0;
    } else {
        s->usedauth = 1;
        temp = s->dusr;
        s->dusr = s->login;
        s->login = temp;
    }

    s->dpasswd = s->passwd;
    return NGX_OK;
}


static void
ngx_mail_do_auth(ngx_mail_session_t *s)
{
    throttle_callback_t         *callback;
    ngx_connection_t            *c;
    ngx_mail_throttle_srv_conf_t    *tscf;

    c = s->connection;
    tscf = ngx_mail_get_module_srv_conf(s, ngx_mail_throttle_module);

    /* all auth mechanisms for all protocols pass through ngx_mail_do_auth()
       here. Therefore, it is best to just look at the zimbra extensions 
       *once* at this point, rather than peppering that code all across 
     */

    if (has_zimbra_extensions(s->login)) {
        s->zlogin = get_zimbra_extension(s->login);
        s->login.len -= s->zlogin.len;
    } else {
        s->zlogin.data = (u_char *)"";
        s->zlogin.len = 0;
    }

    if (s->usedauth)
    {
        if (has_zimbra_extensions(s->dusr)) {
            s->zusr = get_zimbra_extension(s->dusr);
            s->dusr.len -= s->zusr.len;
        } else {
            s->zusr.data = (u_char *)"";
            s->zusr.len = 0;
        }
    }

    if (s->usedauth) {
        /* technically, zimbra extensions are not allowed in authc
           but it is too troublesome to reject the login appropriately
           at this point (with the correct message), therefore it is 
           less bother to just pass the authc + {wm,ni,tb} to upstream
         */
        if (s->login.len == s->dusr.len &&
            ngx_memcmp(s->login.data, s->dusr.data, s->login.len) == 0) {
            s->qualifydauth = 1;
        }
    }

    callback = ngx_pcalloc(c->pool, sizeof(throttle_callback_t));
    if (callback == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    callback->check_only = 1;    /* just check the counter's value */
    callback->session = s;
    callback->connection = c;
    callback->log = ngx_cycle->log;
    callback->pool = c->pool;
    callback->on_allow = ngx_mail_allow_userauth;
    callback->on_deny = ngx_mail_choke_userauth;

    /* because of DOS attacks against legitimate users, throttling is 
       postponed till after authentication
     */
    tscf = ngx_mail_get_module_srv_conf (s, ngx_mail_throttle_module);
    if (tscf->mail_login_user_max == 0) {
        callback->on_allow(callback);
    } else {
        ngx_mail_throttle_user(s->login, callback);
    }

    /* previous body of ngx_mail_do_auth() now in ngx_mail_allow_userauth */
}


static ngx_int_t
ngx_mail_read_command(ngx_mail_session_t *s)
{
    ssize_t    n;
    ngx_int_t  rc;
    ngx_str_t  l;

    n = s->connection->recv(s->connection, s->buffer->last,
                            s->buffer->end - s->buffer->last);

    if (n == NGX_ERROR) {
        ngx_mail_close_connection(s->connection);
        return NGX_ERROR;
    }

    if (n == 0) {
        /* orderly shutdown per recv(2) */
        ngx_mail_end_session(s);
        return NGX_ERROR;
    }

    if (n > 0) {
        s->buffer->last += n;
    }

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(s->connection->read, 0) == NGX_ERROR) {
            ngx_mail_session_internal_server_error(s);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    switch (s->protocol) {
    case NGX_MAIL_POP3_PROTOCOL:
        rc = ngx_pop3_parse_command(s);
        break;

    case NGX_MAIL_IMAP_PROTOCOL:
        rc = ngx_imap_parse_command(s);
        break;

    default: /* NGX_MAIL_SMTP_PROTOCOL */
        rc = ngx_smtp_parse_command(s);
        break;
    }

    if (rc == NGX_AGAIN) {

        if (s->buffer->last < s->buffer->end) {
            return rc;
        }

        l.len = s->buffer->last - s->buffer->start;
        l.data = s->buffer->start;

        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "client sent too long command \"%V\"", &l);

        s->quit = 1;

        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    if (rc == NGX_IMAP_NEXT || rc == NGX_MAIL_PARSE_INVALID_COMMAND) {
        return rc;
    }

    if (rc == NGX_ERROR) {
        ngx_mail_close_connection(s->connection);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* send a protocol-suitable internal error message to downstream
   close the downstream connection immediately afterwards
 */
void
ngx_mail_session_internal_server_error(ngx_mail_session_t *s)
{
    ngx_str_t            err = ngx_mail_session_geterrmsg(s);
    ngx_connection_t    *c;
    
    c = s->connection;

    c->send(c, err.data, err.len);

    /* clean up */
    ngx_mail_cleanup_t * cln = s->cleanup;
    while (cln != NULL) {
        cln->handler(cln->data);
        cln = cln->next;
    }

    ngx_mail_close_connection (c);
}

/* send a protocol-suitable bye message to downstream
   close the downstream connection immediately afterwards
 */
void
ngx_mail_end_session(ngx_mail_session_t *s)
{
    ngx_str_t            bye = ngx_mail_session_getquitmsg(s);
    ngx_connection_t    *c = s->connection;

    if (bye.len > 0) {
        c->send(c, bye.data, bye.len);
    }

    /* clean up */
    ngx_mail_cleanup_t * cln = s->cleanup;
    while (cln != NULL) {
        cln->handler(cln->data);
        cln = cln->next;
    }

    ngx_mail_close_connection (c);
}

/* return protocol-specific bye message */
ngx_str_t ngx_mail_session_getquitmsg(ngx_mail_session_t *s)
{
    return quitmsgs[s->protocol];
}

/* return protocol-specific internal error message */
ngx_str_t ngx_mail_session_geterrmsg(ngx_mail_session_t *s)
{
    return internal_server_errors[s->protocol];
}


void
ngx_mail_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "close mail connection: %d", c->fd);

#if (NGX_MAIL_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_mail_close_connection;
            return;
        }
    }

#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}

/* note -- we want to log the local and remote host/port information for the 
   mail proxy sessions. however, nginx allows a mail servers to be specified as
   listening on a unix domain socket. the code below assumes that the sockaddr
   structure is pointing to an IPv4 address, and prints the address information
   accordingly. we will need to modify the code in case we want to support
   printing of unix domain socket information 
 */

static u_char *
ngx_mail_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_mail_session_t  *s;
    ngx_mail_log_ctx_t  *ctx;
    struct sockaddr_in   dw_host, dw_peer,
                         up_host, up_peer;
    socklen_t            dw_host_len, dw_peer_len,
                         up_host_len, up_peer_len;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    dw_peer_len = sizeof(struct sockaddr_in);
    dw_host_len = sizeof(struct sockaddr_in);
    up_host_len = sizeof(struct sockaddr_in);
    up_peer_len = sizeof(struct sockaddr_in);

    ngx_memzero (&dw_peer, sizeof (struct sockaddr_in));
    ngx_memzero (&dw_host, sizeof (struct sockaddr_in));
    ngx_memzero (&up_host, sizeof (struct sockaddr_in));
    ngx_memzero (&up_peer, sizeof (struct sockaddr_in));

    if (s->connection) {
        getpeername 
            (s->connection->fd, (struct sockaddr *)&dw_peer, &dw_peer_len);
        getsockname 
            (s->connection->fd, (struct sockaddr *)&dw_host, &dw_host_len);
    }

    p = ngx_snprintf(buf, len, "%s, server: %V",
                     s->starttls ? " using starttls" : "",
                     s->addr_text);
    len -= p - buf;
    buf = p;

    if (s->login.len == 0) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", login: \"%V\"", &s->login);
    len -= p - buf;
    buf = p;

    if (s->proxy == NULL) {
        return p;
    }

    if (s->proxy->upstream.connection) {
        getsockname (s->proxy->upstream.connection->fd,
            (struct sockaddr *)&up_host, &up_host_len);
        getpeername (s->proxy->upstream.connection->fd,
            (struct sockaddr *)&up_peer, &up_peer_len);
    }

    p = ngx_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);
    len -= p - buf;
    buf = p;

    p = ngx_snprintf(buf, len,
        ", [%d.%d.%d.%d:%d-%d.%d.%d.%d:%d] <=> [%d.%d.%d.%d:%d-%d.%d.%d.%d:%d]",
        (((u_char *)&dw_peer.sin_addr.s_addr)[0]),
        (((u_char *)&dw_peer.sin_addr.s_addr)[1]),
        (((u_char *)&dw_peer.sin_addr.s_addr)[2]),
        (((u_char *)&dw_peer.sin_addr.s_addr)[3]),
        htons(dw_peer.sin_port),
        (((u_char *)&dw_host.sin_addr.s_addr)[0]),
        (((u_char *)&dw_host.sin_addr.s_addr)[1]),
        (((u_char *)&dw_host.sin_addr.s_addr)[2]),
        (((u_char *)&dw_host.sin_addr.s_addr)[3]),
        htons(dw_host.sin_port),
        (((u_char *)&up_host.sin_addr.s_addr)[0]),
        (((u_char *)&up_host.sin_addr.s_addr)[1]),
        (((u_char *)&up_host.sin_addr.s_addr)[2]),
        (((u_char *)&up_host.sin_addr.s_addr)[3]),
        htons(up_host.sin_port),
        (((u_char *)&up_peer.sin_addr.s_addr)[0]),
        (((u_char *)&up_peer.sin_addr.s_addr)[1]),
        (((u_char *)&up_peer.sin_addr.s_addr)[2]),
        (((u_char *)&up_peer.sin_addr.s_addr)[3]),
        htons(up_peer.sin_port)
        );

    return p;
}

/* stringify the local IPv4 address of a connected IPv4 socket
   return "255.255.255.255" if the socket address family is not IPv4
 */
ngx_str_t ngx_mail_get_local_addr4 (ngx_pool_t *pool, ngx_socket_t fd)
{
    static ngx_str_t    fallback = ngx_string("255.255.255.255");
    ngx_str_t           ip;
    struct sockaddr_in  sin;
    socklen_t           len;

    len = sizeof(sin);
    ngx_memzero(&sin,len);
    getsockname(fd,(struct sockaddr*)&sin,&len);

    if (((struct sockaddr*)&sin)->sa_family != AF_INET) {   /* only IPv4 */
        ip = fallback;
    } else {
        ip.len = serialize_addr_ipv4(NULL,&sin);
        ip.data = ngx_palloc(pool,ip.len);
        if (ip.data == NULL) {
            ip = fallback;
        } else {
            serialize_addr_ipv4(ip.data,&sin);
        }
    }

    return ip;
}


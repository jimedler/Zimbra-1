
/*
 * Copyright (C) Igor Sysoev
 */

/*
 * Portions Copyright (c) VMware, Inc. [1998-2011]. All Rights Reserved.
 */


#ifndef _NGX_MAIL_H_INCLUDED_
#define _NGX_MAIL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#if (NGX_MAIL_SSL)
#include <ngx_mail_ssl_module.h>
#endif

#include <sasl/sasl.h>

typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} ngx_mail_conf_ctx_t;


typedef struct {
    in_addr_t               addr;
    in_port_t               port;
    int                     family;

    /* server ctx */
    ngx_mail_conf_ctx_t    *ctx;

    unsigned                bind:1;
} ngx_mail_listen_t;


typedef struct {
    in_addr_t               addr;
    ngx_mail_conf_ctx_t    *ctx;
    ngx_str_t               addr_text;
} ngx_mail_in_addr_t;


typedef struct {
    ngx_mail_in_addr_t     *addrs;       /* array of ngx_mail_in_addr_t */
    ngx_uint_t              naddrs;
} ngx_mail_in_port_t;


typedef struct {
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_mail_conf_in_addr_t */
} ngx_mail_conf_in_port_t;


typedef struct {
    in_addr_t               addr;
    ngx_mail_conf_ctx_t    *ctx;
    unsigned                bind:1;
} ngx_mail_conf_in_addr_t;


typedef struct {
    ngx_array_t             servers;     /* ngx_mail_core_srv_conf_t */
    ngx_array_t             listen;      /* ngx_mail_listen_t */
} ngx_mail_core_main_conf_t;


#define NGX_MAIL_POP3_PROTOCOL  0
#define NGX_MAIL_IMAP_PROTOCOL  1
#define NGX_MAIL_SMTP_PROTOCOL  2

typedef struct ngx_mail_protocol_s  ngx_mail_protocol_t;

typedef struct {
    ngx_msec_t              timeout;

    size_t                  imap_client_buffer_size;
    size_t                  pop3_client_buffer_size;

    ngx_uint_t              protocol;

    ngx_flag_t              so_keepalive;

    ngx_str_t               pop3_capability;
    ngx_str_t               pop3_starttls_capability;
    ngx_str_t               pop3_starttls_only_capability;
    ngx_str_t               pop3_auth_capability;

    ngx_str_t               imap_capability;
    ngx_str_t               imap_starttls_capability;
    ngx_str_t               imap_starttls_only_capability;

    ngx_str_t               smtp_capability;
    ngx_str_t               smtp_starttls_capability;
    ngx_str_t               smtp_starttls_only_capability;

    ngx_str_t               server_name;
    ngx_str_t               smtp_server_name;

    ngx_str_t               smtp_greeting;
    ngx_str_t               imap_greeting;
    ngx_str_t               pop3_greeting;

    ngx_str_t               greetings[3];

    ngx_uint_t              pop3_auth_methods;
    ngx_uint_t              imap_auth_methods;
    ngx_uint_t              smtp_auth_methods;

    ngx_array_t             pop3_capabilities;
    ngx_array_t             imap_capabilities;
    ngx_array_t             smtp_capabilities;

    ngx_array_t             imap_id_params;
    ngx_str_t               imap_id;

    ngx_str_t               master_auth_username;
    ngx_str_t               master_auth_password;

    ngx_str_t               sasl_app_name;
    ngx_str_t               sasl_service_name;

    ngx_flag_t              imap_literalauth;
    ngx_msec_t              auth_wait_intvl;

    ngx_str_t               default_realm;
    u_char                 *file_name;
    ngx_int_t               line;

    /* server ctx */
    ngx_mail_conf_ctx_t    *ctx;

    ngx_flag_t              sasl_host_from_ip;

} ngx_mail_core_srv_conf_t;


typedef struct {
    void                 *(*create_main_conf)(ngx_conf_t *cf);
    char                 *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                 *(*create_srv_conf)(ngx_conf_t *cf);
    char                 *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                void *conf);
} ngx_mail_module_t;


typedef enum {
    ngx_pop3_start = 0,
    ngx_pop3_xoip,
    ngx_pop3_user,
    ngx_pop3_passwd,
    ngx_pop3_auth_login_username,
    ngx_pop3_auth_login_password,
    ngx_pop3_auth_plain,
    ngx_pop3_auth_plain_response,
    ngx_pop3_auth_cram_md5,
    ngx_pop3_auth_gssapi
} ngx_po3_state_e;


typedef enum {
    ngx_imap_start = 0,
    ngx_imap_id,
    ngx_imap_login,
    ngx_imap_user,
    ngx_imap_passwd,
    ngx_imap_authplain,
    ngx_imap_authplain_ir
} ngx_imap_state_e;

/* imap parser state */
typedef enum {
    swi_start = 0,
    swi_spaces_before_command,
    swi_command,
    swi_spaces_before_argument,
    swi_argument,
    swi_backslash,
    swi_literal,
    swi_no_sync_literal_argument,
    swi_start_literal_argument,
    swi_literal_argument,
    swi_end_literal_argument,
    swi_id_n,
    swi_id_ni,
    swi_id_nil,
    swi_begin_idparams,
    swi_end_idparams,
    swi_done_idparams,
    swi_begin_idfield,
    swi_idfield,
    swi_idfield_len,
    swi_idfield_len_plus,
    swi_begin_idfield_l,
    swi_idfield_l,
    swi_SP_before_idvalue,
    swi_X_before_idfield,
    swi_begin_idvalue,
    swi_idvalue,
    swi_idvalue_n,
    swi_idvalue_ni,
    swi_idvalue_nil,
    swi_idvalue_len,
    swi_idvalue_len_plus,
    swi_begin_idvalue_l,
    swi_idvalue_l,
    swi_spaces_before_saslmech,
    swi_saslmech,
    /* swi_end_saslmech, */
    /* swi_start_saslclientresponse, */
    swi_saslclientIresponse,
    swi_saslclientresponse,
    swi_almost_next,
    swi_almost_done
} ngx_imap_parse_e;

typedef enum {
    ngx_smtp_start = 0,
    ngx_smtp_auth_login_username,
    ngx_smtp_auth_login_password,
    ngx_smtp_auth_plain,
    ngx_smtp_auth_cram_md5,
    ngx_smtp_helo,
    ngx_smtp_noxclient,
    ngx_smtp_xclient
} ngx_smtp_state_e;

/* sasl auth mechanisms */
typedef enum {
    ngx_auth_unknown = 0,
    ngx_auth_plain,
    ngx_auth_gssapi
} ngx_auth_e;

typedef struct {
    ngx_peer_connection_t   upstream;
    ngx_buf_t              *buffer;
} ngx_mail_proxy_ctx_t;

typedef void (*ngx_mail_cleanup_pt)(void *data);

typedef struct ngx_mail_cleanup_s  ngx_mail_cleanup_t;

struct ngx_mail_cleanup_s {
    ngx_mail_cleanup_pt               handler;
    void                             *data;
    ngx_mail_cleanup_t               *next;
};

typedef struct {
    uint32_t                signature;         /* "MAIL" */

    ngx_connection_t       *connection;

    ngx_str_t               out;
    ngx_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    ngx_mail_proxy_ctx_t   *proxy;

    ngx_uint_t              mail_state;

    unsigned                protocol:3;
    unsigned                blocked:1;
    unsigned                quit:1;
    unsigned                quoted:1;
    unsigned                backslash:1;
    unsigned                no_sync_literal:1;
    unsigned                starttls:1;
    unsigned                esmtp:1;
    unsigned                auth_method:4;
    unsigned                auth_wait:1;
    unsigned                sendquitmsg:1;
    unsigned                vlogin:2; /* vlogin = 0 fqdn is not looked up;
                                         vlogin = 1 fqdn has been looked up but not found;
                                         vlogin = 2 fqdn has been looke up and assigned to "login"
                                       */

    ngx_str_t               login;  /* keep the original user input login initially;
                                       after the success route lookup or alias lookup,
                                       it will become the fqn returned with the header
                                        'Auth-User' */

    ngx_str_t               qlogin; /* initially equal to 'login', but hold fqn when
                                       alias cache fetch succeeds */
    ngx_str_t               zlogin;
    ngx_str_t               passwd;

    ngx_str_t               salt;
    ngx_str_t               tag;
    ngx_str_t               tagged_line;
    ngx_str_t               text;

    ngx_str_t              *addr_text;
    ngx_str_t               smtp_helo;

    ngx_uint_t              command;
    ngx_array_t             args;

    ngx_uint_t              login_attempt;

    /* used to parse POP3/IMAP/SMTP command */

    ngx_uint_t              state;
    u_char                 *cmd_start;
    u_char                 *arg_start;
    u_char                 *arg_end;
    ngx_uint_t              literal_len;
    ngx_uint_t              eargs;          /* expected #args for command */

    /* SASL */
    ngx_flag_t              usedauth;
    ngx_flag_t              qualifydauth;
    ngx_str_t               dusr;
    ngx_str_t               zusr;
    ngx_str_t               dpasswd;
    ngx_auth_e              authmech;
    ngx_flag_t              saslfr;
    sasl_conn_t            *saslconn;
    ngx_str_t               authid;         /* SASL authenticating user */

    /* memcache keys */
    ngx_str_t               key_alias;
    ngx_str_t               key_route;

    /* clean up */
    ngx_mail_cleanup_t    *cleanup;

} ngx_mail_session_t;


typedef struct {
    ngx_str_t              *client;
    ngx_mail_session_t     *session;
} ngx_mail_log_ctx_t;


#define NGX_POP3_USER          1
#define NGX_POP3_PASS          2
#define NGX_POP3_CAPA          3
#define NGX_POP3_QUIT          4
#define NGX_POP3_NOOP          5
#define NGX_POP3_STLS          6
#define NGX_POP3_APOP          7
#define NGX_POP3_AUTH          8
#define NGX_POP3_STAT          9
#define NGX_POP3_LIST          10
#define NGX_POP3_RETR          11
#define NGX_POP3_DELE          12
#define NGX_POP3_RSET          13
#define NGX_POP3_TOP           14
#define NGX_POP3_UIDL          15


#define NGX_IMAP_LOGIN         1
#define NGX_IMAP_LOGOUT        2
#define NGX_IMAP_CAPABILITY    3
#define NGX_IMAP_NOOP          4
#define NGX_IMAP_STARTTLS      5
#define NGX_IMAP_ID            6
#define NGX_IMAP_AUTH          7

#define NGX_IMAP_NEXT          8


#define NGX_SMTP_HELO          1
#define NGX_SMTP_EHLO          2
#define NGX_SMTP_AUTH          3
#define NGX_SMTP_QUIT          4
#define NGX_SMTP_NOOP          5
#define NGX_SMTP_MAIL          6
#define NGX_SMTP_RSET          7
#define NGX_SMTP_RCPT          8
#define NGX_SMTP_DATA          9
#define NGX_SMTP_VRFY          10
#define NGX_SMTP_EXPN          11
#define NGX_SMTP_HELP          12
#define NGX_SMTP_STARTTLS      13


#define NGX_MAIL_AUTH_PASSWD    0
#define NGX_MAIL_AUTH_PLAIN     1
#define NGX_MAIL_AUTH_LOGIN     2
#define NGX_MAIL_AUTH_APOP      3
#define NGX_MAIL_AUTH_CRAM_MD5  4
#define NGX_MAIL_AUTH_GSSAPI    5


#define NGX_MAIL_AUTH_PLAIN_ENABLED     0x0002
#define NGX_MAIL_AUTH_LOGIN_ENABLED     0x0004
#define NGX_MAIL_AUTH_APOP_ENABLED      0x0008
#define NGX_MAIL_AUTH_CRAM_MD5_ENABLED  0x0010
#define NGX_MAIL_AUTH_GSSAPI_ENABLED    0x0020


#define NGX_MAIL_PARSE_INVALID_COMMAND  20


#define NGX_MAIL_MODULE      0x4C49414D     /* "MAIL" */

#define NGX_MAIL_MAIN_CONF   0x02000000
#define NGX_MAIL_SRV_CONF    0x04000000


#define NGX_MAIL_MAIN_CONF_OFFSET  offsetof(ngx_mail_conf_ctx_t, main_conf)
#define NGX_MAIL_SRV_CONF_OFFSET   offsetof(ngx_mail_conf_ctx_t, srv_conf)


#define ngx_mail_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_mail_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_mail_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_mail_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_mail_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define ngx_mail_conf_get_module_main_conf(cf, module)                       \
    ((ngx_mail_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]


void ngx_mail_init_connection(ngx_connection_t *c);
void ngx_mail_send(ngx_event_t *wev);
void ngx_pop3_auth_state(ngx_event_t *rev);
void ngx_imap_auth_state(ngx_event_t *rev);
void ngx_smtp_auth_state(ngx_event_t *rev);
void ngx_mail_close_connection(ngx_connection_t *c);
void ngx_mail_session_internal_server_error(ngx_mail_session_t *s);
void ngx_mail_end_session(ngx_mail_session_t *s);
ngx_str_t ngx_mail_session_getquitmsg(ngx_mail_session_t *s);
ngx_str_t ngx_mail_session_geterrmsg(ngx_mail_session_t *s);
ngx_str_t ngx_mail_get_local_addr4 (ngx_pool_t *pool, ngx_socket_t fd);

ngx_int_t ngx_pop3_parse_command(ngx_mail_session_t *s);
ngx_int_t ngx_imap_parse_command(ngx_mail_session_t *s);
ngx_int_t ngx_smtp_parse_command(ngx_mail_session_t *s);

void ngx_mail_proxy_init(ngx_mail_session_t *s, ngx_peer_addr_t *peer);
void ngx_mail_auth_http_init(ngx_mail_session_t *s);
void ngx_mail_auth_http_delete_cached_route_and_fqdn(ngx_mail_session_t *s);
ngx_mail_cleanup_t * ngx_mail_cleanup_add(ngx_mail_session_t * s, size_t size);

extern ngx_uint_t    ngx_mail_max_module;
extern ngx_module_t  ngx_mail_core_module;

#endif /* _NGX_MAIL_H_INCLUDED_ */

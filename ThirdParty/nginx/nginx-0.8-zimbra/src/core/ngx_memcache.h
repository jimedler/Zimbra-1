#ifndef _NGX_MEMCACHE_H_INCLUDED_
#define _NGX_MEMCACHE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#define NGX_MEMCACHE_CONF        0x02000000

typedef struct {
    ngx_pool_t      *cpool;         /* main pool where self resides */
    ngx_log_t       *log;
    ngx_array_t     contexts;       /* mc_context_t[] */
    ngx_array_t     servers;        /* ngx_addr_t*[] */
    ngx_msec_t      timeout;
    ngx_msec_t      reconnect;
    ngx_msec_t      ttl;
    ngx_flag_t      allow_unqualified;
} ngx_memcache_conf_t;

/* supported memcache request codes */
typedef enum {
    mcreq_noop,
    mcreq_get,
    mcreq_add,
    mcreq_delete,
    mcreq_incr,
    mcreq_decr
} mc_request_code_t;

/* memcache response codes */
typedef enum {
    mcres_unknown,
    mcres_success,
    mcres_failure_normal,     /* memcached server response with failure info,
                                 such as NOT_FOUND, NOT_STORED, ...             */
    mcres_failure_again,      /* failures that might be recovered by retry, such as
                                 one of many memcached servers is down; or the
                                 message replied can't be parsed correctly      */
    mcres_failure_unavailable /* failures of no memcache servers are available,
                                 or other failures that make memcache service
                                 unavailable                                    */
} mc_response_code_t;

/* memcache channel status */
typedef enum {
    mcchan_good,
    mcchan_bad,
    mcchan_reconnect /* temp status in reconnection */
} mc_channel_status_t;

/* additional data returned by a memcache operation */
typedef ngx_str_t mc_data_t;

struct mc_work_s;
/* prototype for sucess/failure handler */
typedef void (*mc_chain_handler) (struct mc_work_s *w);

/* workqueue entry representing an outstanding memcache request
 */

struct mc_work_s
{
    mc_request_code_t   request_code;   /* op request code */
    mc_response_code_t  response_code;  /* op response status */
    void               *ctx;           /* op context */
    mc_data_t           payload;        /* op response payload */
    mc_chain_handler    on_success;     /* success handler */
    mc_chain_handler    on_failure;     /* failure handler */
};

typedef struct mc_work_s mc_work_t;


/* a queue of memcache entries representing all outstanding memcache 
   requests for a particular connection to a memcache server
 */

typedef struct mc_workqueue_s mc_workqueue_t;

struct mc_workqueue_s {
    mc_work_t           w;              /* payload of the workqueue entry */
    ngx_pool_t          *pool;          /* pool in which this node resides */
    ngx_flag_t          reclaim;        /* reclaim the pool? (default:0) */
    mc_workqueue_t      *prev;          /* previous node in the queue */
    mc_workqueue_t      *next;          /* next node in the queue */
};

/* a `memcache context' data structure that completely represents the 
   state of a particular connection to a memcached server
 */

typedef struct {
    ngx_buf_t               *readbuffer;    /* circular buffer for recv() */
    mc_workqueue_t          wq_head;        /* head of outstanding requests */
    ngx_addr_t              *srvaddr;       /* address of memcached server */
    ngx_peer_connection_t   *srvconn;       /* active connection to server */
    mc_channel_status_t     status;         /* connection status */
    ngx_msec_t              timeout;        /* read/write timeout */
    ngx_msec_t              cxn_interval;   /* timeout for reconnection */
    ngx_event_t             *reconnect_ev;  /* event for reconnection */
    ngx_atomic_t            lock;           /* concurrent access lock */
} mc_context_t;

/* Functions to manipulate the memcache work queue */
mc_workqueue_t *ngx_memcache_wq_enqueue (mc_workqueue_t *head, mc_workqueue_t *wq);
mc_workqueue_t *ngx_memcache_wq_dequeue (mc_workqueue_t *head);

/* Post a memcache operation request onto an available channel */
void ngx_memcache_post (
     mc_work_t      *w,
     ngx_str_t       k,
     ngx_str_t       pdu,
     ngx_pool_t     *p,
     ngx_log_t      *l
    );

/* zimbra utility functions */
ngx_flag_t  has_zimbra_extensions   (ngx_str_t l);
ngx_str_t   strip_zimbra_extensions (ngx_str_t l);
ngx_str_t   get_zimbra_extension    (ngx_str_t l);

/* get configuration */
ngx_memcache_conf_t *ngx_memcache_get_conf();

/* Cache key routines */
ngx_str_t   ngx_memcache_get_route_key (
    ngx_pool_t      *pool,
    ngx_log_t       *log,
    ngx_str_t        proto,
    ngx_str_t        user,
    ngx_str_t        ip,
    ngx_flag_t       qualified,
    ngx_flag_t       allowpartial
);

ngx_str_t   ngx_memcache_get_alias_key (
    ngx_pool_t      *pool,
    ngx_log_t       *log,
    ngx_str_t        user,
    ngx_str_t        ip
);

ngx_str_t   ngx_memcache_get_user_throttle_key (
    ngx_pool_t      *pool,
    ngx_log_t       *log,
    ngx_str_t        user
);

ngx_str_t   ngx_memcache_get_ip_throttle_key (
    ngx_pool_t      *pool,
    ngx_log_t       *log,
    ngx_str_t        ip
);

ngx_str_t   ngx_memcache_get_http_alias_key (
    ngx_pool_t          *pool,
    ngx_log_t           *log,
    ngx_str_t            user,
    ngx_str_t            vhost
);

ngx_str_t   ngx_memcache_get_http_route_key (
    ngx_pool_t      *pool,
    ngx_log_t       *log,
    ngx_str_t        user
);

ngx_str_t   ngx_memcache_get_http_id_route_key (
    ngx_pool_t      *pool,
    ngx_log_t       *log,
    ngx_str_t        id
);


#endif

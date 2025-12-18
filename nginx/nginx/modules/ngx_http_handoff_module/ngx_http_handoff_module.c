#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <net/if_arp.h>

#include <sys/ipc.h>
#include <sys/shm.h>

#include "util.h"
#include "handoff.h"
#include "http_client.h"
#include "ngx_http_handoff_module.h"

#include "connect.h"
#include "handoff_in.h"
#include "handoff_out.h"

static char *ngx_http_handoff_set_frequency(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_handoff_set_target(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_handoff_set_ifname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_handoff_out(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_handoff_in(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_handoff_create_main_conf(ngx_conf_t *cf);

static ngx_command_t ngx_http_handoff_commands[] = {
    { ngx_string("handoff_out"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_handoff_out,
      0,
      0,
      NULL },

    { ngx_string("handoff_in"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_handoff_in,
      0,
      0,
      NULL },

    { ngx_string("handoff_ifname"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_handoff_set_ifname,
      0,
      0,
      NULL },


    { ngx_string("handoff_target"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_handoff_set_target,
      0,
      0,
      NULL },

    { ngx_string("handoff_freq"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_handoff_set_frequency,
      0,
      0,
      NULL },


      ngx_null_command
};

static ngx_http_module_t ngx_http_handoff_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_handoff_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,   /* merge location configuration */
};

ngx_module_t ngx_http_handoff_module = {
    NGX_MODULE_V1,
    &ngx_http_handoff_module_ctx,           /* module context */
    ngx_http_handoff_commands,              /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *ngx_http_handoff_out(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_handoff_out_handler;

    return NGX_CONF_OK;
}

static char *ngx_http_handoff_in(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_handoff_main_conf_t *my_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_handoff_module);
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_handoff_in_handler;

    // payload buffer
    eight_MB = ngx_pcalloc(cf->pool, sizeof(uint8_t) * 1024 * 1024 * 8);
    memset(eight_MB, 1, sizeof(uint8_t) * 1024 * 1024 * 8);
printf("doing malloc for eight_MB\n");

    // get my ID
    for (int i = 0; i < my_conf->num_peers; i++) {
        if (my_conf->peer_sockaddr[i].sin_addr.s_addr == my_conf->my_sockaddr.sin_addr.s_addr) {
            my_conf->my_id = i;
            break;
        }
    }
    printf("my id is %d\n", my_conf->my_id);

    //int shmid;
    //if ((shmid = shmget(1234, sizeof(uint8_t), 0666)) == -1) {
    //    perror("shmget failed");
    //    exit(1);
    //}

    //if ((my_conf->shmaddr = shmat(shmid, NULL, 0)) == (void *) -1) {
    //    perror("shmat failed");
    //    exit(1);
    //}

    return NGX_CONF_OK;
}

static char *ngx_http_handoff_set_ifname(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_handoff_main_conf_t *my_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_handoff_module);

    ngx_str_t *value = cf->args->elts;
    if (cf->args->nelts != 2) {
        return NGX_CONF_ERROR;
    }

    strncpy(my_conf->ifname, (char*)value[1].data, value[1].len);
    my_conf->ifname[value[1].len] = 0;

    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, my_conf->ifname , IFNAMSIZ);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1 ) {
        close(fd);
        exit(EXIT_FAILURE);
    }

    memcpy(&my_conf->my_sockaddr, (struct sockaddr_in *)&ifr.ifr_addr, sizeof(struct sockaddr_in));

    // Perform the IOCTL operation to fetch the hardware address
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        exit(EXIT_FAILURE);
    }

    memcpy(my_conf->my_mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);

    // init lib forward
    //int err = init_forward(my_conf->ifname, "ingress", "1:");
    int err = init_forward(my_conf->ifname, "ingress", "egress");
    assert( err >= 0 );

    return NGX_CONF_OK;
}

static char *ngx_http_handoff_set_frequency(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_handoff_main_conf_t *my_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_handoff_module);

    ngx_str_t *value = cf->args->elts;
    if (cf->args->nelts != 2) {
        return NGX_CONF_ERROR;
    }

    my_conf->handoff_freq = ngx_atoi(value[1].data, value[1].len);
    printf("Handoff frequency: %d\n", my_conf->handoff_freq);

    return NGX_CONF_OK;
}

static char *ngx_http_handoff_set_target(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_handoff_main_conf_t *my_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_handoff_module);

    ngx_str_t *value = cf->args->elts;
    if (cf->args->nelts != 3) {
        return NGX_CONF_ERROR;
    }

    if (my_conf->num_peers > MAX_PEERS) {
        return NGX_CONF_ERROR;
    }

    // backend
    memset(&my_conf->peer_sockaddr[my_conf->num_peers], 0, sizeof(my_conf->peer_sockaddr[my_conf->num_peers]));
    inet_pton(AF_INET, (char*)value[1].data, &my_conf->peer_sockaddr[my_conf->num_peers].sin_addr);
    my_conf->peer_sockaddr[my_conf->num_peers].sin_port = htons(ngx_atoi(value[2].data, value[2].len));
    my_conf->peer_sockaddr[my_conf->num_peers].sin_family = AF_INET;
    printf("xo target %d %s:%ld\n", my_conf->num_peers, (char*)value[1].data, ngx_atoi(value[2].data, value[2].len));
    my_conf->num_peers++;

    return NGX_CONF_OK;
}

static void *ngx_http_handoff_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_handoff_main_conf_t  *my_conf;

    my_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_handoff_main_conf_t));
    //my_conf = calloc(1, sizeof(ngx_http_handoff_main_conf_t));
    if (my_conf == NULL) {
        return NULL;
    }
    my_conf->num_peers = 0;
    my_conf->my_id = -1;
    my_conf->handoff_freq = 0;

    my_conf->handoff_back_counter = 0;
    my_conf->last_trigger = 0; //ngx_time();

    return my_conf;
}

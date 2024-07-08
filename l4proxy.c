#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/sockios.h>

#define MAX_PREFIX_SZ_MAX    16
#define MAX_DGRAM_SZ_MAX    128
#define MAX_DGRAM_SZ_MIN     16

typedef struct cmdopts_s {
    struct in_addr  dw_addr;
    in_port_t       dw_port;
    struct in_addr  up_addr;
    in_port_t       up_port;
    char           *prefix;
    size_t          prefix_len;
} cmdopts_t;

int  proxy_loop_do(cmdopts_t *opts);

int  signal_quit_flag;
void signal_quit_handler(int signum);

int main(int argc, char **argv)
{
    cmdopts_t opts = (cmdopts_t){0};
    inet_aton("0.0.0.0", &opts.dw_addr);
    opts.dw_port = htons((uint16_t)8080);

    inet_aton("192.168.31.146", &opts.up_addr);
    opts.up_port = htons((uint16_t)1234);

    proxy_loop_do(&opts);

    return 0;
}

int proxy_loop_do(cmdopts_t *opts)
{
    int retcode = 0;

    /* POLL API is good enough here since we have two sockets only with different types
     * for multiple-connection cases EPOLL would be better choice */
    struct pollfd pfds[2] = {{.fd = -1}, {.fd = -1}};
    struct pollfd *dw_pfd = &pfds[0];
    struct pollfd *up_pfd = &pfds[1];

    /* DOWN side initialization */
    if ((dw_pfd->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        goto error;
    }
    if (fcntl(dw_pfd->fd, F_SETFL, O_NONBLOCK) < 0) {
        goto error;
    }
    /* no need to set REUSEADDR flag for SOCK_DGRAM since we don't want multicast support */
    struct sockaddr_in dw_sain = {
        .sin_family = AF_INET,
        .sin_addr = opts->dw_addr,
        .sin_port = opts->dw_port
    };
    if (bind(dw_pfd->fd , (struct sockaddr *)(&dw_sain), sizeof(dw_sain)) < 0) {
        goto error;
    }
    dw_pfd->events = POLLIN;

    /* UP side initialization (immutable things only) */
    struct sockaddr_in up_sain = {
        .sin_family = AF_INET,
        .sin_addr = opts->up_addr,
        .sin_port = opts->up_port
    };

    /* Event Loop initialization */
    enum upstate_e {
        UPSTATE_INIT,
        UPSTATE_CONNECTING,
        UPSTATE_CONNECTED,
        UPSTATE_HEARTSINK
    } up_state = UPSTATE_INIT;
    struct timespec tm_heartbeat = {.tv_sec = 1};
    struct timespec tm_heartsink = {0};

    /* Signal mask initialization */
    sigset_t sigset;
    struct sigaction sa;

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigprocmask(SIG_SETMASK, &sigset, NULL);

    sigemptyset(&sigset);
    sa.sa_handler = &signal_quit_handler;
    sa.sa_mask = sigset;
    sa.sa_flags = 0;
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    for (;;) {
        /* care about UP side (re)connection */
        if (up_state == UPSTATE_INIT) {
            if ((up_pfd->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                goto error;
            }
            if (fcntl(up_pfd->fd, F_SETFL, O_NONBLOCK) < 0) {
                goto error;
            }
            int sockopt = 1;
            if (setsockopt(up_pfd->fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0) {
                goto error;
            }
            int ccode = connect(up_pfd->fd, (struct sockaddr *)(&up_sain), sizeof(up_sain));
            if ((ccode < 0) && (errno != EINPROGRESS)) {
                goto error;
            }
            up_pfd->events = POLLOUT;
            up_state = UPSTATE_CONNECTING;
        }

        /* take UP/DOWN events */
        int pcode = ppoll(pfds, 2, &tm_heartbeat, &sigset);

        if (signal_quit_flag) {
            printf("%d signal was got; quit\n", signal_quit_flag);
            goto finalize;
        }
        if (pcode < 0) {
            goto error;
        }

        if (up_state == UPSTATE_HEARTSINK) {
            /* HEARTSINK is an intermediate state between CONNECTED and INIT
             * adds the necessary pause for UP side reconnect and eliminate
             * reconnection flood on local sockets
             *
             * DOWN side events still processed without delays */
            struct timespec tm_cur;
            if (clock_gettime(CLOCK_REALTIME, &tm_cur) < 0) {
                goto error;
            }
            uint64_t tm64_cur = tm_cur.tv_sec * (uint64_t)1000000000L + tm_cur.tv_nsec;
            uint64_t tm64_hts = tm_heartsink.tv_sec * (uint64_t)1000000000L + tm_heartsink.tv_nsec;
            uint64_t tm64_htb = tm_heartbeat.tv_sec * (uint64_t)1000000000L + tm_heartbeat.tv_nsec;
            if ((tm64_cur - tm64_hts) >= tm64_htb) {
                up_state = UPSTATE_INIT;
            }
        }

        if ((up_pfd->revents & POLLHUP) || (up_pfd->revents & POLLERR)) {
            /* error on UP side socket was happen */
            close(up_pfd->fd);
            up_pfd->fd = -1;  /* no more UP side events until reconnect */
            if (clock_gettime(CLOCK_REALTIME, &tm_heartsink) < 0) {
                goto error;
            }
            up_state = UPSTATE_HEARTSINK;
        } else if (up_pfd->revents & POLLOUT) {
            /* UP side socket is good */
            up_state = UPSTATE_CONNECTED;
            up_pfd->events = 0; /* stop POLLOUT flood */
        }

        if (dw_pfd->revents & POLLIN) {
            struct sockaddr  dw_src;
            socklen_t        dw_src_l;
            char             msg[MAX_PREFIX_SZ_MAX + MAX_DGRAM_SZ_MAX];
            int              msg_dt = 0;

            /* SOCK_DGRAM nature allow us do not care about messages split/re-assembly even on NONBLOCK mode
             * for SOCK_STREAM we also want to make our message-sent operations atomic
             * (otherwise we need to save up incoming UDP messages that goes against the task requirements)
             *
             * so lets sent only if we have enough space in socket buffer for entire message;
             * discard the message otherwise */

            int upbuf_sz = 0;  /* UP side socket buffer total size */
            int upbuf_dt = 0;  /* UP side socket buffer data size  */
            int upbuf_fr = 0;  /* UP side socket buffer free size  */
            if (up_state == UPSTATE_CONNECTED) {
                socklen_t upbuf_sz_le = sizeof(upbuf_sz);
                if (getsockopt(up_pfd->fd, SOL_SOCKET, SO_SNDBUF, &upbuf_sz, &upbuf_sz_le) < 0) {
                    goto error;
                }
                if (ioctl(up_pfd->fd, SIOCOUTQ, &upbuf_dt) < 0) {
                    goto error;
                }
                upbuf_fr = (upbuf_sz > upbuf_dt) ? (upbuf_sz - upbuf_dt) : 0;
                if (!upbuf_fr) {
                    continue;
                }
                printf("upbuf_sz: %d, upbuf_dt: %d, upbuf_fr: %d\n", upbuf_sz, upbuf_dt, upbuf_fr);
            }

            /* we expect strictly one full-filled message per receive call or nothing
             * zero-sized messages are possible */
            while ((msg_dt = recvfrom(dw_pfd->fd, &msg[opts->prefix_len], MAX_DGRAM_SZ_MAX, 0, &dw_src, &dw_src_l)) >= 0) {
                if ((up_state == UPSTATE_CONNECTED) &&
                    //(msg_dt >= MAX_DGRAM_SZ_MIN) &&
                    (msg_dt < upbuf_fr)
                ) {
                    printf("forward %d bytes message: '%.*s'\n", msg_dt, msg_dt, &msg[opts->prefix_len]);
                    int scode = send(up_pfd->fd, msg, opts->prefix_len + msg_dt, 0);
                    if (scode != opts->prefix_len + msg_dt) {
                        /* unexpected state; close UP socket
                         * socket state will fall into UPSTATE_HEARTSINK on POLLHUP event */
                        close(up_pfd->fd);
                        break;
                    } else {
                        upbuf_fr -= scode;
                        printf("was sent successfully\n");
                    }
                } else {
                    printf("discard %d bytes message: '%.*s'\n", msg_dt, msg_dt, &msg[opts->prefix_len]);
                    /* just discard the message */
                }
            }

            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                /* no data to read */
                continue;
            } else {
                goto error;
            }
        }
    }
    goto finalize;

error:
    retcode = -1;

finalize:
    if (dw_pfd->fd >= 0) {
        close(dw_pfd->fd);
    }
    if (up_pfd->fd >= 0) {
        close(up_pfd->fd);
    }
    return retcode;
}

void signal_quit_handler(int signum)
{
    signal_quit_flag = signum;
}

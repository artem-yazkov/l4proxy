#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_PREFIX_SIZE     16
#define MAX_DGRAM_SIZE      128

typedef struct cmdopts_s {
    struct in_addr  dw_addr;
    in_port_t       dw_port;
    struct in_addr  up_addr;
    in_port_t       up_port;
    char           *prefix;
    size_t          prefix_len;
} cmdopts_t;

int proxy_loop_do(cmdopts_t *opts);


int main(int argc, char **argv)
{
    cmdopts_t opts = (cmdopts_t){0};
    inet_aton("0.0.0.0", &opts.dw_addr);
    opts.dw_port = htons((uint16_t)8080);

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

    for (;;) {
        char msg[MAX_PREFIX_SIZE + MAX_DGRAM_SIZE];
        int  msg_l = 0; /* actual length of message data */
        int  msg_c = 0; /* message cursor allow us to send the message partially */

        int  up_is_alive = 0; /* 1 if upstream socket connection is alive */
        int  up_buff_s   = 0; /* upstream socket buffer total size        */
        int  up_buff_l   = 0; /* upstream socket buffer total size        */

        /* first of all, care about UP side connection */
        if (up_pfd->fd < 0) {
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
            /* SOCK_DGRAM nature allow us do not care about messages split/re-assembly even on NONBLOCK mode
             * however, for SOCK_STREAM we also want to make our message-sent operations atomic
             *
             * unfortunately we can't adjust SO_SNDLOWAT option on Linux,
             * but can rely on SO_SNDBUF-SIOCOUTQ (total SNDBUFF - filled SNDBUFF) difference */
            socklen_t sockopt_len = sizeof(up_buff_s);
            if (getsockopt(up_pfd->fd, SOL_SOCKET, SO_SNDBUF, &up_buff_s, &sockopt_len) < 0) {
                goto error;
            }
            printf("up_buff_s: %d bytes\n", up_buff_s);


            int ccode = connect(up_pfd->fd, (struct sockaddr *)(&up_sain), sizeof(up_sain));
            if ((ccode < 0) && (errno != EINPROGRESS)) {
                goto error;
            }
            if (ccode < 0) {
                /* connection in progress. Wait for POLLOUT */
                up_pfd->events = POLLOUT;
            } else {
                /* immediately connected */
                up_is_alive = 1;
            }
        }

        int pcode = ppoll(pfds, 2, NULL, NULL);
        if (pcode < 0) {
            goto error;
        }

        if (up_pfd->revents & POLLOUT) {
            up_is_alive = 1;
            up_pfd->events = 0; /* we want one-shot POLLOUT event */
        }
        if ((up_pfd->revents & POLLHUP) || (up_pfd->revents & POLLERR)) {
            up_is_alive = 0;
            close(up_pfd->fd);
            up_pfd->fd = -1;
        }

        if (dw_pfd->revents & POLLIN) {
            struct sockaddr  dw_src;
            socklen_t        dw_src_l;

            /* we expect strictly one full-filled message per receive call or nothing
             * zero-sized messages are possible */
            while ((msg_l = recvfrom(dw_pfd->fd, msg, MAX_DGRAM_SIZE, 0, &dw_src, &dw_src_l)) >= 0) {
                if (up_is_alive == 0) {
                    /* just skip the message */
                } else {
                    printf("forward %d bytes to upstream: '%.*s'\n", msg_l, msg_l, msg);
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

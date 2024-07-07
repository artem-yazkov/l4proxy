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
     * for multiple-connection cases EPOLL would be right choice
     */
    struct pollfd pfds[2] = {{.fd = -1}, {.fd = -1}};
    struct pollfd *dw_pfd = &pfds[0];
    struct pollfd *up_pfd = &pfds[1];

    /*
     * DOWN side initialization
     */
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

    /*
     * UP side initialization
     */

    for (;;) {
        int pcode = ppoll(pfds, 1, NULL, NULL);
        if (pcode < 0) {
            goto error;
        }
        if (dw_pfd->revents & POLLIN) {
            char   msg[MAX_PREFIX_SIZE + MAX_DGRAM_SIZE];
            int    msg_l = 0;
            struct sockaddr  dw_src;
            socklen_t        dw_src_l;

            /* we expect strictly one full-filled message per receive call or nothing
             * zero-sized messages are possible */
            while ((msg_l = recvfrom(dw_pfd->fd, msg, sizeof(msg), 0, &dw_src, &dw_src_l)) >= 0) {
                printf("%d bytes UDP message received: '%.*s'\n", msg_l, msg_l, msg);
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

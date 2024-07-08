#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

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

int   cmdopts_parse_creds(const char *optname, char *credline, struct in_addr *addr, in_port_t *port);
int   cmdopts_parse(int argc, char **argv, cmdopts_t *opts, bool *help);

FILE *log_stream;
char *log_filename;
int   log__(int severity, const char *format, ...);

int   proxy_loop_do(cmdopts_t *opts);

int   signal_quit_flag;
void  signal_quit_handler(int signum);

int main(int argc, char **argv)
{
    bool fl_help = 0;
    cmdopts_t opts = (cmdopts_t){0};
    if (cmdopts_parse(argc, argv, &opts, &fl_help) < 0) {
        return 1;
    }
    int retcode = proxy_loop_do(&opts);

    free(log_filename);
    free(opts.prefix);
    if (log_stream) {
        fclose(log_stream);
    }
    return (retcode == 0) ? 0 : 1;
}

int cmdopts_parse_creds(const char *optname, char *credline, struct in_addr *addr, in_port_t *port)
{
    char *s_addr, *s_port;
    if (!credline || !((s_addr = strtok(credline, ":"))) || !((s_port = strtok(NULL, ":")))) {
        fprintf(stderr, "    %s must be tuple in form <ipaddr>:<port>\n", optname);
        return -1;
    }
    if (!inet_aton(s_addr, addr)) {
        fprintf(stderr, "    %s has incorrect ip addr\n", optname);
        return -1;
    }
    if ((atoi(s_port) <= 0) || (atoi(s_port) > UINT16_MAX)) {
        fprintf(stderr, "    %s has incorrect port number\n", optname);
        return -1;
    }
    *port = htons((in_port_t)atoi(s_port));
    return 0;
}

int u8strlen(const char *s)
{
  int len=0;
  while (*s) {
    if ((*s & 0xC0) != 0x80) len++ ;
    s++;
  }
  return len;
}

int cmdopts_parse(int argc, char **argv, cmdopts_t *opts, bool *help)
{
    int   retcode = 0;
    char *shortopts = "d:u:p:l:h";
    struct option longopts[] = {
        {"down",       required_argument, NULL, 'd'},
        {"up",         required_argument, NULL, 'u'},
        {"prefix",     required_argument, NULL, 'p'},
        {"log",        required_argument, NULL, 'l'},
        {"help",       no_argument,       NULL, 'h'},
        {NULL,         0,                 NULL,  0}
    };
    char *dw_str = NULL;
    char *up_str = NULL;

    int   opt;
    while ((opt = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
        switch(opt) {
        case 'd':
            dw_str =strdup(optarg);
            break;
        case 'u':
            up_str = strdup(optarg);
            break;
        case 'p':
            opts->prefix = strdup(optarg);
            break;
        case 'l':
            log_filename = strdup(optarg);
            break;
        case 'h':
            *help = 1;
            return 0;
        default:
            fprintf(stderr, "unexpected option was found\n");
            *help = 1;
            return -1;
        }
    }
    if (cmdopts_parse_creds("--down", dw_str, &opts->dw_addr, &opts->dw_port) < 0) {
        retcode = -1;
    }
    if (cmdopts_parse_creds("--up", up_str, &opts->up_addr, &opts->up_port) < 0) {
        retcode = -1;
    }
    if (!opts->prefix) {
        printf("    --prefix option must be set\n");
        retcode = -1;
    } else {
        for (char *pc = opts->prefix; *pc; pc++) {
            if ((*pc & 0xC0) != 0x80) {
                opts->prefix_len++;
            }
        }
        if (opts->prefix_len != 4) {
            printf("    --prefix must be exactly 4 characters width\n");
            retcode = -1;
        }
        if ((opts->prefix_len = strlen(opts->prefix)) > MAX_PREFIX_SZ_MAX) {
            printf("    --prefix contain unexpected utf-8 string\n");
            retcode = -1;
        }
    }

    free(dw_str);
    free(up_str);

    return retcode;
}

int log__(int severity, const char *format, ...)
{
    static bool fallback;
    FILE *outstream = (severity <= LOG_ERR) ? stderr : stdout;

    if (!fallback && !log_stream && log_filename) {
        if ((log_stream = fopen(log_filename, "a+")) != NULL) {
            outstream = log_stream;
        } else {
            /* only one attempt to open log file */
            printf("[ERR] can't open|create %s file: %s\n\t log via standard streams\n", log_filename, strerror(errno));
            fallback = true;
        }
    } else if (!fallback && log_stream) {
        if (!ferror(log_stream)) {
            outstream = log_stream;
        } else {
            printf("[ERR] can't work with log file stream\n\t log via standard streams\n");
            /* does not try to fix log file IO issues */
            fallback = true;
        }
    }

    char *slevel;
    if (severity <= LOG_ERR) {
        slevel = "[ERR]";
    } else if (severity <= LOG_INFO) {
        slevel = "[INF]";
    } else {
        slevel = "[DBG]";
    }
    fprintf(outstream, "%s  ", slevel);

    va_list args;
    va_start(args, format);
    vfprintf(outstream, format, args);
    va_end(args);

    if ((severity <= LOG_ERR) && errno) {
        fprintf(outstream, "  err: %d (%s)\n", errno, strerror(errno));
        errno = 0;
    } else {
        fprintf(outstream, "\n");
    }
    fflush(outstream);

    return (fallback || ferror(outstream)) ? -1 : 0;
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
        log__(LOG_ERR, "DOWN socket initialization error");
        goto error;
    }
    if (fcntl(dw_pfd->fd, F_SETFL, O_NONBLOCK) < 0) {
        log__(LOG_ERR, "DOWN socket flag set error");
        goto error;
    }
    /* no need to set REUSEADDR flag for SOCK_DGRAM since we don't want multicast support */
    struct sockaddr_in dw_sain = {
        .sin_family = AF_INET,
        .sin_addr = opts->dw_addr,
        .sin_port = opts->dw_port
    };
    if (bind(dw_pfd->fd , (struct sockaddr *)(&dw_sain), sizeof(dw_sain)) < 0) {
        log__(LOG_ERR, "DOWN socket bind error");
        goto error;
    }
    dw_pfd->events = POLLIN;
    log__(LOG_INFO, "DOWN side connection initialized successfully");

    /* UP side initialization (immutable things only) */
    struct sockaddr_in up_sain = {
        .sin_family = AF_INET,
        .sin_addr = opts->up_addr,
        .sin_port = opts->up_port
    };

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

    /* Event Loop initialization */
    enum upstate_e {
        UPSTATE_INIT,
        UPSTATE_CONNECTING,
        UPSTATE_CONNECTED,
        UPSTATE_HEARTSINK
    } up_state = UPSTATE_INIT;
    struct timespec tm_heartbeat = {.tv_sec = 1};
    struct timespec tm_heartsink = {0};
    char            msg[MAX_PREFIX_SZ_MAX + MAX_DGRAM_SZ_MAX];
    int             msg_dt = 0;
    memcpy(msg, opts->prefix, opts->prefix_len);

    for (;;) {
        /* care about UP side (re)connection */
        if (up_state == UPSTATE_INIT) {
            if ((up_pfd->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                log__(LOG_ERR, "UP socket initialization error");
                goto error;
            }
            if (fcntl(up_pfd->fd, F_SETFL, O_NONBLOCK) < 0) {
                log__(LOG_ERR, "UP socket flag set error");
                goto error;
            }
            int sockopt = 1;
            if (setsockopt(up_pfd->fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) < 0) {
                log__(LOG_ERR, "UP socket option set error");
                goto error;
            }
            int ccode = connect(up_pfd->fd, (struct sockaddr *)(&up_sain), sizeof(up_sain));
            if ((ccode < 0) && (errno != EINPROGRESS)) {
                log__(LOG_ERR, "UP socket connect error");
                goto error;
            }
            up_pfd->events = POLLOUT;
            up_state = UPSTATE_CONNECTING;
            log__(LOG_INFO, "UP side connection state change: INIT -> CONNECTING");
        }

        /* take UP/DOWN events */
        int pcode = ppoll(pfds, 2, &tm_heartbeat, &sigset);

        if (signal_quit_flag) {
            log__(LOG_INFO, "%d signal was got; gently quit", signal_quit_flag);
            goto finalize;
        }
        if (pcode < 0) {
            log__(LOG_INFO, "unexpected POLL error");
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
                log__(LOG_INFO, "UP side connection state change: HEARTSINK -> INIT");
            }
        }

        if ((up_pfd->revents & POLLHUP) || (up_pfd->revents & POLLERR)) {
            /* some error on UP side socket was happen */
            close(up_pfd->fd);
            up_pfd->fd = -1;  /* no more UP side events until reconnect */
            if (clock_gettime(CLOCK_REALTIME, &tm_heartsink) < 0) {
                log__(LOG_INFO, "clock_gettime error");
                goto error;
            }
            up_state = UPSTATE_HEARTSINK;
            log__(LOG_INFO, "UP side connection got HUP|ERR events, switch to HEARTSINK");
        } else if (up_pfd->revents & POLLOUT) {
            /* UP side socket is good */
            up_state = UPSTATE_CONNECTED;
            log__(LOG_INFO, "UP side connection state change: CONNECTING -> CONNECTED");
            up_pfd->events = 0; /* stop POLLOUT flood */
        }

        if (dw_pfd->revents & POLLIN) {
            struct sockaddr  dw_src;
            socklen_t        dw_src_l;

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
                    log__(LOG_ERR, "UP socket option get error");
                    goto error;
                }
                if (ioctl(up_pfd->fd, SIOCOUTQ, &upbuf_dt) < 0) {
                    log__(LOG_ERR, "UP socket SIOCOUTQ command error");
                    goto error;
                }
                upbuf_fr = (upbuf_sz > upbuf_dt) ? (upbuf_sz - upbuf_dt) : 0;
                if (!upbuf_fr) {
                    continue;
                }
            }

            /* we expect strictly one full-filled message per receive call or nothing
             * zero-sized messages are possible */
            while ((msg_dt = recvfrom(dw_pfd->fd, &msg[opts->prefix_len], MAX_DGRAM_SZ_MAX, 0, &dw_src, &dw_src_l)) >= 0) {
                if ((up_state == UPSTATE_CONNECTED) &&
                    //(msg_dt >= MAX_DGRAM_SZ_MIN) &&
                    (msg_dt < upbuf_fr)
                ) {
                    int scode = send(up_pfd->fd, msg, opts->prefix_len + msg_dt, 0);
                    if (scode != (int)opts->prefix_len + msg_dt) {
                        /* unexpected state; close UP socket
                         * socket state will fall into UPSTATE_HEARTSINK on POLLHUP event */
                        log__(LOG_ERR, "UP socket unexpected send() result");
                        close(up_pfd->fd);
                        break;
                    } else {
                        upbuf_fr -= scode;
                    }
                } else {
                    log__(LOG_DEBUG, "discard %d bytes message: '%.*s'\n", msg_dt, msg_dt, &msg[opts->prefix_len]);
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

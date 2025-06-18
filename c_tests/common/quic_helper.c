#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "random.h"
#include "quic_helper.h"

#define MAX_DATAGRAM_SIZE 1350

#define HTTP_REQ_STREAM_ID 4

struct _quic_handler {
    int fd;

    socklen_t local_len;
    socklen_t peer_len;
    struct sockaddr local;
    struct sockaddr peer;

    quiceh_config* config;
    quiceh_conn* conn;
    quiceh_app_recv_buff_map* app_buffers;
    quiceh_h3_config* h3_config;
    quiceh_h3_conn* h3_conn;
};

static bool set_blocking_mode(int fd, char blocking)
{
    if (fd < 0)
        return false;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return false;
    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return fcntl(fd, F_SETFL, flags) == 0;
}

static int bind_connect_addr(int fd, const struct addrinfo* hints, const char* name, const char* str_port, struct sockaddr* addr, socklen_t* addr_len, int (*func)(int, const struct sockaddr*, socklen_t))
{
    struct addrinfo* result = NULL;
    struct addrinfo* next_result = NULL;

    if(getaddrinfo(name, str_port, hints, &result))
    {
        fprintf(stderr, "Unable to find address\n");
        goto FREE;
    }

    next_result = result;

    while(next_result != NULL)
    {
        if (func(fd, next_result->ai_addr, next_result->ai_addrlen) == 0)
            break;

        next_result = next_result->ai_next;
    }

    if(next_result == NULL)
    {
        fprintf(stderr, "Connection refused\n");
        close(fd);
        fd = -1;
        goto FREE;
    }
    *addr = *(next_result->ai_addr);
    *addr_len = next_result->ai_addrlen;

FREE:
    freeaddrinfo(result);
    return fd;
}

static int build_socket(const char* local_hostname, const char* str_local_port, const char* peer_hostname, const char* str_peer_port, struct sockaddr* local, socklen_t* local_len, struct sockaddr* peer, socklen_t* peer_len)
{
    int fd;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = IPPROTO_UDP;

    fd = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
    if(fd == -1)
    {
        return -1;
    }

    fd = bind_connect_addr(fd, &hints, local_hostname, str_local_port, local, local_len, bind);
    if(fd == -1)
    {
        return -1;
    }

    fd = bind_connect_addr(fd, &hints, peer_hostname, str_peer_port, peer, peer_len, connect);

    return fd;
}


static bool process_ingress(QuicHandler* handler)
{
    ssize_t n = 0;
    uint8_t buffer[65535] = {0};

    struct pollfd pollfd[] = {{.fd = handler->fd, .events = POLLIN}};

    int nfds = poll(pollfd, sizeof(pollfd) / sizeof(struct pollfd), quiceh_conn_timeout_as_millis(handler->conn));
    if(nfds < 0)
    {
        perror("poll");
        return false;
    }

    if(nfds == 0)
    {
        // timeout
        quiceh_conn_on_timeout(handler->conn);
        return true;
    }

    errno = 0;
    while(nfds > 0 && (n = recv(handler->fd, buffer, sizeof(buffer), 0)) > 0)
    {
        quiceh_recv_info recv_info = {.from = &handler->peer, .from_len = handler->peer_len, .to = &handler->local, .to_len = handler->local_len};

        if(quiceh_conn_recv(handler->conn, (uint8_t*)buffer, n, handler->app_buffers, &recv_info) < 0)
        {
            break;
        }
    }
    if(nfds > 0 && n < 0 && errno != 0 && errno != EWOULDBLOCK)
    {
        perror("recv");
        return false;
    }

    return true;
}

static bool process_egress(QuicHandler* handler)
{
    ssize_t n = 0;
    uint8_t out[MAX_DATAGRAM_SIZE] = {0};
    quiceh_send_info out_info;

    while((n = quiceh_conn_send(handler->conn, (uint8_t*)out, sizeof(out), &out_info)) > 0)
    {
        if(send(handler->fd, out, n, 0) != n)
        {
            perror("send didn't send enough bytes");
            return false;
        }
    }
    if(n < 0 && n != QUICEH_ERR_DONE)
    {
        quiceh_conn_close(handler->conn, false, 0x1, (uint8_t*)"fail", 4);
        return false;
    }
    return true;
}


QuicHandler* quic_connect(const char* hostname, const char* port, uint32_t protocol_version, bool verify_peer)
{
    ssize_t n;
    uint8_t out[MAX_DATAGRAM_SIZE] = {0};

    uint8_t scid[QUICEH_MAX_CONN_ID_LEN];

    QuicHandler* handler = NULL;

    handler = calloc(1, sizeof(QuicHandler));
    if(handler == NULL)
    {
        goto FREE;
    }
    handler->fd = -1;

    handler->fd = build_socket("0.0.0.0", "0", hostname, port, &handler->local, &handler->local_len, &handler->peer, &handler->peer_len);
    if(handler->fd < 0)
    {
        goto FREE;
    }

    if(!set_blocking_mode(handler->fd, false))
    {
        goto FREE;
    }

    handler->config = quiceh_config_new(protocol_version);
    if(handler->config == NULL)
    {
        goto FREE;
    }

    quiceh_config_verify_peer(handler->config, verify_peer);

    const char* protos[] = {
        "h3",
        NULL
    };

    quiceh_config_set_application_protos(handler->config, protos);

    quiceh_config_set_max_idle_timeout(handler->config, 5000);
    quiceh_config_set_max_recv_udp_payload_size(handler->config, MAX_DATAGRAM_SIZE);
    quiceh_config_set_max_send_udp_payload_size(handler->config, MAX_DATAGRAM_SIZE);
    quiceh_config_set_initial_max_data(handler->config, 10000000);
    quiceh_config_set_initial_max_stream_data_bidi_local(handler->config, 1000000);
    quiceh_config_set_initial_max_stream_data_bidi_remote(handler->config, 1000000);
    quiceh_config_set_initial_max_stream_data_uni(handler->config, 1000000);
    quiceh_config_set_initial_max_streams_bidi(handler->config, 100);
    quiceh_config_set_initial_max_streams_uni(handler->config, 100);
    quiceh_config_set_disable_active_migration(handler->config, true);
    quiceh_config_set_active_connection_id_limit(handler->config, 2);
    quiceh_config_set_max_connection_window(handler->config, 25165824);
    quiceh_config_set_max_stream_window(handler->config, 16777216);
    quiceh_config_set_cc_algorithm_name(handler->config, "cubic");

    random_set_unsecure_seed(random_standard_seed());
    random_unsecure_bytes(scid, sizeof(scid));

    handler->conn = quiceh_connect(hostname, (uint8_t*)scid, sizeof(scid), &handler->local, handler->local_len, &handler->peer, handler->peer_len, handler->config);
    if(handler->conn == NULL)
    {
        goto FREE;
    }

    handler->app_buffers = quiceh_app_recv_buf_map_default();
    if(handler->app_buffers == NULL)
    {
        goto FREE;
    }

    quiceh_send_info out_info;

    n = quiceh_conn_send(handler->conn, (uint8_t*)out, sizeof(out), &out_info);
    if(n < 0)
    {
        goto FREE;
    }
    if(send(handler->fd, out, n, 0) != n)
    {
        perror("send didn't send enough bytes");
        goto FREE;
    }

    while(!quiceh_conn_is_closed(handler->conn))
    {
        if(!process_ingress(handler))
        {
            goto FREE;
        }

        if(quiceh_conn_is_established(handler->conn))
        {
            // connected
            handler->h3_config = quiceh_h3_config_new();
            if(handler->h3_config == NULL)
            {
                goto FREE;
            }
            handler->h3_conn = quiceh_h3_conn_new_with_transport(handler->conn, handler->h3_config);
            if(handler->h3_conn == NULL)
            {
                goto FREE;
            }
            return handler;
        }

        if(!process_egress(handler))
        {
            goto FREE;
        }
    }

FREE:
    quic_free(&handler);
    return NULL;
}


int64_t quic_send_request(QuicHandler* handler, const char* method, const char* scheme, const char* hostname, const char* path, const char* user_agent)
{
    quiceh_h3_header headers[] = {
        {.name = (uint8_t*)":method", .name_len = sizeof(":method")-1, .value = (uint8_t*)method, .value_len = strlen(method)},
        {.name = (uint8_t*)":scheme", .name_len = sizeof(":scheme")-1, .value = (uint8_t*)scheme, .value_len = strlen(scheme)},
        {.name = (uint8_t*)":authority", .name_len = sizeof(":authority")-1, .value = (uint8_t*)hostname, .value_len = strlen(hostname)},
        {.name = (uint8_t*)":path", .name_len = sizeof(":path")-1, .value = (uint8_t*)path, .value_len = strlen(path)},
        {.name = (uint8_t*)"user-agent", .name_len = sizeof("user-agent")-1, .value = (uint8_t*)user_agent, .value_len = strlen(user_agent)}
    };

    return quiceh_h3_send_request(handler->h3_conn, handler->conn, headers, sizeof(headers) / sizeof(quiceh_h3_header), true);
}


int64_t quic_poll(QuicHandler* handler, quiceh_h3_event** ev)
{
    int64_t stream_id = QUICEH_H3_ERR_DONE;
    do
    {
        if(quiceh_conn_version(handler->conn) == QUICEH_PROTOCOL_VERSION_V1)
        {
            stream_id = quiceh_h3_conn_poll(handler->h3_conn, handler->conn, ev);
        }
        else
        {
            stream_id = quiceh_h3_conn_poll_v3(handler->h3_conn, handler->conn, handler->app_buffers, ev);
        }

        if(stream_id >= 0 && quiceh_h3_event_type(*ev) == QUICEH_H3_EVENT_FINISHED)
        {
            quiceh_conn_close(handler->conn, true, 0x0, (uint8_t*)"kthxbye", 7);
            return QUICEH_H3_ERR_DONE;
        }

        if(stream_id >= 0 || stream_id != QUICEH_H3_ERR_DONE)
        {
            return stream_id;
        }

        if(!process_egress(handler))
        {
            return QUICEH_H3_ERR_DONE;
        }
    } while(process_ingress(handler) && !quiceh_conn_is_closed(handler->conn));

    return QUICEH_H3_ERR_DONE;
}

uint32_t quic_conn_version(QuicHandler* handler)
{
    return quiceh_conn_version(handler->conn);
}


ssize_t quic_recv_body_v1(QuicHandler* handler, uint64_t stream_id, uint8_t *out, size_t out_len)
{
    return quiceh_h3_recv_body(handler->h3_conn, handler->conn, stream_id, out, out_len);
}

ssize_t quic_recv_body_v3(QuicHandler* handler, uint64_t stream_id, const uint8_t **out)
{
    return quiceh_h3_recv_body_v3(handler->h3_conn, handler->conn, stream_id, handler->app_buffers, out, NULL);
}

int quic_body_consumed(QuicHandler* handler, uint64_t stream_id, size_t consumed)
{
    return quiceh_h3_body_consumed(handler->h3_conn, handler->conn, stream_id, consumed, handler->app_buffers);
}

void quic_free(QuicHandler** handler)
{
    if(*handler == NULL)
    {
        return;
    }

    quiceh_app_recv_buf_map_free((*handler)->app_buffers);
    quiceh_conn_free((*handler)->conn);
    quiceh_config_free((*handler)->config);
    quiceh_h3_config_free((*handler)->h3_config);
    quiceh_h3_conn_free((*handler)->h3_conn);
    if((*handler)->fd >= 0)
    {
        close((*handler)->fd);
    }
    free(*handler);
    *handler = NULL;
}
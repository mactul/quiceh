#ifndef QUIC_HELPER_H
#define QUIC_HELPER_H

#include <stdint.h>
#include <stdbool.h>
#include "quiceh.h"


typedef struct _quic_base_handler QuicBaseHandler;
typedef struct _quic_conn_handler QuicConnHandler;


QuicConnHandler* quic_connect(const char* hostname, const char* port, uint32_t protocol_version, bool verify_peer);
QuicBaseHandler* quic_server_init(const char* hostname, const char* port, uint32_t protocol_version, const char* cert_path, const char* key_path);
int64_t quic_send_request(QuicConnHandler* handler, const char* method, const char* scheme, const char* hostname, const char* path, const char* user_agent);
int64_t quic_poll(QuicConnHandler* handler, quiceh_h3_event** ev);
uint32_t quic_conn_version(QuicConnHandler* handler);
ssize_t quic_recv_body_v1(QuicConnHandler* handler, uint64_t stream_id, uint8_t *out, size_t out_len);
ssize_t quic_recv_body_v3(QuicConnHandler* handler, uint64_t stream_id, const uint8_t **out);
int quic_body_consumed(QuicConnHandler* handler, uint64_t stream_id, size_t consumed);
QuicConnHandler* quic_accept(QuicBaseHandler* server_handler);
void quic_reply(QuicConnHandler* handler, uint64_t stream_id, uint8_t* content, size_t content_length);
void quic_close(QuicConnHandler* handler);
void quic_conn_free(QuicConnHandler** handler);
void quic_base_free(QuicBaseHandler** handler);

#endif
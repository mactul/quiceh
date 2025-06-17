#ifndef QUIC_HELPER_H
#define QUIC_HELPER_H

#include <stdint.h>
#include <stdbool.h>
#include "quiceh.h"


typedef struct _quic_handler QuicHandler;


QuicHandler* quic_connect(const char* hostname, const char* port, uint32_t protocol_version, bool verify_peer);
int64_t quic_send_request(QuicHandler* handler, const char* method, const char* scheme, const char* hostname, const char* path, const char* user_agent);
int64_t quic_poll(QuicHandler* handler, quiceh_h3_event** ev);
uint32_t quic_conn_version(QuicHandler* handler);
ssize_t quic_recv_body_v1(QuicHandler* handler, uint64_t stream_id, uint8_t *out, size_t out_len);
ssize_t quic_recv_body_v3(QuicHandler* handler, uint64_t stream_id, const uint8_t **out);
int quic_body_consumed(QuicHandler* handler, uint64_t stream_id, size_t consumed);
void quic_free(QuicHandler** handler);

#endif
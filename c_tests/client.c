#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/http_utils.h"
#include "common/quic_helper.h"


int main(int argc, char* argv[])
{
    http_utils_UrlSplitted url = {.host = "127.0.0.1", .port = "4433", .secured = true, .req = "/test.md"};
    int return_code = 1;

    int64_t stream_id;
    quiceh_h3_event* ev;
    size_t total_received = 0;

    QuicConnHandler* handler = NULL;

    if(argc > 1)
    {
        if(!http_utils_parse_url(argv[1], &url))
        {
            fprintf(stderr, "Invalid URL provided");
            goto FREE;
        }
    }


    handler = quic_connect(url.host, url.port, QUICEH_PROTOCOL_VERSION_V1, false);
    if(handler == NULL)
    {
        goto FREE;
    }

    printf("connected\n");

    if(quic_send_request(handler, "GET", url.secured ? "https" : "http", url.host, url.req, "quiceh") < 0)
    {
        goto FREE;
    }

    while((stream_id = quic_poll(handler, &ev)) >= 0)
    {
        switch(quiceh_h3_event_type(ev))
        {
            case QUICEH_H3_EVENT_HEADERS:
                printf("headers received\n");
                break;
            case QUICEH_H3_EVENT_DATA:
                if(quic_conn_version(handler) == QUICEH_PROTOCOL_VERSION_V1)
                {
                    ssize_t read;
                    uint8_t data[BUFSIZ];
                    while((read = quic_recv_body_v1(handler, stream_id, data, sizeof(data))) > 0)
                    {
                        // write(STDOUT_FILENO, data, read);
                        total_received += read;
                    }
                }
                else
                {
                    const uint8_t* data;
                    ssize_t read = quic_recv_body_v3(handler, stream_id, &data);
                    if(read > 0)
                    {
                        write(STDOUT_FILENO, data, read);
                        total_received += read;
                        quic_body_consumed(handler, stream_id, read);
                    }
                }
                break;
            case QUICEH_H3_EVENT_FINISHED:
                quic_close(handler);
        }
        quiceh_h3_event_free(ev);
    }

    printf("\nTotal received: %lu\n", total_received);

    return_code = 0;
FREE:
    quic_conn_free(&handler);
    return return_code;
}
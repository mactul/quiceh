#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/http_utils.h"
#include "common/quic_helper.h"


static int callback(uint8_t *name, size_t name_len, uint8_t *value, size_t value_len, void *argp)
{
    write(STDOUT_FILENO, name, name_len);
    write(STDOUT_FILENO, " : ", 3);
    write(STDOUT_FILENO, value, value_len);
    write(STDOUT_FILENO, "\n", 1);

    return 0;
}

int main(int argc, char* argv[])
{
    http_utils_UrlSplitted url = {.host = "127.0.0.1", .port = "4433", .secured = true, .req = "/test.md"};
    int return_code = 1;

    int64_t stream_id;
    quiceh_h3_event* ev;

    QuicBaseHandler* server_handler = NULL;
    QuicConnHandler* client_handler = NULL;

    if(argc > 1)
    {
        if(!http_utils_parse_url(argv[1], &url))
        {
            fprintf(stderr, "Invalid URL provided");
            goto FREE;
        }
    }


    server_handler = quic_server_init(url.host, url.port, QUICEH_PROTOCOL_VERSION_V1, "./cert.crt", "./cert.key");
    if(server_handler == NULL)
    {
        goto FREE;
    }

    client_handler = quic_accept(server_handler);
    if(client_handler == NULL)
    {
        goto FREE;
    }

    while((stream_id = quic_poll(client_handler, &ev)) >= 0)
    {
        switch(quiceh_h3_event_type(ev))
        {
            case QUICEH_H3_EVENT_HEADERS:
                printf("headers received\n");
                quiceh_h3_event_for_each_header(ev, callback, NULL);
                quic_reply(client_handler, stream_id, "hello world", sizeof("hello world")-1);
                break;
        }
        quiceh_h3_event_free(ev);
    }
    printf("stream id: %d\n", stream_id);

    return_code = 0;
FREE:
    quic_conn_free(&client_handler);
    quic_base_free(&server_handler);
    return return_code;
}
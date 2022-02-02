/** @file net_lib.c
 *
 * @brief A library for network releated code.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2000, 2018 Michael Barr. This software is placed in the
 * public domain and may be used for any purpose. However, this notice must not
 * be changed or removed. No warranty is expressed or implied by the publication
 * or distribution of this source code.
 */

#include "header/includes.h"
#include "header/net_lib.h"

int
generate_server(int *p_sock, char *p_port)
{
    /*---------------------Variables/structs set-up-----------------------*/
    int status = 0; // For error handling.

    socklen_t one     = 1; // Used for setsockopt.
    socklen_t one_len = sizeof(one);

    struct addrinfo *p_server = NULL; // Server addrinfo.
    struct addrinfo  hints;
    memset(&hints, 0, sizeof(hints)); // Clear out hints struct.
    /*--------------------------------------------------------------------*/

    /*------------------Set up prelim server info ------------------------*/
    hints.ai_family   = AF_UNSPEC;   // Accept either IPv4 or IPv6.
    hints.ai_socktype = SOCK_STREAM; // TCP.
    hints.ai_flags    = AI_PASSIVE;  // Get IP dynamically (localhost).
    /*--------------------------------------------------------------------*/

    /*------------------Generate listening socket ------------------------*/
    /* getaddrinfo(NULL, ...) | the NULL indicates localhost */
    status = getaddrinfo(NULL, p_port, &hints, &p_server);
    if (status != 0)
    {
        /* Special getaddr_status error (converts error to string) */
        fprintf(stderr, "getaddrinfo err: %s\n", gai_strerror(status));
        goto OUT;
    }

    /* Generate main listening socket, non_blocking */
    *p_sock = socket(p_server->ai_family,
                     p_server->ai_socktype | SOCK_NONBLOCK,
                     p_server->ai_protocol);
    if (*p_sock <= 0)
    {
        perror("Main server socket error");
        status = *p_sock;
        goto OUT;
    }

    /* Reuse the port binded/reusable socket descriptor */
    status = setsockopt(*p_sock, SOL_SOCKET, SO_REUSEADDR, &one, one_len);
    if (status != 0)
    {
        perror("Set sock option");
        goto OUT;
    }

    status = bind(*p_sock, p_server->ai_addr, p_server->ai_addrlen);
    if (status != 0)
    {
        perror("Main RHP bind error");
        close_socket(p_sock);
        goto OUT;
    }

    if (NULL == p_sock)
    {
        fprintf(stderr, "Server failed to generate\n");
        goto OUT;
    }

    puts("|--------------------|");
    puts("|TCP Server generated|");
    puts("|--------------------|");
    /*--------------------------------------------------------------------*/

    /*------------------Actually listen for things------------------------*/
    /* SOMAXCONN: System max of queued connections */
    status = listen(*p_sock, SOMAXCONN);
    if (status != 0)
    {
        perror("Listen");
        goto OUT;
    }
    /*--------------------------------------------------------------------*/

OUT:
    if (p_server != NULL)
        freeaddrinfo(p_server);

    return status;
}

ssize_t
send_data(int *p_sock, void *p_data, ssize_t size)
{

    ssize_t sent_bytes = 0;

    if (size <= 0 || NULL == p_data)
    {
        puts("No data found");
        goto DONE;
    }

    sent_bytes = send(*p_sock, p_data, size, 0);
    if (sent_bytes <= 0)
    {
        perror("send");
        goto DONE;
    }

DONE:
    return sent_bytes;
}

ssize_t
receive_data(int *p_sock, void *p_buf, ssize_t size)
{
    ssize_t recv_bytes = 0;

    if (size <= 0)
    {
        puts("Incorrect size given");
        goto DONE;
    }

    recv_bytes = recv(*p_sock, p_buf, size, 0);
    if (recv_bytes <= 0)
    {
        goto DONE;
    }

DONE:
    return recv_bytes;
}

int
close_socket(int *p_sock)
{
    int status = 0;

    status = close(*p_sock);
    if (status != 0)
    {
        perror("Close sock");
    }

    return status;
}

void
pop_user_request(void **pp_generic_packet, char buf[])
{
    int offset = 0;

    user_request_i *p_packet = (user_request_i *)pp_generic_packet;

    // OPCODE.
    memcpy(&p_packet->opcode, buf + offset, sizeof(p_packet->opcode));
    offset = offset + sizeof(p_packet->opcode);

    // User flag.
    memcpy(&p_packet->flag, buf + offset, sizeof(p_packet->flag));
    offset = offset + sizeof(p_packet->flag);

    // Reserved.
    memcpy(&p_packet->rsvd, buf + offset, sizeof(p_packet->rsvd));
    offset         = offset + sizeof(p_packet->rsvd);
    p_packet->rsvd = ntohs(p_packet->rsvd);

    // Username length.
    memcpy(&p_packet->u_len, buf + offset, sizeof(p_packet->u_len));
    offset          = offset + sizeof(p_packet->u_len);
    p_packet->u_len = ntohs(p_packet->u_len);

    // Password length.
    memcpy(&p_packet->p_len, buf + offset, sizeof(p_packet->p_len));
    offset          = offset + sizeof(p_packet->p_len);
    p_packet->p_len = ntohs(p_packet->p_len);

    // Session ID.
    memcpy(&p_packet->s_id, buf + offset, sizeof(p_packet->s_id));
    offset         = offset + sizeof(p_packet->s_id);
    p_packet->s_id = ntohl(p_packet->s_id);

    // Username...Password...
    p_packet->p_data = strndup(buf + offset, p_packet->u_len + p_packet->p_len);
}

void
pop_user_reply(void **pp_generic_packet, uint8_t retcode)
{
    user_reply_i *p_packet = (user_reply_i *)pp_generic_packet;

    // RETCODE
    p_packet->retcode = retcode;

    // Reserved
    p_packet->rsvd = 0;

    // Session ID
    p_packet->s_id = 0;
    p_packet->rsvd = htons(p_packet->rsvd);
}

void
pop_rm_request(void **pp_generic_packet, char buf[])
{
    int offset = 0;

    rm_request_i *p_packet = (rm_request_i *)pp_generic_packet;

    // OPCODE
    memcpy(&p_packet->opcode, buf + offset, sizeof(p_packet->opcode));
    offset = offset + sizeof(p_packet->opcode);

    // Reserved
    memcpy(&p_packet->rsvd, buf + offset, sizeof(p_packet->rsvd));
    offset = offset + sizeof(p_packet->rsvd);

    // Filename length
    memcpy(&p_packet->len, buf + offset, sizeof(p_packet->len));
    offset        = offset + sizeof(p_packet->len);
    p_packet->len = ntohs(p_packet->len);

    // Session ID
    memcpy(&p_packet->s_id, buf + offset, sizeof(p_packet->s_id));
    offset         = offset + sizeof(p_packet->s_id);
    p_packet->s_id = ntohl(p_packet->s_id);

    // Filename...
    p_packet->p_data = strndup(buf + offset, p_packet->len);
}

void
pop_rm_reply(void **pp_generic_packet, uint8_t retcode)
{
    rm_reply_i *p_packet = (rm_reply_i *)pp_generic_packet;

    // RETCODE
    p_packet->retcode = retcode;
}

void
pop_ls_request(void **pp_generic_packet, char buf[])
{
    int offset = 0;

    ls_request_i *p_packet = (ls_request_i *)pp_generic_packet;

    // OPCODE
    memcpy(&p_packet->opcode, buf + offset, sizeof(p_packet->opcode));
    offset = offset + sizeof(p_packet->opcode);

    // Reserved
    memcpy(&p_packet->rsvd, buf + offset, sizeof(p_packet->rsvd));
    offset = offset + sizeof(p_packet->rsvd);

    // Filename length
    memcpy(&p_packet->len, buf + offset, sizeof(p_packet->len));
    offset        = offset + sizeof(p_packet->len);
    p_packet->len = ntohs(p_packet->len);

    // Session ID
    memcpy(&p_packet->s_id, buf + offset, sizeof(p_packet->s_id));
    offset         = offset + sizeof(p_packet->s_id);
    p_packet->s_id = ntohl(p_packet->s_id);

    // Position
    memcpy(&p_packet->pos, buf + offset, sizeof(p_packet->pos));
    offset        = offset + sizeof(p_packet->pos);
    p_packet->pos = ntohl(p_packet->pos);

    // Directory...
    p_packet->p_data = strndup(buf + offset, p_packet->len);
}

void
pop_ls_reply(void **pp_generic_packet, uint8_t retcode)
{
    ls_reply_i *p_packet = (ls_reply_i *)pp_generic_packet;

    // RETCODE
    p_packet->retcode = retcode;

    // Reserved
    for (int i = 0; i < 3; i++)
    {
        p_packet->rsvd[i] = 0;
    }

    // Total data length
    p_packet->data_len = 0;
    p_packet->data_len = htonl(p_packet->data_len);

    // Length of data in p_packet
    p_packet->msg_len = 0;
    p_packet->msg_len = htonl(p_packet->msg_len);

    // Total data read so far
    p_packet->pos = 0;
    p_packet->pos = htonl(p_packet->pos);

    memset(&p_packet->data, 0, sizeof(p_packet->data));
}

void
pop_get_request(void **pp_generic_packet, char buf[])
{
    int offset = 0;

    get_request_i *p_packet = (get_request_i *)pp_generic_packet;

    // OPCODE
    memcpy(&p_packet->opcode, buf + offset, sizeof(p_packet->opcode));
    offset = offset + sizeof(p_packet->opcode);

    // Reserved
    memcpy(&p_packet->rsvd, buf + offset, sizeof(p_packet->rsvd));
    offset = offset + sizeof(p_packet->rsvd);

    // Filename length
    memcpy(&p_packet->len, buf + offset, sizeof(p_packet->len));
    offset        = offset + sizeof(p_packet->len);
    p_packet->len = ntohs(p_packet->len);

    // Session ID
    memcpy(&p_packet->s_id, buf + offset, sizeof(p_packet->s_id));
    offset         = offset + sizeof(p_packet->s_id);
    p_packet->s_id = ntohl(p_packet->s_id);

    // Filename...
    p_packet->p_data = strndup(buf + offset, p_packet->len);
}

void
pop_get_reply(void **pp_generic_packet, uint8_t retcode)
{
    get_reply_i *p_packet = (get_reply_i *)pp_generic_packet;

    // RETCODE
    p_packet->retcode = retcode;

    // Reserved
    p_packet->rsvd = 0;

    // File length
    p_packet->len = 0;
    p_packet->len = htonl(p_packet->len);

    memset(&p_packet->data, 0, sizeof(p_packet->data));
}

void
pop_mkdir_request(void **pp_generic_packet, char buf[])
{
    int offset = 0;

    mkdir_request_i *p_packet = (mkdir_request_i *)pp_generic_packet;

    // OPCODE
    memcpy(&p_packet->opcode, buf + offset, sizeof(p_packet->opcode));
    offset = offset + sizeof(p_packet->opcode);

    // Reserved_8
    memcpy(&p_packet->rsvd_8, buf + offset, sizeof(p_packet->rsvd_8));
    offset = offset + sizeof(p_packet->rsvd_8);

    // Filename length
    memcpy(&p_packet->len, buf + offset, sizeof(p_packet->len));
    offset        = offset + sizeof(p_packet->len);
    p_packet->len = ntohs(p_packet->len);

    // Session ID
    memcpy(&p_packet->s_id, buf + offset, sizeof(p_packet->s_id));
    offset         = offset + sizeof(p_packet->s_id);
    p_packet->s_id = ntohl(p_packet->s_id);

    // Reserved_32
    memcpy(&p_packet->rsvd_32, buf + offset, sizeof(p_packet->rsvd_32));
    offset            = offset + sizeof(p_packet->rsvd_32);
    p_packet->rsvd_32 = ntohl(p_packet->rsvd_32);

    // Directory...
    p_packet->p_data = strndup(buf + offset, p_packet->len);
}

void
pop_mkdir_reply(void **pp_generic_packet, uint8_t retcode)
{
    mkdir_reply_i *p_packet = (mkdir_reply_i *)pp_generic_packet;

    // RETCODE
    p_packet->retcode = retcode;
}

void
pop_put_request(void **pp_generic_packet, char buf[])
{
    int offset = 0;

    put_request_i *p_packet = (put_request_i *)pp_generic_packet;

    // OPCODE
    memcpy(&p_packet->opcode, buf + offset, sizeof(p_packet->opcode));
    offset = offset + sizeof(p_packet->opcode);

    // Reserved
    memcpy(&p_packet->flag, buf + offset, sizeof(p_packet->flag));
    offset = offset + sizeof(p_packet->flag);

    // Filename length
    memcpy(&p_packet->name_len, buf + offset, sizeof(p_packet->name_len));
    offset             = offset + sizeof(p_packet->name_len);
    p_packet->name_len = ntohs(p_packet->name_len);

    // Session ID
    memcpy(&p_packet->s_id, buf + offset, sizeof(p_packet->s_id));
    offset         = offset + sizeof(p_packet->s_id);
    p_packet->s_id = ntohl(p_packet->s_id);

    // Data length
    memcpy(&p_packet->data_len, buf + offset, sizeof(p_packet->data_len));
    offset             = offset + sizeof(p_packet->data_len);
    p_packet->data_len = ntohl(p_packet->data_len);

    // Filename...Filedata
    p_packet->p_data
        = strndup(buf + offset, p_packet->name_len + p_packet->data_len);
}

void
pop_put_reply(void **pp_generic_packet, uint8_t retcode)
{
    put_reply_i *p_packet = (put_reply_i *)pp_generic_packet;

    // RETCODE
    p_packet->retcode = retcode;
}

/*** end of file ***/
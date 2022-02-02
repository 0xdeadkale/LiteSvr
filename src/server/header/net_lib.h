/** @file net_lib.h
 *
 * @brief The private header file fornet_lib.c.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2018 Barr Group. All rights reserved.
 */

#ifndef NETLIB_H
#define NETLIB_H

/*-------------USER operation--------------*/
typedef struct __attribute__((__packed__)) user_request
{
    uint8_t  opcode; /* OPCODE. */
    uint8_t  flag;   /* User flag. */
    uint16_t rsvd;   /* Reserved. */
    uint16_t u_len;  /* Username length. */
    uint16_t p_len;  /* Password length. */
    uint32_t s_id;   /* Session ID. */
    char *   p_data; /* Username...+Password... */
} user_request_i;

typedef struct __attribute__((__packed__)) user_reply
{
    uint8_t  retcode; /* Return code. */
    uint8_t  rsvd;    /* Reserved. */
    uint32_t s_id;    /* Session ID. */
} user_reply_i;
/*-----------------------------------------*/

/*--------------RM remote file-------------*/
typedef struct __attribute__((__packed__)) rm_request
{
    uint8_t  opcode; /* OPCODE. */
    uint8_t  rsvd;   /* Reserved. */
    uint16_t len;    /* Filename length. */
    uint32_t s_id;   /* Session ID. */
    char *   p_data; /* Filename... */
} rm_request_i;

typedef struct __attribute__((__packed__)) rm_reply
{
    uint8_t retcode; /* Return code. */
} rm_reply_i;
/*-----------------------------------------*/

/*--------------LS remote dir--------------*/
typedef struct __attribute__((__packed__)) ls_request
{
    uint8_t  opcode; /* OPCODE. */
    uint8_t  rsvd;   /* Reserved. */
    uint16_t len;    /* Dir name length. */
    uint32_t s_id;   /* Session ID. */
    uint32_t pos;    /* Position. */
    char *   p_data; /* Directory name... */
} ls_request_i;

typedef struct __attribute__((__packed__)) ls_reply
{
    uint8_t  retcode;    /* Return code. */
    uint8_t  rsvd[3];    /* Reserved. */
    uint32_t data_len;   /* Total content length. */
    uint32_t msg_len;    /* Packet content length. */
    uint32_t pos;        /* Current position (bytes recv so far). */
    char     data[2032]; /* File data. */
} ls_reply_i;

/*-------------GET remote file--------------*/
typedef struct __attribute__((__packed__)) get_request
{
    uint8_t  opcode; /* OPCODE. */
    uint8_t  rsvd;   /* Reserved. */
    uint16_t len;    /* Filename length. */
    uint32_t s_id;   /* Session ID. */
    char *   p_data; /* Filename... */
} get_request_i;

typedef struct __attribute__((__packed__)) get_reply
{
    uint8_t  retcode;    /* Return code. */
    uint8_t  rsvd;       /* Reserved. */
    uint32_t len;        /* file data length. */
    char     data[1016]; /* File data. */
} get_reply_i;
/*-----------------------------------------*/

/*------------MKDIR remote dir-------------*/
typedef struct __attribute__((__packed__)) mkdir_request
{
    uint8_t  opcode;  /* OPCODE. */
    uint8_t  rsvd_8;  /* Reserved. */
    uint16_t len;     /* Dir name length. */
    uint32_t s_id;    /* Session ID. */
    uint32_t rsvd_32; /* Reserved. */
    char *   p_data;  /* Directory name. */
} mkdir_request_i;

typedef struct __attribute__((__packed__)) mkdir_reply
{
    uint8_t retcode; /* Return code. */
} mkdir_reply_i;
/*-----------------------------------------*/

/*-------------PUT remote file-------------*/
typedef struct __attribute__((__packed__)) put_request
{
    uint8_t  opcode;   /* OPCODE. */
    uint8_t  flag;     /* OVERWRITE flag. */
    uint16_t name_len; /* Filename length. */
    uint32_t s_id;     /* Session ID. */
    uint32_t data_len; /* File content length. */
    char *   p_data;   /* Filename...+file data... */
} put_request_i;

typedef struct __attribute__((__packed__)) put_reply
{
    uint8_t retcode; /* Return code. */
} put_reply_i;
/*-----------------------------------------*/

enum opcodes
{
    USER  = 1,
    RM    = 2,
    LS    = 3,
    GET   = 4,
    MKDIR = 5,
    PUT   = 6
};

enum retcodes
{
    SUCCESS = 1,
    S_ERR   = 2,
    P_ERR   = 3,
    U_EXIST = 4,
    F_EXIST = 5,
    FAIL    = 255
};

enum usercodes
{
    LOGIN   = 0,
    R_ONLY  = 1,
    RW_ONLY = 2,
    ADMIN   = 3,
    DEL     = 255
};

enum overwritecodes
{
    NO_OVERWRITE = 0,
    OVERWRITE    = 1
};

enum contraints
{
    MTU         = 2048,
    PORT_MAX    = 65535,
    TIMEOUT_MIN = 0,
    TIMEOUT_MAX = 1000,
    FILE_MAX    = 1016,
    PACKET_MAX  = 2032
};

int generate_server(int *sock, char *port);

ssize_t send_data(int *sock, void *data, ssize_t size);

ssize_t receive_data(int *sock, void *buffer, ssize_t size);

int close_socket(int *sock);

void pop_user_request(void **generic_packer, char buf[]);

void pop_user_reply(void **generic_packet, uint8_t retcode);

void pop_rm_request(void **generic_packet, char buf[]);

void pop_rm_reply(void **generic_packet, uint8_t retcode);

void pop_ls_request(void **generic_packet, char buf[]);

void pop_ls_reply(void **generic_packet, uint8_t retcode);

void pop_get_request(void **generic_packet, char buf[]);

void pop_get_reply(void **generic_packet, uint8_t retcode);

void pop_mkdir_request(void **generic_packet, char buf[]);

void pop_mkdir_reply(void **generic_packet, uint8_t retcode);

void pop_put_request(void **generic_packet, char buf[]);

void pop_put_reply(void **generic_packet, uint8_t retcode);

void (*pop_request_packet[])(void **, char *)
    = { NULL,           pop_user_request, pop_rm_request,
        pop_ls_request, pop_get_request,  pop_mkdir_request,
        pop_put_request };

void (*pop_error_packet[])(void **, uint8_t)
    = { NULL,          pop_user_reply,  pop_rm_reply, pop_ls_reply,
        pop_get_reply, pop_mkdir_reply, pop_put_reply };

#endif /* NETLIB_H */

/*** end of file ***/
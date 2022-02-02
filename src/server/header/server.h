/** @file server.h
 *
 * @brief The private header file for server.c.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2018 Barr Group. All rights reserved.
 */

#ifndef SERVER_H
#define SERVER_H

#include "includes.h"
#include "net_lib.h"
#include "file_lib.h"
#include "../../../include/p_hash.h"

#define SERV_PATH "test/server/"
#define CLI_PATH  "test/client/"

volatile sig_atomic_t gb_main_loop = true;
volatile sig_atomic_t g_jobs      = 0;

pthread_mutex_t  g_job_lock  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t  g_exit_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t  g_data_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_rwlock_t g_file_lock = PTHREAD_RWLOCK_INITIALIZER;

typedef struct client
{
    int       cli_num; // ID of client.
    int       conn_sock;
    char      conn_ip[INET6_ADDRSTRLEN];
    in_port_t port;
    uint32_t  s_id; // Session id of client.
    server_i *p_login;
    uint8_t   permission;
} client_i;

int validate_optarg_nums(char *timeout, char *port);

int validate_dir(char **server_dir, char *cmd_dir);

void create_sig_handler(int signum, void (*func)(int));

int server_start(char *port, char *server_dir, int timeout);

int make_root_dir(char *server_dir);

int fill_sigsets(sigset_t **block, sigset_t **non_block);

int login_system_start(server_i **login,
                       char *     server_dir,
                       int        timeout,
                       sigset_t * non_block);

int server_loop(int main_sock, sigset_t **non_block, server_i **login);

int create_epoll(int *fd, int sock);

int epoll_handler(
    int nfds, int sock, int **count, struct epoll_event evs[], server_i *login);

int accept_connection(int sock, int *i, server_i *login);

void insert_cli(client_i **    client,
                int            i,
                int            conn_sock,
                struct in_addr ip,
                in_port_t      port,
                server_i *     login);

int check_clients(pthread_t *threads);

void *conn_event(void *client_num);

int dispatcher(client_i *cli, int *err);

bool validate_s_id(client_i *cli, char *buf, uint8_t opcode);

#endif /* SERVER_H */

/*** end of file ***/

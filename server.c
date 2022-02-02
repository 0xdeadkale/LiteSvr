/** @file server.c
 *
 * @brief The FTP server capstone source code.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2000, 2018 Michael Barr. This software is placed in the
 * public domain and may be used for any purpose. However, this notice must not
 * be changed or removed. No warranty is expressed or implied by the publication
 * or distribution of this source code.
 */

#include "header/server.h"

static void handler(int signum);

int
main(int argc, char *p_argv[])
{
    /*--------------------------Set up variables--------------------------*/
    int status = 0; // Server status.

    /* getopt variables */
    int                option    = 0; // getopt usage.
    static const char *p_opt_str = ":t:d:p:";

    /* optarg variables */
    char *p_timeout = NULL;
    char *p_dir     = NULL;
    char *p_port    = NULL;

    int   timeout_num  = 0;    // For timeout.
    char *p_server_dir = NULL; // For root dir of server.
    /*--------------------------------------------------------------------*/

    /*-------------------------Validate # of args-------------------------*/
    if (argc != 7)
    {
        puts("[Invalid # of arguments]");
        puts(" Usage: ./capstone -t [time] -d [dir] -p [port]");
        status = -1;
        goto EXIT;
    }
    /*--------------------------------------------------------------------*/

    /*--------------------------CMD-LINE Parsing--------------------------*/
    opterr = 0;
    while (option != -1)
    {
        option = getopt(argc, p_argv, p_opt_str);
        if (option == -1)
        {
            break;
        }

        switch (option)
        {
            /* Client timeout */
            case 't':
                p_timeout = optarg;
                break;
            /* File directory */
            case 'd':
                p_dir = optarg;
                break;
            /* Server port */
            case 'p':
                p_port = optarg;
                break;
            case ':':
                printf("Option: '-%c' needs a value\n", optopt);
                status = -1;
                goto EXIT;
            case '?':
                printf("Unknown option: %c\n", optopt);
                status = -1;
                goto EXIT;
            default:
                puts("Usage: ./capstone -t [time] -d [dir] -p [port]");
                status = -1;
                goto EXIT;
        }
    }
    /*--------------------------------------------------------------------*/

    /*--------------------Validation of cmd-line input--------------------*/
    status = validate_optarg_nums(p_timeout, p_port);
    if (status == -1)
    {
        goto EXIT;
    }
    else
    {
        timeout_num = status;
        status      = 0;
    }

    status = validate_dir(&p_server_dir, p_dir);
    if (status == -1)
    {
        puts("Root directory is invalid");
        goto EXIT;
    }
    /*--------------------------------------------------------------------*/

    /*-------------------------Signal handler-----------------------------*/
    create_sig_handler(SIGINT, handler); // For CTRL+C.
    /*--------------------------------------------------------------------*/

    /*----Initiate server----*/
    status = server_start(p_port, p_server_dir, timeout_num);

EXIT:
    puts("\nExiting...");
    exit(status);
}

int
validate_optarg_nums(char *p_timeout, char *p_port)
{
    int   status  = 0;
    long  arg_num = 0;
    char *p_junk  = NULL;

    /* Check if port is a number */
    arg_num = strtol(p_port, &p_junk, 10);
    if (strncmp(p_junk, "", 1) != 0)
    {
        puts("Port must be a number");
        status = -1;
        goto END;
    }

    /* Check port for (non-privileged) port range */
    if (arg_num < IPPORT_USERRESERVED || arg_num > PORT_MAX)
    {
        printf("Port must be %d - %d", IPPORT_USERRESERVED, PORT_MAX);
        status = -1;
    }

    arg_num = strtol(p_timeout, &p_junk, 10);
    if (strncmp(p_junk, "", 1) != 0)
    {
        puts("Timeout must be a number");
        status = -1;
        goto END;
    }

    if (arg_num < TIMEOUT_MIN || arg_num > TIMEOUT_MAX)
    {
        printf("Timeout must be %d - %d", TIMEOUT_MIN, TIMEOUT_MAX);
        status = -1;
        goto END;
    }

    status = arg_num;

END:
    return status;
}

int
validate_dir(char **pp_server_dir, char *p_cmd_dir)
{
    int    status    = 0;
    int    result    = 0;
    int    num_bytes = 0;
    size_t safe_len  = 0;

    char        safe_buf[PATH_MAX] = { 0 };
    char        comp_buf[PATH_MAX] = { 0 };
    char        resolved[PATH_MAX] = { 0 };
    char *      p_pwd              = NULL; // Present working directory.
    const char *p_fmt              = NULL;

    const char *p_root = "/test/server";

    p_pwd = getcwd(NULL, 0);
    if (NULL == p_pwd)
    {
        perror("getcwd");
        status = -1;
        goto END;
    }

    /* Appends the present working dir to the root directory. */
    num_bytes = snprintf(safe_buf, sizeof(safe_buf), "%s%s", p_pwd, p_root);
    if (num_bytes <= 0)
    {
        puts("snprintf error");
        status = -1;
        goto END;
    }

    safe_len = strnlen(safe_buf, PATH_MAX);

    /* Checks if / was given or not. */
    if (strncmp(p_cmd_dir, "/", 1) == 0)
    {
        p_fmt = "%s%s";
    }
    else if (strncmp(p_cmd_dir, "/", 1) != 0)
    {
        p_fmt = "%s/%s";
    }
    else
    {
        status = -1;
        goto END;
    }

    /* Appends the cmd line directory arg to the safe directory. */
    num_bytes
        = snprintf(comp_buf, sizeof(comp_buf), p_fmt, safe_buf, p_cmd_dir);
    if (num_bytes <= 0)
    {
        puts("snprintf error");
        status = -1;
        goto END;
    }

    if (num_bytes > PATH_MAX)
    {
        puts("Root path too big");
        status = -1;
        goto END;
    }

    realpath(comp_buf, resolved);

    /* Resolve the directory and check against safe directory. */
    result = strncmp(resolved, safe_buf, safe_len);
    if (result != 0)
    {
        status = -1;
        goto END;
    }

    *pp_server_dir = (char *)calloc(num_bytes + 1, sizeof(char));
    if (NULL == pp_server_dir)
    {
        perror("root dir calloc");
        status = -1;
        goto END;
    }

    memcpy(*pp_server_dir, &resolved, num_bytes);

END:
    if (p_pwd != NULL)
    {
        free(p_pwd);
    }

    return status;
}

void
create_sig_handler(int signum, void (*p_func)(int))
{
    struct sigaction sa = { .sa_handler = p_func };
    if (sigaction(signum, &sa, NULL) == -1)
    {
        perror("Sigaction:");
    }
}

int
server_start(char *p_port, char *p_server_dir, int timeout)
{
    /*--------------------------Set up variables--------------------------*/
    /* Server */
    int status    = 0; // Status of server.
    int main_sock = 0; // Main socket of server.

    /* Signal handling */
    sigset_t *p_block     = NULL;
    sigset_t *p_non_block = NULL;

    /* Login hash table */
    server_i *p_login = NULL;
    /*--------------------------------------------------------------------*/

    /*-----------------Set up socket, sigsets, login system---------------*/
    status = generate_server(&main_sock, p_port);
    if (status != 0)
    {
        goto EXIT;
    }

    status = make_root_dir(p_server_dir);
    if (status != 0)
    {
        puts("Make server root dir error");
        goto EXIT;
    }

    status = fill_sigsets(&p_block, &p_non_block);
    if (status != 0)
    {
        puts("Fill sigsets error...");
        goto EXIT;
    }

    status = login_system_start(&p_login, p_server_dir, timeout, p_non_block);
    if (NULL == p_login)
    {
        puts("Login system generation fail");
        goto EXIT;
    }
    /*--------------------------------------------------------------------*/

    /*---------------------------Run server-------------------------------*/
    status = server_loop(main_sock, &p_non_block, &p_login);
    /*--------------------------------------------------------------------*/

EXIT:
    return status;
}

int
make_root_dir(char *p_server_dir)
{
    int status = 0;

    /* Creates server root directory */
    status = mkdir(p_server_dir, S_IRWXU | S_IRWXG | S_IRWXO);
    if ((status == -1) && (errno == EEXIST))
    {
        status = 0;
    }
    else if ((status == -1) && (errno != EEXIST))
    {
        perror("root mkdir");
    }

    return status;
}

int
fill_sigsets(sigset_t **pp_block, sigset_t **pp_non_block)
{
    int status = 0;

    status = sigfillset(*pp_block); // Fill set with every signal.
    status = sigprocmask(SIG_BLOCK, *pp_block, NULL); // Block all signals.

    status = sigemptyset(*pp_non_block);       // Set with no signals.
    status = sigaddset(*pp_non_block, SIGINT); // For CTRL-C.
    status = sigprocmask(SIG_UNBLOCK, *pp_non_block, NULL); // Unblock CTRL-C.

    /* Bulk status check on return */

    return status;
}

int
login_system_start(server_i **pp_login,
                   char *     p_server_dir,
                   int        timeout,
                   sigset_t * p_non_block)
{
    int status = 0;

    size_t dir_str_len = 0;

    creds_i admin;
    size_t  admin_hash = 0;

    admin.p_user     = NULL;
    admin.p_pwd      = NULL;
    admin.permission = 0;

    *pp_login = create_hash(FOPEN_MAX);
    if (NULL == *pp_login)
    {
        goto END;
    }

    dir_str_len = strnlen(p_server_dir, PATH_MAX);

    /* Inserts server metadata into hashtable struct. */
    (*pp_login)->time_out   = timeout;
    (*pp_login)->p_root_dir = strndup(p_server_dir, dir_str_len);
    free(p_server_dir);
    (*pp_login)->p_feeder = p_non_block;
    memset((*pp_login)->threads, 0, sizeof((*pp_login)->threads));

    /* Generates default admin~password creds. */
    admin.p_user     = strndup("admin", 5);
    admin.p_pwd      = strndup("password", 8);
    admin.permission = ADMIN;

    admin_hash = hash(admin.p_user);

    status = insert_node(*pp_login, admin_hash, &admin);
    if (status != 0)
    {
        puts("Hash table insertion error");
    }

END:
    if (admin.p_user != NULL)
    {
        free(admin.p_user);
    }
    if (admin.p_pwd != NULL)
    {
        free(admin.p_pwd);
    }

    return status;
}

int
server_loop(int main_sock, sigset_t **pp_non_block, server_i **pp_login)
{
    /*--------------------------Set up variables--------------------------*/
    /* Server variables */
    int status = 0; // Status of server.

    /* Client/thread count */
    int *count = NULL;

    /* Epoll */
    struct epoll_event events[FOPEN_MAX] = { 0 };
    int nfds = 0, epollfd = 0; // Number of file descriptors, and epoll fd.
    /*--------------------------------------------------------------------*/

    count = (int *)calloc(1, sizeof(int));
    if (NULL == count)
    {
        perror("Count calloc");
        goto EXIT;
    }

    /*----------------Generates epoll fd for main socket------------------*/
    status = create_epoll(&epollfd, main_sock);
    if (status != 0)
    {
        puts("Cannot create epoll...");
        goto EXIT;
    }
    /*--------------------------------------------------------------------*/

    /*----------------------------Server loop-----------------------------*/
    puts("Waiting for connections...\n**********************");
    while (gb_main_loop)
    {
        /*-------If max threads are used, wait for some to close------*/
        while (((*count) >= FOPEN_MAX) || (g_jobs == FOPEN_MAX))
        {
            puts("Max clients connected...waiting");
            printf("Clients connected: %d\n", g_jobs);
            printf("Count before: %d\n", *count);
            sleep(3);

            (*count) = check_clients((*pp_login)->threads);
            while ((*count == -1))
            {
                sleep(3);
                (*count) = check_clients((*pp_login)->threads);
            }
        }

        /* pwait waits for ready fd or caught signal */
        nfds = epoll_pwait(epollfd, events, FOPEN_MAX, -1, *pp_non_block);
        if (errno == EINTR)
        {
            ;
        }
        else if (nfds == -1)
        {
            perror("epoll_wait");
            break;
        }

        status = epoll_handler(nfds, main_sock, &count, events, *pp_login);
        if (status != 0)
        {
            puts("epoll handler error");
        }
    }
    /*--------------------------------------------------------------------*/

EXIT:
    if (main_sock != 0)
    {
        close_socket(&main_sock);
    }

    if (count != NULL)
        free(count);

    if (*pp_login != NULL)
    {
        cleanup(*pp_login);
    }

    return status;
}

int
check_clients(pthread_t *p_threads)
{
    int free_thread = -1;
    /* Loop through all client array and see if any slots are open */
    for (int i = 0; i < FOPEN_MAX; i++)
    {
        if (p_threads[i] == 0)
        {
            free_thread = i;
            return free_thread;
        }
    }

    return free_thread;
}

int
create_epoll(int *fd, int sock)
{
    int status = 0;

    struct epoll_event event = { 0 };

    *fd = epoll_create1(0);
    if (*fd == -1)
    {
        perror("epoll_create1");
        status = -1;
        goto EXIT;
    }

    /* Add server/listening socket into epoll event struct */
    event.events  = EPOLLIN;
    event.data.fd = sock;

    status = epoll_ctl(*fd, EPOLL_CTL_ADD, sock, &event);
    if (status == -1)
    {
        perror("epoll_ctl: main_sock");
    }

EXIT:
    return status;
}

int
epoll_handler(int                nfds,
              int                sock,
              int **             pp_count,
              struct epoll_event evs[],
              server_i *         p_login)
{
    int status = 0;

    for (int x = 0; x < nfds; ++x)
    {
        /* If main sock is ready to receive data */
        if (evs[x].data.fd == sock)
        {
            status = accept_connection(sock, *pp_count, p_login);
            if (status != 0)
            {
                puts("Could not accept client");
            }
            else
            {
                (**pp_count)++; // Increment client/thread index.
            }
        }
    }

    return status;
}

int
accept_connection(int main_sock, int *p_count, server_i *p_login)
{
    int status = 0; // Thread check.

    int                conn_sock = 0;     // Client socket file descriptor.
    struct sockaddr_in conn      = { 0 }; // Connection struct information.
    socklen_t          size      = sizeof(conn); // Size of address.

    client_i *p_client = NULL; // Tracker of clients.

    if (gb_main_loop == false)
    {
        puts("Thread not creating");
        goto END;
    }

    //------------------------------------------------------------*/

    conn_sock = accept(main_sock, (struct sockaddr *)&conn, &size);
    if (conn_sock == -1)
    {
        perror("accept");
        status = -1;
        goto END;
    }

    insert_cli(
        &p_client, *p_count, conn_sock, conn.sin_addr, conn.sin_port, p_login);
    if (NULL == p_client)
    {
        puts("Malloc error");
        status = -1;
        goto END;
    }

    status = pthread_sigmask(SIG_UNBLOCK, p_client->p_login->p_feeder, NULL);

    /*--------------------Generate thread for each client-----------------*/
    /* Create thread for the client */
    status = pthread_create(
        &((p_login)->threads[*p_count]), NULL, &conn_event, (void *)(p_client));
    if (status != 0)
    {
        perror("Could not create thread");
        goto END;
    }
    /* Detatch thread */
    status = pthread_detach((p_login)->threads[*p_count]);
    if (status != 0)
    {
        perror("Could not detach thread");
        pthread_join((p_login)->threads[*p_count], NULL);
    }
END:
    return status;
}

void
insert_cli(client_i **    pp_client,
           int            i,
           int            conn_sock,
           struct in_addr ip,
           in_port_t      port,
           server_i *     p_login)
{
    char *str_ip = inet_ntoa(ip);

    *pp_client = (client_i *)malloc(sizeof(client_i));
    if (NULL == pp_client)
    {
        perror("Malloc client metadata");
    }

    memset((*(pp_client))->conn_ip, 0, sizeof((*(pp_client))->conn_ip));

    // Files client struct data.
    //
    (*(pp_client))->cli_num   = i;
    (*(pp_client))->conn_sock = conn_sock;
    memcpy((*(pp_client))->conn_ip, str_ip, strnlen(str_ip, INET6_ADDRSTRLEN));
    (*(pp_client))->port       = ntohs(port);
    (*(pp_client))->s_id       = 0;
    (*(pp_client))->p_login    = p_login;
    (*(pp_client))->permission = 0;

    puts("\n----------------");
    puts("---[+] Connection from [+]---");
    printf("      |%s:%d|\n", (*(pp_client))->conn_ip, (*(pp_client))->port);
    puts("-----------------------------\n");
}

bool
check_conn(int errors, client_i *p_client)
{
    int status = 0;

    struct timeval timeout;
    timeout.tv_sec  = 0;
    timeout.tv_usec = 0;

    bool conn = true;

    /* If main_loop atomic is trigger from signal, quit */
    if (gb_main_loop == false)
    {
        puts("[SYSTEM] Main loop break");
        conn = false;
        goto END;
    }
    /*-----------------------------------------------*/

    /* If there is a sock error during SEND/RECV */
    if (errno == EPIPE || errno == ECONNRESET)
    {
        puts("[-] Pipe error");
        conn = false;
        goto END;
    }
    /*-----------------------------------------*/

    /* If the client times out from inactivity, reset s_id. */
    if (errno == EAGAIN)
    {
        puts("[-] Timed out");
        p_client->s_id       = 0;
        p_client->permission = 0;
        errno                = 0;

        status = setsockopt(p_client->conn_sock,
                            SOL_SOCKET,
                            SO_RCVTIMEO,
                            &timeout,
                            sizeof(timeout));
        if (status != 0)
        {
            perror("setsockopt recv timeout failed\n");
            conn = false;
            goto END;
        }

        status = setsockopt(p_client->conn_sock,
                            SOL_SOCKET,
                            SO_SNDTIMEO,
                            &timeout,
                            sizeof(timeout));
        if (status != 0)
        {
            perror("setsockopt send timeout failed\n");
            conn = false;
            goto END;
        }
    }

    /* If send/recv keeps throwing errors, terminate connection */
    if (errors >= 1)
    {
        if (errors == 1)
        {
            puts("[SYSTEM] Closing connection...");
        }
        else
        {
            puts("[SYSTEM] Error with connection. Closing...");
        }

        conn = false;
        goto END;
    }
    /*-------------------------------------------------------*/
END:
    return conn;
}

bool
validate_s_id(client_i *p_client, char *p_buf, uint8_t opcode)
{
    bool     id_valid = false;
    uint32_t s_id     = 0;

    switch (opcode)
    {
        case USER:
            s_id = ((user_request_i *)p_buf)->s_id;

            break;

        case RM:
            s_id = ((rm_request_i *)p_buf)->s_id;

            break;

        case LS:
            s_id = ((ls_request_i *)p_buf)->s_id;

            break;

        case GET:
            s_id = ((get_request_i *)p_buf)->s_id;

            break;

        case MKDIR:
            s_id = ((mkdir_request_i *)p_buf)->s_id;

            break;
        case PUT:
            s_id = ((put_request_i *)p_buf)->s_id;

            break;
        default:
            puts("[SYSTEM] OPCODE failsafe");
            break;
    }

    s_id = ntohl(s_id);

    /* Validates s_id of client against requesting packet. */
    if ((s_id == p_client->s_id) && (p_client->s_id != 0))
    {
        id_valid = true;
    }

    return id_valid;
}

void *
conn_event(void *p_client)
{
    /*--------------------------Set up variables--------------------------*/
    int status      = 0;
    int err_counter = 0;

    bool valid_conn = true;

    sigset_t thread_set;
    sigfillset(&thread_set);
    pthread_sigmask(SIG_BLOCK, &thread_set, NULL); // Block all signals.
    /*--------------------------------------------------------------------*/

    /*------Lock and unlock jobs atomic (Used for graceful shutdown)------*/
    pthread_mutex_lock(&g_job_lock);
    g_jobs++;
    pthread_mutex_unlock(&g_job_lock);

    srand((unsigned int)time(NULL)); // For generating a psuedo-random number.
    /*--------------------------------------------------------------------*/

    /*--------------------------Connection loop---------------------------*/
    while (valid_conn == true)
    {

        valid_conn = check_conn(err_counter, ((client_i *)(p_client)));
        if (valid_conn == false)
        {
            break;
        }

        status = dispatcher(((client_i *)(p_client)), &err_counter);
        if (status == -1)
        {
            puts("[SYSTEM] Something broke");
            // Checking connection next anyway.
        }

        valid_conn = check_conn(err_counter, ((client_i *)(p_client)));
        if (valid_conn == false)
        {
            break;
        }

        printf("-------[~] Client %d Event END [~]-------\n\n",
               ((client_i *)(p_client))->cli_num);

        continue;
        /*------------------------------------------------------------*/
    }
    /*--------------------------------------------------------------------*/

    /*---Clean up on exit---*/
    if (((client_i *)(p_client))->conn_sock != 0)
    {
        close_socket(&(((client_i *)(p_client))->conn_sock));
    }

    printf("[-] Client %d disconnected\n", (((client_i *)(p_client))->cli_num));

    pthread_mutex_lock(&g_job_lock);
    g_jobs--; // Decs from jobs (for gracefull thread shutdown).
    if (((client_i *)(p_client))->p_login->threads != NULL)
    {
        /* Ugly thing that sets the thread array index to 0 (free to use). */
        ((client_i *)(p_client))
            ->p_login->threads[((client_i *)(p_client))->cli_num]
            = 0;
    }
    pthread_mutex_unlock(&g_job_lock);

    if (p_client != NULL)
    {
        free(p_client);
    }

    pthread_exit(&status);
}

static void
handler(int signum)
{
    (void)signum;

    switch (signum)
    {
        // Add other signals here.
        case SIGINT:
            gb_main_loop = false;
            break;
        default:
            puts("\nHow did this happen!?");
            break;
    }

    pthread_mutex_lock(&g_exit_lock);
    while (g_jobs != 0)
    {
        puts("Attempting to exit...");
        puts("\nWaiting for all threads to close");
        printf("Jobs remaining: %d\n", g_jobs);
        sleep(3);
    }
    pthread_mutex_unlock(&g_exit_lock);
}

/*** end of file ***/
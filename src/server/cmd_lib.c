/** @file cmd_lib.c
 *
 * @brief A library for ftp cmd related code.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2000, 2018 Michael Barr. This software is placed in the
 * public domain and may be used for any purpose. However, this notice must not
 * be changed or removed. No warranty is expressed or implied by the publication
 * or distribution of this source code.
 */

#include "header/includes.h"
#include "header/cmd_lib.h"

int
dispatcher(client_i *p_client, int *p_err)
{
    /*-----------------Variables------------------*/
    int status = 0;

    uint8_t opcode   = 0;
    uint8_t usercode = 0;
    uint8_t retcode  = 0;

    ssize_t sent_bytes = 0;
    ssize_t recv_bytes = 0;

    bool b_valid_s_id = false;

    char buf[MTU] = { 0 }; // Receiving initial packet from client.

    void *p_recv = NULL; // Receive packet.
    void *p_send = NULL; // Send packet.

    /*---------------------------------------------*/

    printf("[~] Client %d waiting for CMD\n", p_client->cli_num);

    /*-----------------------CMD from Client----------------------*/
    recv_bytes = receive_data(&(p_client->conn_sock), buf, MTU);
    if (recv_bytes <= 0)
    {
        if (errno == EAGAIN)
        {
            goto END;
        }
        else
        {
            (*p_err)++;
        }
    }

    opcode = ((uint8_t)buf[0]);
    if ((opcode == 0) && ((*p_err) == 1))
    {
        puts("[~] Client terminated connection");
        goto END;
    }
    else if ((opcode < 1) || (opcode > 6))
    {
        puts("[SYSTEM] Invalid opcode");
        (*p_err)++;
        goto END;
    }
    usercode = ((uint8_t)buf[1]);

    /* If login event, skip session id auth */
    if ((opcode == USER) && (usercode == LOGIN))
    {
        /* Function ptr dict to populate different received packets */
        (*pop_request_packet[opcode])(&p_recv, buf);
        /*---------------------------------------------------------*/
    }
    /*----------------Check if session ID is valid----------------*/
    else
    {
        b_valid_s_id = validate_s_id(p_client, buf, opcode);

        /* If s_id is not valid, send s_err back. */
        if (b_valid_s_id != true)
        {
            retcode = S_ERR;
            (*pop_error_packet[opcode])(&p_send, retcode);
            send_data(&(p_client->conn_sock), &p_send, MTU);
            goto END;
        }
        else
            (*pop_request_packet[opcode])(&p_recv, buf);
    }

    /*---------------Parse cmd recvieved from client--------------*/
    printf("\n------[~] Client %d Event START [~]------\n", p_client->cli_num);
    switch (opcode)
    {
        case USER:
            switch (usercode)
            {
                case LOGIN:
                    puts("[SYSTEM] USER login");
                    user_login(&p_recv, &p_send, p_client);
                    break;

                case R_ONLY:
                case RW_ONLY:
                case ADMIN:
                    puts("[SYSTEM] USER create");
                    user_create(&p_recv, &p_send, p_client);
                    break;

                case DEL:
                    puts("[SYSTEM] USER delete");
                    user_delete(&p_recv, &p_send, p_client);
                    break;
            }
            break;

        case RM:
            puts("[SYSTEM] RM event");
            remove_file(&p_recv, &p_send, p_client);
            break;

        case LS:
            puts("[SYSTEM] LS event");
            ls_directory(&p_recv, &p_send, p_client);
            break;

        case GET:
            puts("[SYSTEM] GET event");
            get_file(&p_recv, &p_send, p_client);
            break;

        case MKDIR:
            puts("[SYSTEM] MKDIR event");
            make_directory(&p_recv, &p_send, p_client);
            break;
        case PUT:
            puts("[SYSTEM] PUT event");
            put_file(&p_recv, &p_send, p_client);
            break;
        default:
            (*p_err)++;
            goto END;
    }

    /* Send populated send packet back to client. */
    sent_bytes = send_data(&(p_client->conn_sock), &p_send, MTU);
    if (sent_bytes <= 0)
    {
        (*p_err)++;
    }

END:
    return status;
}

void
user_login(void **pp_request_tmp, void **pp_reply_tmp, client_i *p_client)
{
    /*-----------------Variables------------------*/
    int status     = 0;
    int tmp_status = 0;
    int ran_num    = 0; // For generating Session ID.

    char * p_username = NULL;
    char * p_password = NULL;
    size_t pass_len   = 0; // Len of pasword from packet.

    bool b_lock_flag = false; // For mutex lock gracefull shutdown.

    user_request_i *p_request = (user_request_i *)pp_request_tmp;
    user_reply_i *  p_reply   = (user_reply_i *)pp_reply_tmp;

    char *p_free_me = ((user_request_i *)(pp_request_tmp))->p_data;

    p_username = strndup(p_request->p_data, p_request->u_len);
    p_password
        = strndup(p_request->p_data + p_request->u_len, p_request->p_len);
    pass_len = strnlen(p_password, PASSWORD_MAX);
    /*-------------------------------------------*/

    status = pthread_mutex_lock(&g_data_lock);
    if (status != 0)
    {
        puts("[-] RM failed: Could not lock rw mutex");
        goto END;
    }
    b_lock_flag = true;

    /* Search for username before doing anything. */
    size_t  hash_num = hash(p_username);
    data_i *result   = search_node(p_client->p_login, hash_num);
    if (NULL == result)
    {
        puts("[SYSTEM] Username not found");
    }

    /* Core check to see if creds match. If pass, set data. */
    if ((result != NULL)
        && (strncmp(result->p_creds->p_pwd, p_password, pass_len) == 0))
    {
        struct timeval timeout;
        timeout.tv_sec  = p_client->p_login->time_out;
        timeout.tv_usec = 0;

        ran_num = rand();

        p_reply->retcode = SUCCESS;
        p_reply->rsvd    = 0;
        p_reply->s_id    = (((uint32_t)(hash(p_password))) + ran_num);

        p_client->s_id       = p_reply->s_id;
        p_client->permission = result->p_creds->permission;

        /* Session time out is set here (recv timeout). */
        status = setsockopt(p_client->conn_sock,
                            SOL_SOCKET,
                            SO_RCVTIMEO,
                            &timeout,
                            sizeof(timeout));
        if (status != 0)
        {
            puts("[-] Login failed: recv timeout set fail");
            goto END;
        }

        /* Session time out is set here (send timeout). */
        status = setsockopt(p_client->conn_sock,
                            SOL_SOCKET,
                            SO_SNDTIMEO,
                            &timeout,
                            sizeof(timeout));
        if (status != 0)
        {
            puts("[-] Login failed: send timeout set fail");
            goto END;
        }

        printf("[+] Login Success: s_id-> %d\n", p_reply->s_id);
    }
    else
    {
        puts("[-] Login failed: creds do not exist");
        status = -1;
    }

END:
    tmp_status = status;

    if (b_lock_flag == true)
    {
        status = pthread_mutex_unlock(&g_data_lock);
        if (status != 0)
        {
            puts("[-] Login failed: Could not unlock rw mutex");
        }
    }

    if (status == -1)
    {
        ;
    }
    else
    {
        status = tmp_status;
    }

    /* Make sure to send back correct s_id */
    if (status != 0)
    {
        p_reply->retcode = FAIL;
        p_reply->rsvd    = 0;
        if (p_client->s_id == 0)
        {
            p_reply->s_id = 0;
        }
        else
        {
            p_reply->s_id = p_client->s_id;
        }
    }

    p_reply->s_id = htonl(p_reply->s_id);

    free(p_free_me);
    free(p_username);
    free(p_password);
}

void
user_create(void **pp_request_tmp, void **pp_reply_tmp, client_i *p_client)
{
    /*-----------------Variables------------------*/
    /* Same in all user events */
    int status     = 0;
    int tmp_status = 0;

    char *p_username = NULL;
    char *p_password = NULL;

    bool b_lock_flag = false;

    user_request_i *p_request = (user_request_i *)pp_request_tmp;
    user_reply_i *  p_reply   = (user_reply_i *)pp_reply_tmp;

    char *p_free_me = ((user_request_i *)(pp_request_tmp))->p_data;

    p_username = strndup(p_request->p_data, p_request->u_len);
    p_password
        = strndup(p_request->p_data + p_request->u_len, p_request->p_len);
    /*-------------------------------------------*/

    status = pthread_mutex_lock(&g_data_lock);
    if (status != 0)
    {
        puts("[-] RM failed: Could not lock rw mutex");
        goto END;
    }
    b_lock_flag = true;

    /* Search for username before doing anything. */
    size_t  hash_num = hash(p_username);
    data_i *result   = search_node(p_client->p_login, hash_num);
    if (NULL == result)
    {
        puts("[SYSTEM] Username not found");
    }

    /* Creating a user. */
    if (result == NULL)
    {
        bool    valid_permission = false;
        uint8_t action           = p_request->flag;
        valid_permission = check_permissions(p_client->permission, action);
        if (valid_permission == true)
        {
            creds_i user;
            size_t  user_hash = 0;

            user.p_user     = p_username;
            user.p_pwd      = p_password;
            user.permission = p_request->flag;

            user_hash = hash(user.p_user);

            status = insert_node(p_client->p_login, user_hash, &user);
            if (status != 0)
            {
                puts("[-] Create user failed");
                p_reply->retcode = FAIL;
                goto END;
            }
            else
            {
                puts("[+] Create user Success");
                p_reply->retcode = SUCCESS;
            }
        }
        else
        {
            puts("[-] Create user P_ERR");
            p_reply->retcode = P_ERR;
            goto END;
        }
    }
    else
    {
        puts("[-] Create user U_EXIST");
        p_reply->retcode = U_EXIST;
    }

END:
    tmp_status = status;

    if (b_lock_flag == true)
    {
        status = pthread_mutex_unlock(&g_data_lock);
        if (status != 0)
        {
            puts("[-] User create failed: Could not unlock rw mutex");
        }
    }

    if (status == -1)
    {
        ;
    }
    else
    {
        status = tmp_status;
    }

    /* Same as above. */
    if (status != 0)
    {
        p_reply->retcode = FAIL;
        p_reply->rsvd    = 0;
        if (p_client->s_id == 0)
        {
            p_reply->s_id = 0;
        }
        else
        {
            p_reply->s_id = p_client->s_id;
        }
    }

    p_reply->s_id = htonl(p_reply->s_id);

    free(p_free_me);
    free(p_username);
    free(p_password);
}

void
user_delete(void **pp_request_tmp, void **pp_reply_tmp, client_i *p_client)
{
    /*-----------------Variables------------------*/
    /* Same as above */
    int status     = 0;
    int tmp_status = 0;

    char *p_username = NULL;
    char *p_password = NULL;

    bool b_lock_flag = false; // For mutex lock gracefull shutdown.

    user_request_i *p_request = (user_request_i *)pp_request_tmp;
    user_reply_i *  p_reply   = (user_reply_i *)pp_reply_tmp;

    char *p_free_me = ((user_request_i *)(pp_request_tmp))->p_data;

    p_username = strndup(p_request->p_data, p_request->u_len);
    p_password
        = strndup(p_request->p_data + p_request->u_len, p_request->p_len);

    /*-------------------------------------------*/

    status = pthread_mutex_lock(&g_data_lock);
    if (status != 0)
    {
        puts("[-] RM failed: Could not lock rw mutex");
        goto END;
    }
    b_lock_flag = true;

    /* Search for username before doing anything. */
    size_t  hash_num = hash(p_username);
    data_i *result   = search_node(p_client->p_login, hash_num);
    if (NULL == result)
    {
        puts("[SYSTEM] Username not found");
    }

    if (result != NULL)
    {
        bool    valid_permission = false;
        uint8_t action           = ADMIN;

        /* Only admin's can delete, to include themselves. */
        valid_permission = check_permissions(p_client->permission, action);
        if (valid_permission == true)
        {

            status = delete_node(p_client->p_login, hash_num);
            if (status != 0)
            {
                puts("[-] Delete user failed");
                p_reply->retcode = FAIL;
                goto END;
            }
            else
            {
                puts("[+] Delete user Success");
                p_reply->retcode = SUCCESS;
            }
        }
        else
        {
            puts("[-] Delete user failed: P_ERR");
            p_reply->retcode = P_ERR;
            goto END;
        }
    }
    else
    {
        puts("[-] Delete user failed: User does not exist");
        p_reply->retcode = FAIL;
        goto END;
    }

END:
    tmp_status = status;

    if (b_lock_flag == true)
    {
        status = pthread_mutex_unlock(&g_data_lock);
        if (status != 0)
        {
            puts("[-] RM failed: Could not unlock rw mutex");
        }
    }

    if (status == -1)
    {
        ;
    }
    else
    {
        status = tmp_status;
    }

    if (status != 0)
    {
        p_reply->retcode = FAIL;
        p_reply->rsvd    = 0;
        if (p_client->s_id == 0)
        {
            p_reply->s_id = 0;
        }
        else
        {
            p_reply->s_id = p_client->s_id;
        }
    }

    p_reply->s_id = htonl(p_reply->s_id);

    free(p_free_me);
    free(p_username);
    free(p_password);
}

bool
check_permissions(uint8_t permission, uint8_t action)
{
    bool result = false;

    switch (action)
    {
        case R_ONLY:
            switch (permission)
            {
                case ADMIN:
                case RW_ONLY:
                case R_ONLY:
                    result = true;
            }
        case RW_ONLY:
            switch (permission)
            {
                case ADMIN:
                case RW_ONLY:
                    result = true;
            }
        case ADMIN:
            switch (permission)
            {
                case ADMIN:
                    result = true;
            }
    }
    return result;
}

void
remove_file(void **pp_request_tmp, void **pp_reply_tmp, client_i *p_client)
{
    /*-----------------Variables------------------*/
    int status     = 0;
    int tmp_status = 0;

    bool b_gatekeeper = false;
    bool b_lock_flag  = false;

    char *      p_file_name        = NULL;
    struct stat attrs              = { 0 };
    uint8_t     action             = 0;
    size_t      bytes              = 0;
    char        fullpath[PATH_MAX] = { 0 };

    rm_request_i *p_request = (rm_request_i *)pp_request_tmp;
    rm_reply_i *  p_reply   = (rm_reply_i *)pp_reply_tmp;

    char *p_free_me = p_request->p_data;
    /*--------------------------------------------*/

    p_file_name = strndup(p_request->p_data, p_request->len);

    action       = RW_ONLY;
    b_gatekeeper = check_permissions(p_client->permission, action);
    if (b_gatekeeper == false)
    {
        puts("[-] RM file failed: P_ERR");
        p_reply->retcode = P_ERR;
        status           = -1;
        goto END;
    }

    /* Combines requests file with server root directory. */
    bytes = snprintf(fullpath,
                     sizeof(fullpath),
                     "%s/%s",
                     p_client->p_login->p_root_dir,
                     p_file_name);
    if (bytes <= 0)
    {
        puts("[-] RM file failed: snprintf error!?");
        p_reply->retcode = FAIL;
        status           = -1;
        goto END;
    }
    bytes = 0;

    status = pthread_rwlock_wrlock(&g_file_lock);
    if (status != 0)
    {
        puts("[-] RM failed: Could not lock rw mutex");
        goto END;
    }
    b_lock_flag = true;

    b_gatekeeper = check_path(fullpath, p_client);
    if (b_gatekeeper == false)
    {
        puts("[-] RM file failed: Out of root directory");
        p_reply->retcode = FAIL;
        status           = -1;
        goto END;
    }

    /* Checks to see if file exists. */
    status = get_attributes(fullpath, &attrs);
    if (status != 0)
    {
        puts("[-] RM file failed: File not found");
        p_reply->retcode = FAIL;
        goto END;
    }

    status = delete_file(fullpath);
    if (status != 0)
    {
        puts("[-] RM file failed: Could not delete file");
        p_reply->retcode = FAIL;
        goto END;
    }

END:
    tmp_status = status;
    if (b_lock_flag == true)
    {
        status = pthread_rwlock_unlock(&g_file_lock);
        if (status != 0)
        {
            puts("[-] LS failed: Could not unlock rw mutex");
        }
    }

    if (status == -1)
    {
        ;
    }
    else
    {
        status = tmp_status;
    }

    if (status == 0)
    {
        puts("[+] RM file Success");
        p_reply->retcode = SUCCESS;
    }

    free(p_free_me);
    free(p_file_name);
}

void
ls_directory(void **pp_request_tmp, void **pp_reply_tmp, client_i *p_client)
{
    /*-----------------Variables------------------*/
    int status     = 0;
    int tmp_status = 0;

    ssize_t net_bytes       = 0;
    size_t  tmp_bytes       = 0;
    size_t  bytes           = 0;
    char    buf[PACKET_MAX] = { 0 }; // For calculating the size of the dir.

    /* Packet strucs to store data. */
    ls_request_i *p_request     = (ls_request_i *)pp_request_tmp;
    ls_reply_i *  p_reply       = (ls_reply_i *)pp_reply_tmp;
    ls_request_i  multi_request = { 0 }; // Used if data > size of one packet.

    /* Directory path variables. */
    char *p_tmp_directory     = NULL;
    char  directory[PATH_MAX] = { 0 };
    char  file_path[PATH_MAX] = { 0 };

    char *p_fmt = NULL;

    /* Directory specific variables. */
    DIR *          p_dir_fd     = NULL;
    struct dirent *p_dir_ptr    = NULL;
    struct stat    dir_data     = { 0 };
    bool           b_gatekeeper = false;
    bool           b_lock_flag  = false;

    char *p_free_me = p_request->p_data;
    /*-------------------------------------------*/

    /* Combines requests directory with server root directory. */
    p_tmp_directory = strndup(p_request->p_data, p_request->len);
    if (strncmp(p_tmp_directory, ".", 2) == 0)
    {
        p_fmt = "%s/";
    }
    else
    {
        p_fmt = "%s/%s";
    }

    bytes = snprintf(directory,
                     sizeof(directory),
                     p_fmt,
                     p_client->p_login->p_root_dir,
                     p_tmp_directory);
    if (bytes <= 0)
    {
        puts("[-] LS failed: snprintf error[1]!?");
        status = -1;
        goto END;
    }
    bytes = 0;

    status = pthread_rwlock_wrlock(&g_file_lock);
    if (status != 0)
    {
        puts("[-] LS failed: Could not lock rw mutex");
        goto END;
    }
    b_lock_flag = true;

    /* Validates requested directory. */
    b_gatekeeper = check_path(directory, p_client);
    if (b_gatekeeper == false)
    {
        puts("[-] LS failed: Out of root directory");
        status = -1;
        goto END;
    }

    p_dir_fd = opendir(directory);
    if (NULL == p_dir_fd)
    {
        puts("[-] LS failed: Cannot open directory");
        status = -1;
        goto END;
    }
    /*--------------------------------*/

    /*------------Get size of file/subdir names----------*/
    while ((p_dir_ptr = readdir(p_dir_fd)))
    {
        uint8_t type = 0x01;

        tmp_bytes = snprintf(buf, sizeof(buf), "%x%s", type, p_dir_ptr->d_name);
        if (bytes < 0)
        {
            puts("[-] LS failed: snprintf error[2]!?");
            status = -1;
            goto END;
        }
        tmp_bytes += 1; // Add one extra byte for /x00.
        if ((tmp_bytes + bytes) > PACKET_MAX)
        {
            memset(&buf, 0, sizeof(buf));
        }
        bytes += tmp_bytes;
    }

    status = closedir(p_dir_fd);
    if (status != 0)
    {
        puts("[-] LS failed: Could not close directory");
        goto END;
    }

    p_dir_fd  = NULL;
    p_dir_ptr = NULL;

    p_reply->data_len = htonl((uint32_t)bytes);

    /*-----------------------Generate packet(s) to send-----------------------*/
    p_dir_fd = opendir(directory);
    if (NULL == p_dir_fd)
    {
        puts("[-] LS failed: Could not open directory");
        status = -1;
        goto END;
    }

    /* Clear variables. */
    tmp_bytes               = 0;
    bytes                   = 0;
    int      packets        = 0;
    uint32_t position       = 0;
    size_t   offset         = 0;
    size_t   check_snprintf = 0;

    memset(&(p_reply->data), 0, sizeof(p_reply->data));

    //------------Parse directory----------//
    while ((p_dir_ptr = readdir(p_dir_fd)))
    {
        size_t  name_len = 0;
        uint8_t type     = 0;

        /* Store name into file_path buffer. */
        check_snprintf = snprintf(
            file_path, sizeof(file_path), "%s%s", directory, p_dir_ptr->d_name);
        if (check_snprintf <= 0)
        {
            puts("[-] LS failed: snprintf error[3]!?");
            status = -1;
            goto END;
        }

        stat(file_path, &dir_data);
        if (S_ISDIR(dir_data.st_mode))
        {
            type = 0x01;
        }
        else
        {
            type = 0x02;
        }
        memset(&file_path, 0, sizeof(file_path));

        name_len = strnlen(p_dir_ptr->d_name, FILENAME_MAX);

        /* If future size of packet exceeds the max allowed size, split send. */
        if (((name_len + 2) + bytes) > PACKET_MAX) // 2 is for /x00 and uint8_t.
        {
            p_reply->retcode = SUCCESS;
            p_reply->msg_len = htonl((uint32_t)bytes);
            p_reply->pos     = htonl(position);

            /* Send current buffer. */
            net_bytes = send_data(&(p_client->conn_sock), p_reply, MTU);
            if (net_bytes < 0)
            {
                status = -1;
                goto END;
            }
            puts("[~] LS content exceeds MTU: Split sending...");

            memset(&(p_reply->data), 0, sizeof(p_reply->data));
            bytes = 0, offset = 0;
            packets++;

            /* Receive pseudo-ACK back from client. */
            net_bytes
                = receive_data(&(p_client->conn_sock), &multi_request, MTU);
            if (net_bytes < 0)
            {
                status = -1;
                goto END;
            }

            /* Continue creating packet with the data that was in standby. */
            tmp_bytes = snprintf(p_reply->data + offset,
                                 sizeof(p_reply->data),
                                 "%x%s",
                                 type,
                                 p_dir_ptr->d_name);
            if (tmp_bytes <= 0)
            {
                puts("[-] LS failed: snprintf error[4]!?");
                status = -1;
                goto END;
            }

            /* Offsets for data alignment. */
            tmp_bytes += 1; // For the /x00.
            offset += tmp_bytes;
            bytes += tmp_bytes;
            position += (uint32_t)tmp_bytes;
        }
        /* If data is small enough for just one packet. */
        else
        {
            tmp_bytes = snprintf(p_reply->data + offset,
                                 sizeof(p_reply->data),
                                 "%x%s",
                                 type,
                                 p_dir_ptr->d_name);
            if (tmp_bytes <= 0)
            {
                puts("[-] LS failed: snprintf error[5]!?");
                status = -1;
                goto END;
            }

            /* Offsets for data alignment. */
            tmp_bytes += 1; // For the /x00.
            offset += (tmp_bytes);
            bytes += tmp_bytes;
            position += (uint32_t)tmp_bytes;
        }
    }

END:
    tmp_status = status;
    if (p_dir_fd != NULL)
    {
        status = closedir(p_dir_fd);
        if (status != 0)
        {
            puts("[-] LS failed: Could not close directory");
        }
    }

    if (b_lock_flag == true)
    {
        status = pthread_rwlock_unlock(&g_file_lock);
        if (status != 0)
        {
            puts("[-] LS failed: Could not unlock rw mutex");
        }
    }

    if (status == -1)
    {
        ;
    }
    else
    {
        status = tmp_status;
    }

    if (status == -1)
    {
        p_reply->retcode  = FAIL;
        p_reply->data_len = 0;
        p_reply->msg_len  = 0;
        p_reply->pos      = 0;
    }
    else
    {
        p_reply->retcode = SUCCESS;
        p_reply->msg_len = htonl((uint32_t)bytes);
        p_reply->pos     = htonl(position);

        puts("[+] LS Success: Sending [last] packet");
    }

    for (int i = 0; i < 3; i++)
    {
        p_reply->rsvd[i] = 0;
    }

    free(p_free_me);
    free(p_tmp_directory);
}

void
get_file(void **pp_request_tmp, void **pp_reply_tmp, client_i *p_client)
{
    /*-----------------Variables------------------*/
    int status     = 0;
    int tmp_status = 0;

    char * p_file_name        = NULL;
    FILE * p_file_ptr         = NULL;
    size_t read_bytes         = 0;
    char   buf[FILE_MAX]      = { 0 }; // Actual file data.
    char   fullpath[PATH_MAX] = { 0 };

    struct stat attrs;
    uint32_t    file_size    = 0;
    size_t      bytes        = 0;
    bool        b_gatekeeper = 0;
    bool        b_lock_flag  = false;

    get_request_i *p_request = (get_request_i *)pp_request_tmp;
    get_reply_i *  p_reply   = (get_reply_i *)pp_reply_tmp;

    memset(&p_reply->data, 0, sizeof(p_reply->data));

    char *p_free_me = p_request->p_data;
    /*---------------------------------------------*/

    p_file_name = strndup(p_request->p_data, p_request->len);

    /* Generate path and validate. */
    bytes = snprintf(fullpath,
                     sizeof(fullpath),
                     "%s/%s",
                     p_client->p_login->p_root_dir,
                     p_file_name);
    if (bytes <= 0)
    {
        puts("[-] GET failed: snprintf error");
        status = -1;
        goto END;
    }

    status = pthread_rwlock_rdlock(&g_file_lock);
    if (status != 0)
    {
        puts("[-] GET failed: Could not lock rw mutex");
        goto END;
    }
    b_lock_flag = true;

    b_gatekeeper = check_path(fullpath, p_client);
    if (b_gatekeeper == false)
    {
        puts("[-] GET failed: Out of root directory");
        status = -1;
        goto END;
    }
    /*-------------------------------*/

    status = get_attributes(fullpath, &attrs);
    if (status != 0)
    {
        puts("[-] GET failed: File not found");
        goto END;
    }

    file_size = (uint32_t)attrs.st_size;

    if (file_size > FILE_MAX)
    {
        puts("[-] GET failed: File size exceeds 1016");
        status = -1;
        goto END;
    }

    p_file_ptr = open_file(fullpath);
    if (p_file_ptr == NULL)
    {
        puts("[-] GET failed: Could not open file");
        status = -1;
        goto END;
    }

    /* Read the actual file. */
    read_bytes = read_file(buf, file_size, p_file_ptr);
    printf("[SYSTEM] Read bytes: %ld\n", read_bytes);
    if (read_bytes < 0)
    {
        puts("[-] GET failed: Could not read file");
        status = -1;
        goto END;
    }

END:
    tmp_status = status;

    if (p_file_ptr != NULL)
    {
        status = close_file(p_file_ptr);
        if (status != 0)
        {
            puts("[-] GET failed: Could not close file");
        }
    }

    if (b_lock_flag == true)
    {
        status = pthread_rwlock_unlock(&g_file_lock);
        if (status == -1)
        {
            puts("[-] GET failed: Could not unlock rw mutex");
        }
    }

    if (status == -1)
    {
        ;
    }
    else
    {
        status = tmp_status;
    }

    if (status == -1)
    {
        p_reply->retcode = FAIL;
        p_reply->rsvd    = 0;
        p_reply->len     = 0;
        memcpy(&p_reply->data, &buf, 0);
    }
    else
    {
        p_reply->retcode = SUCCESS;
        p_reply->rsvd    = 0;
        p_reply->len     = ((uint32_t)read_bytes);
        p_reply->len     = (htonl(p_reply->len));
        memcpy(&p_reply->data, &buf, read_bytes);

        puts("[+] GET Success");
    }

    free(p_free_me);
    free(p_file_name);
}

void
make_directory(void **pp_request_tmp, void **pp_reply_tmp, client_i *p_client)
{
    /*-----------------Variables------------------*/
    int status     = 0;
    int tmp_status = 0;

    char *  p_directory        = NULL;
    uint8_t action             = 0;
    bool    valid_permission   = false;
    size_t  bytes              = 0;
    char    fullpath[PATH_MAX] = { 0 };

    bool b_gatekeeper = false;
    bool b_lock_flag  = false;

    mkdir_request_i *p_request = (mkdir_request_i *)pp_request_tmp;
    mkdir_reply_i *  p_reply   = (mkdir_reply_i *)pp_reply_tmp;

    char *p_free_me = p_request->p_data;
    /*---------------------------------------------*/

    p_directory = strndup(p_request->p_data, p_request->len);

    action           = RW_ONLY;
    valid_permission = check_permissions(p_client->permission, action);
    if (valid_permission == false)
    {
        puts("[-] MKDIR failed: P_ERR");
        p_reply->retcode = P_ERR;
        status           = -1;
        goto END;
    }

    /* Generate path and validate. */
    bytes = snprintf(fullpath,
                     sizeof(fullpath),
                     "%s/%s",
                     p_client->p_login->p_root_dir,
                     p_directory);
    if (bytes <= 0)
    {
        puts("[-] MKDIR failed: snprintf error");
        p_reply->retcode = FAIL;
        status           = -1;
        goto END;
    }

    status = pthread_rwlock_wrlock(&g_file_lock);
    if (status == -1)
    {
        puts("[-] MKDIR failed: Could not lock rw mutex");
        goto END;
    }
    b_lock_flag = true;

    b_gatekeeper = check_path(fullpath, p_client);
    if (b_gatekeeper == false)
    {
        puts("[-] MKDIR failed: Out of root directory");
        p_reply->retcode = FAIL;
        status           = -1;
        goto END;
    }
    /*-----------------------------*/

    status = mkdir(fullpath, S_IRWXU | S_IRWXG | S_IRWXO);
    if (status == -1)
    {
        puts("[-] MKDIR failed: Could not make directory");
        p_reply->retcode = FAIL;
    }

END:
    tmp_status = status;

    if (b_lock_flag == true)
    {
        status = pthread_rwlock_unlock(&g_file_lock);
        if (status == -1)
        {
            puts("[-] MKDIR failed: Could not unlock rw mutex");
            status = -1;
        }
    }

    if (status == -1)
    {
        ;
    }
    else
    {
        status = tmp_status;
    }

    if (status == 0)
    {
        puts("[+] MKDIR Success");
        p_reply->retcode = SUCCESS;
    }

    free(p_free_me);
    free(p_directory);
}

void
put_file(void **pp_request_tmp, void **pp_reply_tmp, client_i *p_client)
{
    /*-----------------Variables------------------*/
    int status     = 0;
    int tmp_status = 0;

    uint8_t action       = 0;
    bool    b_gatekeeper = false;
    bool    b_lock_flag  = false;

    struct stat attrs              = { 0 };
    char *      p_file_name        = NULL;
    char *      p_data             = NULL;
    size_t      write_bytes        = 0;
    size_t      snprint_bytes      = 0;
    char        fullpath[PATH_MAX] = { 0 };

    put_request_i *p_request = (put_request_i *)pp_request_tmp;
    put_reply_i *  p_reply   = (put_reply_i *)pp_reply_tmp;

    char *p_free_me = p_request->p_data;
    /*------------------------------------------*/

    p_file_name = strndup(p_request->p_data, p_request->name_len);
    p_data
        = strndup(p_request->p_data + p_request->name_len, p_request->data_len);

    action       = RW_ONLY;
    b_gatekeeper = check_permissions(p_client->permission, action);
    if (b_gatekeeper == false)
    {
        puts("[-] PUT failed: P_ERR");
        p_reply->retcode = P_ERR;
        status           = -1;
        goto END;
    }

    /* Generate path and validate. */
    snprint_bytes = snprintf(fullpath,
                             sizeof(fullpath),
                             "%s/%s",
                             p_client->p_login->p_root_dir,
                             p_file_name);
    if (snprint_bytes <= 0)
    {
        puts("[-] PUT failed: snprintf error");
        p_reply->retcode = FAIL;
        status           = -1;
        goto END;
    }

    status = pthread_rwlock_wrlock(&g_file_lock);
    if (status == -1)
    {
        puts("[-] PUT failed: Could not lock rw mutex");
        status = -1;
        goto END;
    }
    b_lock_flag = true;

    b_gatekeeper = check_path(fullpath, p_client);
    if (b_gatekeeper == false)
    {
        puts("[-] PUT failed: Out of root directory");
        p_reply->retcode = FAIL;
        status           = -1;
        goto END;
    }
    /*---------------------------------*/

    if (p_request->data_len > FILE_MAX)
    {
        puts("[-] PUT failed: Exceeds make file size");
        p_reply->retcode = FAIL;
        status           = -1;
        goto END;
    }

    status = get_attributes(fullpath, &attrs);
    if (status != 0)
    {
        puts("[~] PUT: File not present");
        status = 0;
    }
    else
    {
        puts("[~] PUT: File present");
        if (p_request->flag == NO_OVERWRITE)
        {
            puts("[-] PUT error: File present and no-overwrite");
            p_reply->retcode = F_EXIST;
            status           = -1;
            goto END;
        }
        else if (p_request->flag == OVERWRITE)
        {
            status = 0;
        }
    }

    /* If all checks pass, write to file. */
    write_bytes = write_file(fullpath, "wb", p_data, p_request->data_len);
    if (write_bytes < 0 || write_bytes != p_request->data_len)
    {
        puts("[-] PUT error: Cannot write to file");
        p_reply->retcode = FAIL;
        status           = -1;
        goto END;
    }

END:
    tmp_status = status;

    if (b_lock_flag == true)
    {
        status = pthread_rwlock_unlock(&g_file_lock);
        if (status == -1)
        {
            puts("[-] PUT failed: Could not unlock rw mutex");
        }
    }

    if (status == -1)
    {
        ;
    }
    else
    {
        status = tmp_status;
    }

    if (status == 0)
    {
        puts("[-] PUT Success");
        p_reply->retcode = SUCCESS;
    }

    free(p_free_me);
    free(p_file_name);
    free(p_data);
}

bool
check_path(char *p_fullpath, client_i *p_client)
{
    int    result   = 0;
    size_t safe_len = 0;
    bool   b_valid  = true;

    char resolved[PATH_MAX] = { 0 };

    safe_len = strnlen(p_client->p_login->p_root_dir, PATH_MAX);

    /* The magic behind path validation. */
    realpath(p_fullpath, resolved);

    result = strncmp(resolved, p_client->p_login->p_root_dir, safe_len);
    if (result != 0)
    {
        b_valid = false;
    }

    return b_valid;
}

/*** end of file ***/
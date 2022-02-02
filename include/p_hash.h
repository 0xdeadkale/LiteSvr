/** @file p_hash.h
 *
 * @brief The public facing header file for hash_table.c.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2018 Barr Group. All rights reserved.
 */

#ifndef HASH_H
#define HASH_H

typedef struct creds
{
    char *  p_user;
    char *  p_pwd;
    uint8_t permission;
} creds_i;

typedef struct data
{
    size_t       key;
    size_t       count;
    creds_i *    p_creds;
    struct data *p_next;
} data_i;

typedef struct server
{
    size_t    size;  /* Size of hashtable. */
    int       time_out;  /* Timeout of each client/user. */
    char *    p_root_dir; /* Root directory of server. */
    sigset_t *p_feeder;  /* sigset for pthread_sigmask . */
    pthread_t threads[FOPEN_MAX];
    data_i ** pp_array;
} server_i;

server_i *create_hash(size_t size);

int insert_node(server_i *hashtable, size_t key, creds_i *data);

void validate_node(server_i *hashtable, data_i *node);

data_i *search_node(server_i *hashtable, size_t key);

int delete_node(server_i *hashtable, size_t key);

void cleanup(server_i *hashtable);

size_t hash(const void *var);

enum constraints
{
    USERNAME_MAX = 20,
    PASSWORD_MAX = 30,
    PVAL         = 167 // For hashing algo.
};

#endif /* HASH_H */

/*** end of file ***/

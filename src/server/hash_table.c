/** @file hash_table.c
 *
 * @brief A library for hash table releated code.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2000, 2018 Michael Barr. This software is placed in the
 * public domain and may be used for any purpose. However, this notice must not
 * be changed or removed. No warranty is expressed or implied by the publication
 * or distribution of this source code.
 */

#include "header/includes.h"
#include "../../include/p_hash.h"

server_i *
create_hash(size_t size)
{
    if (size < 1)
    {
        printf("Need a real bucket size\n");
        goto END;
    }

    // Creates hashtable.
    //
    server_i *p_hashtable = malloc(sizeof(server_i));
    if (NULL == p_hashtable)
    {
        perror("Hashtable Malloc failed");
        goto END;
    }
    p_hashtable->size       = size;
    p_hashtable->time_out   = 0;
    p_hashtable->p_root_dir = NULL;

    // Malloc given size for data/credential nodes.
    //
    p_hashtable->pp_array = (data_i **)calloc(size, sizeof(data_i *));
    if (NULL == p_hashtable->pp_array)
    {
        perror("Array Calloc failed!\n");
        goto END;
    }

    return p_hashtable;

END:
    if (p_hashtable != NULL)
    {
        free(p_hashtable);
    }
    return NULL;
}

int
insert_node(server_i *p_hashtable, size_t key, creds_i *p_data)
{
    int status = 0;

    data_i * p_node  = NULL;
    creds_i *p_creds = NULL;

    size_t username_len = strnlen(p_data->p_user, USERNAME_MAX);
    size_t password_len = strnlen(p_data->p_pwd, PASSWORD_MAX);

    // Check if p_hashtable is NULL.
    //
    if (NULL == p_hashtable)
    {
        puts("Hashtable does not exist!");
        status = -1;
        goto END;
    }

    p_node = calloc(1, sizeof(data_i));
    if (NULL == p_node)
    {
        printf("Node calloc failed!\n");
        status = -1;
        goto END;
    }

    p_creds = calloc(1, sizeof(creds_i));
    if (NULL == p_creds)
    {
        printf("Creds calloc failed!\n");
        status = -1;
        goto END;
    }

    // Inserts key and values.
    //
    p_node->key         = key;
    p_creds->p_user     = strndup(p_data->p_user, username_len);
    p_creds->p_pwd      = strndup(p_data->p_pwd, password_len);
    p_creds->permission = p_data->permission;
    p_node->p_creds     = p_creds;

    validate_node(p_hashtable, p_node); /* Validates the node */

END:
    return status;
}

void
validate_node(server_i *p_hashtable, data_i *p_node)
{
    size_t  index = p_node->key % p_hashtable->size;
    data_i *p_tmp = p_hashtable->pp_array[index];

    // If there is already a node at the index.
    //
    if (p_hashtable->pp_array[index] != NULL)
    {
        p_tmp = p_hashtable->pp_array[index];
        // Moves to null spot.
        //
        while (p_tmp != NULL)
        {
            if (p_tmp->key == p_node->key)
            {
                break;
            }
            p_tmp = p_tmp->p_next;
        }
        // Places node and links.
        //
        if (NULL == p_tmp)
        {
            p_node->p_next               = p_hashtable->pp_array[index];
            p_hashtable->pp_array[index] = p_node;
            p_node->count                = 1;
        }
        // Free's if can not place.
        //
        else
        {
            puts("Cannot place");

            free(p_tmp->p_creds->p_user);
            free(p_tmp->p_creds->p_pwd);
            p_tmp->p_creds->p_user = p_node->p_creds->p_user;
            p_tmp->p_creds->p_pwd  = p_node->p_creds->p_pwd;
            free(p_node->p_creds->p_user);
            free(p_node->p_creds->p_pwd);
            free(p_node->p_creds);
            free(p_node);
        }
    }
    // There is no node at the index.
    //
    else
    {
        p_node->count                = 1;
        p_node->p_next               = NULL;
        p_hashtable->pp_array[index] = p_node;
    }
}

data_i *
search_node(server_i *p_hashtable, size_t key)
{
    data_i *p_tmp = NULL;
    size_t  index = 0;

    if (NULL == p_hashtable)
    {
        puts("Hashtable does not exist!");
        return NULL;
    }

    index = key % p_hashtable->size;
    p_tmp = p_hashtable->pp_array[index];

    // Searchs for key through linked-list at the index of the p_hashtable.
    //
    while (p_tmp != NULL)
    {
        if (p_tmp->key == key)
        {
            break;
        }
        p_tmp = p_tmp->p_next;
    }
    if (NULL == p_tmp)
    {
        return NULL;
    }
    return p_tmp;
}

int
delete_node(server_i *p_hashtable, size_t key)
{
    data_i *p_tmp  = NULL;
    data_i *p_prev = NULL;
    data_i *p_del  = NULL;

    size_t index  = 0;
    int    status = 0;
    int    count  = 0;
    int    after  = 0;

    if (NULL == p_hashtable)
    {
        puts("Hashtable does not exist!");
        status = -1;
        goto END;
    }

    index = key % p_hashtable->size;
    p_tmp = p_hashtable->pp_array[index];

    // Searchs for key through linked-list at the index of the p_hashtable.
    //
    while (p_tmp != NULL)
    {
        /* If found. */
        if (p_tmp->key == key)
        {
            p_del = p_tmp;
            if (p_tmp->p_next != NULL)
            {
                after = 1;
            }
            break;
        }
        p_tmp = p_tmp->p_next;
        count++;
    }

    if (NULL == p_tmp)
    {
        status = -1;
        goto END;
    }

    // Only one node in linked list.
    //
    if ((count == 0) && (after == 0))
    {
        free(p_del->p_creds->p_user);
        free(p_del->p_creds->p_pwd);
        free(p_del->p_creds);
        free(p_del);
        p_del                        = NULL;
        p_hashtable->pp_array[index] = NULL;
    }
    // Node is in between nodes.
    //
    else if ((count > 0) && (after == 1))
    {
        p_tmp  = p_del->p_next; /* Point to next node. */
        p_prev = p_hashtable->pp_array[index];

        while (p_prev != NULL)
        {
            if (p_prev->p_next == p_del) /* Node before deletion. */
            {
                break;
            }
            p_prev = p_prev->p_next;
        }

        p_prev->p_next = p_tmp; /* Point prev node to next node. */
        free(p_del->p_creds->p_user);
        free(p_del->p_creds->p_pwd);
        free(p_del->p_creds);
        free(p_del);
        p_del = NULL;
    }
    // If head of list and one after.
    //
    else if ((count == 0) && (after == 1))
    {
        p_tmp = p_del->p_next; /* Point to next node. */

        free(p_del->p_creds->p_user);
        free(p_del->p_creds->p_pwd);
        free(p_del->p_creds);
        free(p_del);
        p_del = NULL;

        p_hashtable->pp_array[index] = p_tmp;
    }
    // Last node in linked list.
    //
    else if ((count > 0) && (after == 0))
    {
        p_prev = p_hashtable->pp_array[index];

        while (p_prev != NULL)
        {
            if (p_prev->p_next == p_del) /* Node before deletion. */
            {
                break;
            }
            p_prev = p_prev->p_next;
        }

        p_prev->p_next = NULL;
        free(p_del->p_creds->p_user);
        free(p_del->p_creds->p_pwd);
        free(p_del->p_creds);
        free(p_del);
        p_del = NULL;
    }

END:
    return status;
}

void
cleanup(server_i *p_hashtable)
{
    data_i *p_tmp;

    if (NULL == p_hashtable)
    {
        return;
    }

    // Loops through and cleans up everything.
    //
    for (size_t i = 0; i < p_hashtable->size; ++i)
    {
        while (p_hashtable->pp_array[i] != NULL)
        {
            p_tmp = p_hashtable->pp_array[i]->p_next;
            free(p_hashtable->pp_array[i]->p_creds->p_user);
            free(p_hashtable->pp_array[i]->p_creds->p_pwd);
            free(p_hashtable->pp_array[i]->p_creds);
            free(p_hashtable->pp_array[i]);
            p_hashtable->pp_array[i] = p_tmp;
        }
        free(p_hashtable->pp_array[i]);
    }
    free(p_hashtable->pp_array);
    free(p_hashtable->p_root_dir);
    free(p_hashtable);
    p_hashtable = NULL;
}

/**
 * @brief This function opens a file and returns the file handle.
 * https://cp-algorithms.com/string/string-hashing.html
 *
 * @param p_var Seed number for algoithm.
 *
 * @return Hashed number.
 */
size_t
hash(const void *p_var)
{
    size_t sum = 0;
    size_t p   = 1;

    for (const char *p_str = (const char *)p_var; *p_str; p_str++)
    {
        sum = ((*p_str - 'a' + 1) * p + sum);
        p   = (p * PVAL);
    }
    return sum;
}

/*** end of file ***/

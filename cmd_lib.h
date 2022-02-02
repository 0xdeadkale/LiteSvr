/** @file cmd_Lib.h
 *
 * @brief The header file for cmd_lib.c.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2018 Barr Group. All rights reserved.
 */

#ifndef CMDLIB_H
#define CMDLIB_H

#include "server.h"

void user_login(void **pp_request_tmp, void **pp_reply_tmp, client_i *p_client);

void user_create(void **   pp_request_tmp,
                 void **   pp_reply_tmp,
                 client_i *p_client);

void user_delete(void **   pp_request_tmp,
                 void **   pp_reply_tmp,
                 client_i *p_client);

void user_event(void **request_tmp, void **reply_tmp, client_i *cli);

void remove_file(void **request_tmp, void **reply_tmp, client_i *cli);

bool check_permissions(uint8_t permission, uint8_t action);

void ls_directory(void **request_tmp, void **reply_tmp, client_i *cli);

void get_file(void **request_tmp, void **reply_tmp, client_i *cli);

void make_directory(void **request_tmp, void **reply_tmp, client_i *cli);

void put_file(void **request_tmp, void **reply_tmp, client_i *cli);

bool check_conn(int errors, client_i *cli);

bool check_path(char *fullpath, client_i *cli);

#endif /* CMDLIB_H */

/*** end of file ***/
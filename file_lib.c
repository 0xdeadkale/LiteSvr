/** @file file_lib.c
 *
 * @brief Provides the ability to interface with files.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2000, 2018 Michael Barr. This software is placed in the
 * public domain and may be used for any purpose. However, this notice must not
 * be changed or removed. No warranty is expressed or implied by the publication
 * or distribution of this source code.
 */

#include "header/includes.h"
#include "header/file_lib.h"

FILE *
open_file(char *p_name)
{
    FILE *p_file_ptr = NULL;

    p_file_ptr = fopen(p_name, "rb");
    if (NULL == p_file_ptr)
    {
        perror("Open file read");
    }

    return p_file_ptr;

} /* open_file() */

size_t
read_file(char *p_buffer, size_t size, FILE *p_file_ptr)
{
    size_t bytes_read = 0;

    bytes_read = fread(p_buffer, 1, size, p_file_ptr);
    if (bytes_read < 0)
    {
        perror("Read file");
    }

    return bytes_read;

} /* read_file() */

size_t
write_file(char *p_name, char *p_flags, void *p_data, size_t data_size)
{
    size_t bytes_written = 0;
    FILE * p_file_ptr    = NULL;

    p_file_ptr = fopen(p_name, p_flags);
    if (NULL == p_file_ptr)
    {
        bytes_written = -1;
        perror("Open file write");
        goto END;
    }

    bytes_written = fwrite(p_data, sizeof(char), data_size, p_file_ptr);
    if (bytes_written < 0)
    {
        perror("Write file");
    }

END:
    if (p_file_ptr != NULL)
    {
        close_file(p_file_ptr);
    }

    return bytes_written;

} /* write_file() */

int
get_attributes(char *p_name, struct stat *p_attrs)
{
    int status = 0;

    status = stat(p_name, p_attrs);
    if (status != 0)
    {
        perror("File stat");
    }

    return status;

} /* get_attributes() */

int
delete_file(char *p_name)
{
    int status = 0;

    status = remove(p_name);
    if (status != 0)
    {
        perror("Delete file");
    }

    return status;

} /* delete_attributes() */

int
close_file(FILE *p_file_ptr)
{
    int status = 0;

    status = fclose(p_file_ptr);
    if (status != 0)
    {
        perror("CLose file");
    }

    return status;

} /* close_file() */

/*** end of file ***/
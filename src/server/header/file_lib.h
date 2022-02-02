/** @file file_Lib.h
 *
 * @brief The header file for file_lib.c.
 *
 * @par
 * COPYRIGHT NOTICE: (c) 2018 Barr Group. All rights reserved.
 */

#ifndef FILELIB_H
#define FILELIB_H

/**
 * @brief This function opens a file and returns the file handle.
 *
 * @param name This is the name of the file to be opened.
 *
 * @return file pointer on success, IO_FAIL error code on failure.
 */
FILE *open_file(char *name);

/**
 * @brief This function reads a file and returns how many bytes were read.
 *
 * @param name This is the name of the file to be opened.
 * @param size This is the amount of data to be read.
 * @param file_ptr The file pointer itself for fread() to utilize.
 *
 * @return bytes_read on success, IO_FAIL error code on failure.
 */
size_t read_file(char *buffer, size_t size, FILE *file_ptr);

/**
 * @brief This function closes a file and returns a status code.
 *
 * @param file_ptr Actual pointer to file used in
 *
 * @return status value on success, OC_FAIL error code on failure.
 */
int close_file(FILE *file_ptr);

/**
 * @brief This function obtains the attributes of a file and prints to console.
 * 
 * @param name This is the name of the file to be scanned.
 * @param buffer Used to return the attributes obtained from the file.
 *
 * @return Status code on success, GENERIC_FAIL error code on failure.
 */
int get_attributes(char *name, struct stat *buffer);

/**
 * @brief This function writes to a file and returns how many bytes were
 * written.
 *
 * @param name This is the name of the file to be written to.
 * @param flags Passed to fwrite on how to write data.
 * @param data Actual data to write to file.
 *
 * @return Bytes written on success, IO_FAIL error code on failure.
 */
size_t write_file(char *name, char *flags, void *data, size_t data_size);

/**
 * @brief This function deletes a file and returns the status of completion.
 * @param name This is the name of the file to be deleted.
 *
 * @return Status code on success, GENERIC_FAIL error code on failure.
 */
int delete_file(char *name);

#endif /* FILELIB_H */

/*** end of file ***/
/*
 * UNIX Network Programming: Sockets Introduction
 * Andrew M. Rudoff, Bill Fenner, W. Richard Stevens
 * Feb 27, 2004
 */
#ifndef _UNP_H
#define _UNP_H

ssize_t readn(int filedes, void *buff, size_t nbytes);
ssize_t writen(int filedes, const void *buff, size_t nbytes);
ssize_t readline(int filedes, void *buff, size_t maxlen);

#endif

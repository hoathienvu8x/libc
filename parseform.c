/*
 * Parse results HTML forms for use in CGI scripts.
 * Copyright © 2000 World Wide Web Consortium
 * See http://www.w3.org/Consortium/Legal/copyright-software-19980720.html
 *
 * Author: Bert Bos <bert@w3.org>
 * Created: 31 July 2000
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#define MAXLINE 4096
#define ACCEPT "abcdefghijklmnopqrstuvwxyz0123456789_-."

typedef enum {Variable, Value, Hex1, Hex2} State;


/* error -- print error message and exit */
static void error(char *msg)
{
  fprintf(stderr, "parseform: %s\n", msg);
  exit(1);
}


/* parse_query_string -- parse the contents of the QUERY_STRING variable */
static void parse_query_string(char *prefix)
{
  State state;
  char *query, filename[MAXLINE], hexchar = 0; /* Initialized to stop -Wall */
  FILE *f = NULL;
  size_t i;

  if (! (query = getenv("QUERY_STRING"))) error("Missing QUERY_STRING");

  strcpy(filename, prefix);
  i = strlen(prefix);

  for (state = Variable; *query; query++) {

    switch (state) {

      case Variable:				/* Scanning name of var */
	if (*query == '=') {
	  filename[i] = '\0';
	  if (! (f = fopen(filename, "w"))) error(strerror(errno));
	  state = Value;
	} else if (i < sizeof(filename) - 1 && isalnum(*query)) {
	  filename[i++] = *query;
	}
	break;

      case Value:				/* Scanning a value */
	if (*query == ';' || *query == '&') {
	  fclose(f);
	  i = strlen(prefix);
	  state = Variable;
	} else if (*query == '%') {
	  state = Hex1;
	} else {
	  putc(*query == '+' ? ' ' : *query, f);
	}
	break;

      case Hex1:				/* 1st char after '%' */
	state = Hex2;
	if ('0' <= *query && *query <= '9') hexchar = *query - '0';
	else if ('A' <= *query && *query <= 'F') hexchar = *query - 'A' + 10;
	else if ('a' <= *query && *query <= 'f') hexchar = *query - 'a' + 10;
	else state = Value;			/* Error, skip char... */
	break;

      case Hex2:				/* 2nd char after '%' */
	if ('0' <= *query && *query <= '9')
	  putc(16 * hexchar + *query - '0', f);
	else if ('A' <= *query && *query <= 'F')
	  putc(16 * hexchar + *query - 'A' + 10, f);
	else if ('a' <= *query && *query <= 'f')
	  putc(16 * hexchar + *query - 'a' + 10, f);
	else
	  ;					/* Error, skip char... */
	state = Value;
	break;

      default:
	assert(!"Cannot happen");
    }

  }

  if (f) fclose(f);
}


/* parse_url_encoded -- parse URL-encoded data from stdin */
static void parse_url_encoded(char *prefix)
{
  State state;
  char *length, c, filename[MAXLINE], hexchar = 0; /* Init'ed to stop -Wall */
  FILE *f = NULL;
  size_t i, len;

  if (! (length = getenv("CONTENT_LENGTH"))) error("Missing CONTENT_LENGTH");
  len = atoi(length);
  
  strcpy(filename, prefix);
  i = strlen(prefix);

  for (state = Variable; len > 0; len--) {
    c = getchar();

    switch (state) {

      case Variable:				/* Scanning name of var */
	if (c == '=') {
	  filename[i] = '\0';
	  if (! (f = fopen(filename, "w"))) error(strerror(errno));
	  state = Value;
	} else if (i < sizeof(filename) - 1 && isalnum(c)) {
	  filename[i++] = c;
	}
	break;

      case Value:				/* Scanning a value */
	if (c == ';' || c == '&') {
	  fclose(f);
	  i = strlen(prefix);
	  state = Variable;
	} else if (c == '%') {
	  state = Hex1;
	} else {
	  putc(c == '+' ? ' ' : c, f);
	}
	break;

      case Hex1:				/* 1st char after '%' */
	state = Hex2;
	if ('0' <= c && c <= '9') hexchar = c - '0';
	else if ('A' <= c && c <= 'F') hexchar = c - 'A' + 10;
	else if ('a' <= c && c <= 'f') hexchar = c - 'a' + 10;
	else state = Value;			/* Error, skip char... */
	break;

      case Hex2:				/* 2nd char after '%' */
	if ('0' <= c && c <= '9')
	  putc(16 * hexchar + c - '0', f);
	else if ('A' <= c && c <= 'F')
	  putc(16 * hexchar + c - 'A' + 10, f);
	else if ('a' <= c && c <= 'f')
	  putc(16 * hexchar + c - 'a' + 10, f);
	else
	  ;					/* Error, skip char... */
	state = Value;
	break;

      default:
	assert(!"Cannot happen");
    }

  }

  if (f) fclose(f);
}


/* shift_and_read_more -- remove prefix from buf and read more from stdin */
static void shift_and_read_more(size_t start, char buf[MAXLINE], size_t *len)
{
  assert(start <= *len);
  *len -= start;
  memmove(buf, buf + start, *len);
  *len += fread(buf + *len, 1, MAXLINE - *len, stdin);
  if (ferror(stdin)) error(strerror(errno));
}


/* parse_multipart -- parse multipart/form-data from stdin */
static void parse_multipart(char *prefix)
{
  char boundary[MAXLINE], buf[MAXLINE], filename[MAXLINE], *p;
  size_t blen, n, j;
  FILE *f = NULL;

  /* Read first buffer full of data */
  n = fread(buf, 1, sizeof(buf), stdin);
  if (ferror(stdin)) error(strerror(errno));

  /* At this point, buf should contain at least the first boundary */
  for (j = 0; j < n && buf[j] != '\r'; j++) boundary[j] = buf[j];
  if (j + 1 >= n || buf[j+1] != '\n') error("Failed to parse multipart data");

  boundary[j] = '\0';	/* Not needed, just for easier debugging */
  blen = j;

  /* Loop over all parts of the multipart, until a boundary + "--" */
  do {

    /* Remove this boundary and the following newline, and read more */
    shift_and_read_more(blen + 2, buf, &n);
    /* At this point, buf contains the start of a part of the multipart */

    /* Loop over headers until an empty line */
    while (strncmp(buf, "\r\n", 2) != 0) {
      /* At this point buf contains (hopefully) a line of text or more */
      if (strncasecmp(buf, "Content-disposition:", 20) == 0) {
	/* Create a file named after the parameter */
	if (! (p = strstr(buf, "name="))) error("Missing name=");
	if (*(p + 5) == '"') p += 6; else p += 5;
	if ((j = strspn(p, ACCEPT)) == 0) error("Illegal variable name");
	strncat(strcpy(filename, prefix), p, j);
	if (f) error("Syntax error in input, duplicate headers");
	if (! (f = fopen(filename, "w"))) error(strerror(errno));
      } else if (strncasecmp(buf, "Content-type:", 13) == 0) {
	; /* Skip this header */
      } else {
	error("Possible bug: unrecognized header");
      }
      /* Remove this line from buf and read more from stdin */
      for (j = 0; j < n && buf[j] != '\r'; j++) ;
      if (j + 1 >= n) error("Failed to parse multipart data");
      shift_and_read_more(j + 2, buf, &n);
    }
    if (! f) error("Missing parameter name");

    /* Remove the \r\n and read more */
    shift_and_read_more(2, buf, &n);

    /* Copy data up to next \r from buf to file f */
    for (j = 0; buf[j] != '\r';) {
      if (fputc(buf[j++], f) == EOF) error(strerror(errno));
      if (j == n) {
	shift_and_read_more(j, buf, &n);
	if (n == 0) error("Premature EOF on input");
	j = 0;
      }
    }

    /* Remove that part from buf and read more */
    shift_and_read_more(j, buf, &n);

    /* At this point, buf starts with \r */
    while (buf[1] != '\n' || strncmp(buf + 2, boundary, blen) != 0) {

      /* Copy the \r */
      if (fputc(buf[0], f) == EOF) error(strerror(errno));

      /* Copy data up to next \r from buf to file f */
      for (j = 1; buf[j] != '\r';) {
	if (fputc(buf[j++], f) == EOF) error(strerror(errno));
	if (j == n) {
	  shift_and_read_more(j, buf, &n);
	  if (n == 0) error("Premature EOF on input");
	  j = 0;
	}
      }

      /* Remove that part from buf and read more */
      shift_and_read_more(j, buf, &n);
    }
    if (fclose(f) == EOF) error(strerror(errno));
    f = NULL;

    /* Remove the \r\n, leave the boundary */
    shift_and_read_more(2, buf, &n);

  } while (buf[blen] != '-');
}


/* parse_stdin -- parse URL-encoded or multipart/form-data data from stdin */
static void parse_stdin(char *prefix)
{
  char *type;
  
  if (! (type = getenv("CONTENT_TYPE"))) error("Missing CONTENT_TYPE");

  setvbuf(stdin, NULL, _IONBF, 0);		/* Unbuffered input */
  if (strncmp(type, "multipart/form-data", 19) == 0) parse_multipart(prefix);
  else parse_url_encoded(prefix);
}


/* main -- main body */
int main(int argc, char *argv[])
{
  char *method, *prefix;

  if (argc != 2) error("Usage: parseform file-prefix\n");
  prefix = argv[1];

  if (! (method = getenv("REQUEST_METHOD"))) error("Missing REQUEST_METHOD");

  if (strcmp(method, "GET") == 0) parse_query_string(prefix);
  else if (strcmp(method, "HEAD") == 0) parse_query_string(prefix);
  else if (strcmp(method, "POST") == 0) parse_stdin(prefix);
  else error("Unknown REQUEST_METHOD");

  return 0;
}

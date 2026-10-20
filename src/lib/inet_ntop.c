/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

#include "ares_private.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#include "ares_nameser.h"
#include "ares_ipv6.h"

#ifdef USE_WINSOCK
#  define SOCKERRNO        ((int)WSAGetLastError())
#  define SET_SOCKERRNO(x) (WSASetLastError((int)(x)))
#  undef EMSGSIZE
#  define EMSGSIZE WSAEMSGSIZE
#  undef ENOENT
#  define ENOENT WSA_INVALID_PARAMETER
#  undef EAFNOSUPPORT
#  define EAFNOSUPPORT WSAEAFNOSUPPORT
#  undef ENOSPC
#  define ENOSPC WSA_INVALID_PARAMETER
#else
#  define SOCKERRNO        (errno)
#  define SET_SOCKERRNO(x) (errno = (x))
#endif

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

static const char *inet_ntop4(const unsigned char *src, char *dst, size_t size);
static const char *inet_ntop6(const unsigned char *src, char *dst, size_t size);

/* RFC 5952 requires lowercase hex. ares_buf_append_num_hex() emits uppercase.
 */
static ares_status_t append_hex_group(ares_buf_t *buf, unsigned int word)
{
  static const char hexdig[] = "0123456789abcdef";
  char              tmp[4];
  size_t            n;
  size_t            i;
  unsigned int      v;
  ares_status_t     status;

  v = word;
  if (v == 0) {
    return ares_buf_append_byte(buf, '0');
  }

  n = 0;
  while (v != 0 && n < sizeof(tmp)) {
    tmp[n++]   = hexdig[v & 0x0f];
    v        >>= 4;
  }

  for (i = n; i > 0; i--) {
    status = ares_buf_append_byte(buf, (unsigned char)tmp[i - 1]);
    if (status != ARES_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }
  return ARES_SUCCESS;
}

static const char *finish_presentation(ares_buf_t *buf, char *dst, size_t size)
{
  char  *str;
  size_t slen = 0;

  str = ares_buf_finish_str(buf, &slen);
  if (str == NULL) {
    /* finish_str() frees buf only after it has taken the allocation. */
    ares_buf_destroy(buf); /* LCOV_EXCL_LINE: OutOfMemory */
    SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
    return NULL;           /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* slen does not include the trailing NUL. */
  if (slen + 1 > size) {
    ares_free(str);
    SET_SOCKERRNO(ENOSPC);
    return NULL;
  }

  ares_strcpy(dst, str, size);
  ares_free(str);
  return dst;
}

/* char *
 * inet_ntop(af, src, dst, size)
 *     convert a network format address to presentation format.
 * return:
 *     pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *     Paul Vixie, 1996.
 */
const char *ares_inet_ntop(int af, const void *src, char *dst,
                           ares_socklen_t size)
{
  switch (af) {
    case AF_INET:
      return inet_ntop4(src, dst, (size_t)size);
    case AF_INET6:
      return inet_ntop6(src, dst, (size_t)size);
    default:
      break;
  }
  SET_SOCKERRNO(EAFNOSUPPORT);
  return NULL;
}

/* const char *
 * inet_ntop4(src, dst, size)
 *     format an IPv4 address
 * return:
 *     `dst' (as a const)
 * notes:
 *     (1) uses no statics
 *     (2) takes a unsigned char* not an in_addr as input
 * author:
 *     Paul Vixie, 1996.
 */
static const char *inet_ntop4(const unsigned char *src, char *dst, size_t size)
{
  ares_buf_t   *buf;
  ares_status_t status;
  size_t        i;

  /* Historical contract: the destination must be able to hold the longest
   * IPv4 presentation form, not merely this particular address. */
  if (size < sizeof("255.255.255.255")) {
    SET_SOCKERRNO(ENOSPC);
    return NULL;
  }

  buf = ares_buf_create();
  if (buf == NULL) {
    SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
    return NULL;           /* LCOV_EXCL_LINE: OutOfMemory */
  }

  for (i = 0; i < 4; i++) {
    if (i != 0) {
      status = ares_buf_append_byte(buf, '.');
      if (status != ARES_SUCCESS) {
        ares_buf_destroy(buf); /* LCOV_EXCL_LINE: OutOfMemory */
        SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
        return NULL;           /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
    status = ares_buf_append_num_dec(buf, src[i], 0);
    if (status != ARES_SUCCESS) {
      ares_buf_destroy(buf); /* LCOV_EXCL_LINE: OutOfMemory */
      SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
      return NULL;           /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  return finish_presentation(buf, dst, size);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *     convert IPv6 binary address into presentation (printable) format
 * author:
 *     Paul Vixie, 1996.
 */
static const char *inet_ntop6(const unsigned char *src, char *dst, size_t size)
{
  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size.  On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays.  All the world's not a VAX.
   */
  struct {
    ares_ssize_t base;
    size_t       len;
  } best, cur;

  unsigned int  words[NS_IN6ADDRSZ / NS_INT16SZ];
  size_t        i;
  ares_buf_t   *buf;
  ares_status_t status;
  char          v4[sizeof("255.255.255.255")];

  /*
   * Preprocess:
   *  Copy the input (bytewise) array into a wordwise array.
   *  Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset(words, '\0', sizeof(words));
  for (i = 0; i < NS_IN6ADDRSZ; i++) {
    words[i / 2] |= (unsigned int)(src[i] << ((1 - (i % 2)) << 3));
  }
  best.base = -1;
  best.len  = 0;
  cur.base  = -1;
  cur.len   = 0;
  for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
    if (words[i] == 0) {
      if (cur.base == -1) {
        cur.base = (ares_ssize_t)i;
        cur.len  = 1;
      } else {
        cur.len++;
      }
    } else {
      if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len) {
          best = cur;
        }
        cur.base = -1;
      }
    }
  }
  if (cur.base != -1) {
    if (best.base == -1 || cur.len > best.len) {
      best = cur;
    }
  }
  if (best.base != -1 && best.len < 2) {
    best.base = -1;
  }

  /*
   * Format the result through ares_buf so a mis-sized group cannot walk
   * off a stack temporary.
   */
  buf = ares_buf_create();
  if (buf == NULL) {
    SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
    return NULL;           /* LCOV_EXCL_LINE: OutOfMemory */
  }

  for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
    /* Are we inside the best run of 0x00's? */
    if (best.base != -1 && i >= (size_t)best.base &&
        i < ((size_t)best.base + best.len)) {
      if (i == (size_t)best.base) {
        status = ares_buf_append_byte(buf, ':');
        if (status != ARES_SUCCESS) {
          ares_buf_destroy(buf); /* LCOV_EXCL_LINE: OutOfMemory */
          SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
          return NULL;           /* LCOV_EXCL_LINE: OutOfMemory */
        }
      }
      continue;
    }
    /* Are we following an initial run of 0x00s or any real hex? */
    if (i != 0) {
      status = ares_buf_append_byte(buf, ':');
      if (status != ARES_SUCCESS) {
        ares_buf_destroy(buf); /* LCOV_EXCL_LINE: OutOfMemory */
        SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
        return NULL;           /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
    /* Is this address an encapsulated IPv4? */
    if (i == 6 && best.base == 0 &&
        (best.len == 6 || (best.len == 7 && words[7] != 0x0001) ||
         (best.len == 5 && words[5] == 0xffff))) {
      if (inet_ntop4(src + 12, v4, sizeof(v4)) == NULL) {
        ares_buf_destroy(buf);
        return NULL;
      }
      status = ares_buf_append_str(buf, v4);
      if (status != ARES_SUCCESS) {
        ares_buf_destroy(buf); /* LCOV_EXCL_LINE: OutOfMemory */
        SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
        return NULL;           /* LCOV_EXCL_LINE: OutOfMemory */
      }
      break;
    }
    status = append_hex_group(buf, words[i]);
    if (status != ARES_SUCCESS) {
      ares_buf_destroy(buf); /* LCOV_EXCL_LINE: OutOfMemory */
      SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
      return NULL;           /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }
  /* Was it a trailing run of 0x00's? */
  if (best.base != -1 &&
      ((size_t)best.base + best.len) == (NS_IN6ADDRSZ / NS_INT16SZ)) {
    status = ares_buf_append_byte(buf, ':');
    if (status != ARES_SUCCESS) {
      ares_buf_destroy(buf); /* LCOV_EXCL_LINE: OutOfMemory */
      SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
      return NULL;           /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  return finish_presentation(buf, dst, size);
}

/*
 * Copyright (c) 2012 by Gilles Chehade <gilles@openbsd.org>
 * Copyright (c) 1996,1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
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
#include "ares_inet_net_pton.h"

#ifdef USE_WINSOCK
#  define SOCKERRNO        ((int)WSAGetLastError())
#  define SET_SOCKERRNO(x) (WSASetLastError((int)(x)))
#  undef EMSGSIZE
#  define EMSGSIZE WSAEMSGSIZE
#  undef ENOENT
#  define ENOENT WSA_INVALID_PARAMETER
#  undef EAFNOSUPPORT
#  define EAFNOSUPPORT WSAEAFNOSUPPORT
#else
#  define SOCKERRNO        (errno)
#  define SET_SOCKERRNO(x) (errno = (x))
#endif

const struct ares_in6_addr ares_in6addr_any = { { { 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                    0, 0, 0, 0, 0, 0, 0 } } };

/* Wrap a NUL-terminated string. Empty input yields NULL with *len == 0;
 * allocation failure yields NULL with *len > 0. */
static ares_buf_t *open_text(const char *src, size_t *len)
{
  *len = ares_strlen(src);
  if (*len == 0) {
    return NULL;
  }
  return ares_buf_create_const((const unsigned char *)src, *len);
}

static void fail_open(size_t len)
{
  if (len == 0) {
    SET_SOCKERRNO(ENOENT);
  } else {
    SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
  }
}

/* Fetch one byte. At the end of the buffer, *ch is 0 and the result is false,
 * matching a read of the terminating NUL that was not stored in the buffer. */
static ares_bool_t take_byte(ares_buf_t *buf, unsigned char *ch)
{
  if (ares_buf_fetch_bytes(buf, ch, 1) != ARES_SUCCESS) {
    *ch = 0;
    return ARES_FALSE;
  }
  return ARES_TRUE;
}

static int hex_value(unsigned char ch)
{
  if (ares_isdigit(ch)) {
    return (int)(ch - '0');
  }
  if (ch >= 'a' && ch <= 'f') {
    return (int)(ch - 'a' + 10);
  }
  if (ch >= 'A' && ch <= 'F') {
    return (int)(ch - 'A' + 10);
  }
  return -1;
}

static ares_status_t append_octet(ares_buf_t *octets, size_t size,
                                  unsigned char b)
{
  if (ares_buf_len(octets) >= size) {
    return ARES_EBADRESP;
  }
  return ares_buf_append_byte(octets, b);
}

/*
 * static int
 * inet_net_pton_ipv4(src, dst, size, allow_cidr)
 *      convert IPv4 network number from presentation to network format.
 *      accepts hex octets, hex strings, decimal octets, and, if
 *      "allow_cidr" is true, /CIDR.  "size" is in bytes and describes "dst".
 * return:
 *      number of bits, either imputed classfully or specified with /CIDR,
 *      or -1 if some failure occurred (check errno).  ENOENT means it was
 *      not an IPv4 network specification (including a /CIDR suffix when
 *      "allow_cidr" is false).
 * note:
 *      network byte order assumed.  this means 192.5.5.240/28 has
 *      0b11110000 in its fourth octet.
 * note:
 *      On Windows we store the error in the thread errno, not
 *      in the winsock error code. This is to avoid losing the
 *      actual last winsock error. So use macro ERRNO to fetch the
 *      errno this function sets when returning (-1), not SOCKERRNO.
 * author:
 *      Paul Vixie (ISC), June 1996
 */
static int ares_inet_net_pton_ipv4(const char *src, unsigned char *dst,
                                   size_t size, ares_bool_t allow_cidr)
{
  ares_buf_t          *in     = NULL;
  ares_buf_t          *octets = NULL;
  size_t               len;
  unsigned char        ch;
  unsigned char        first = 0;
  const unsigned char *look;
  size_t               look_len;
  int                  n;
  int                  tmp = 0;
  int                  dirty;
  int                  bits;
  int                  result = -1;
  ares_status_t        status;
  ares_bool_t          saw_octet = ARES_FALSE;

  memset(dst, 0, size);

  in = open_text(src, &len);
  if (in == NULL) {
    fail_open(len);
    return -1;
  }

  octets = ares_buf_create();
  if (octets == NULL) {
    SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;             /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (!take_byte(in, &ch)) {
    goto enoent; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  look = ares_buf_peek(in, &look_len);
  if (ch == '0' && look != NULL && look_len >= 2 &&
      (look[0] == 'x' || look[0] == 'X') && ares_isascii(look[1]) &&
      ares_isxdigit(look[1])) {
    /* Hexadecimal: Eat nybble string. */
    if (size == 0) {
      goto emsgsize;
    }
    if (ares_buf_consume(in, 1) != ARES_SUCCESS) {
      goto enoent; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
    dirty = 0;
    while (take_byte(in, &ch) && ares_isascii(ch) && ares_isxdigit(ch)) {
      if (ares_isupper(ch)) {
        ch = ares_tolower(ch);
      }
      n = hex_value(ch);
      if (dirty == 0) {
        tmp = n;
      } else {
        tmp = (tmp << 4) | n;
      }
      if (++dirty == 2) {
        status = append_octet(octets, size, (unsigned char)tmp);
        if (status == ARES_EBADRESP) {
          goto emsgsize;
        }
        if (status != ARES_SUCCESS) {
          SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
          goto done;             /* LCOV_EXCL_LINE: OutOfMemory */
        }
        if (!saw_octet) {
          first     = (unsigned char)tmp;
          saw_octet = ARES_TRUE;
        }
        dirty = 0;
      }
    }
    if (dirty) { /* Odd trailing nybble? */
      status = append_octet(octets, size, (unsigned char)(tmp << 4));
      if (status == ARES_EBADRESP) {
        goto emsgsize;
      }
      if (status != ARES_SUCCESS) {
        SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;             /* LCOV_EXCL_LINE: OutOfMemory */
      }
      if (!saw_octet) {
        first     = (unsigned char)(tmp << 4);
        saw_octet = ARES_TRUE;
      }
    }
  } else if (ares_isascii(ch) && ares_isdigit(ch)) {
    /* Decimal: eat dotted digit string. */
    for (;;) {
      tmp = 0;
      do {
        n    = (int)(ch - '0');
        tmp *= 10;
        tmp += n;
        if (tmp > 255) {
          goto enoent;
        }
      } while (take_byte(in, &ch) && ares_isascii(ch) && ares_isdigit(ch));
      status = append_octet(octets, size, (unsigned char)tmp);
      if (status == ARES_EBADRESP) {
        goto emsgsize;
      }
      if (status != ARES_SUCCESS) {
        SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;             /* LCOV_EXCL_LINE: OutOfMemory */
      }
      if (!saw_octet) {
        first     = (unsigned char)tmp;
        saw_octet = ARES_TRUE;
      }
      if (ch == '\0' || ch == '/') {
        break;
      }
      if (ch != '.') {
        goto enoent;
      }
      if (!take_byte(in, &ch) || !ares_isascii(ch) || !ares_isdigit(ch)) {
        goto enoent;
      }
    }
  } else {
    goto enoent;
  }

  bits = -1;
  if (allow_cidr && ch == '/' && saw_octet) {
    look = ares_buf_peek(in, &look_len);
    if (look != NULL && look_len > 0 && ares_isascii(look[0]) &&
        ares_isdigit(look[0])) {
      /* CIDR width specifier.  Nothing can follow it. */
      bits = 0;
      for (;;) {
        if (!take_byte(in, &ch) || !ares_isdigit(ch)) {
          goto enoent; /* LCOV_EXCL_LINE: DefensiveCoding */
        }
        n     = (int)(ch - '0');
        bits *= 10;
        bits += n;
        if (bits > 32) {
          goto enoent;
        }
        look = ares_buf_peek(in, &look_len);
        if (look == NULL || !ares_isdigit(look[0])) {
          break;
        }
      }
      /* A non-digit after the width is not a prefix length. */
      if (ares_buf_len(in) != 0) {
        goto enoent;
      }
      ch = 0;
    }
  }

  /* Firey death and destruction unless we prefetched EOS. */
  if (ch != '\0') {
    goto enoent;
  }

  /* If nothing was written to the destination, we found no address. */
  if (!saw_octet) {
    goto enoent; /* LCOV_EXCL_LINE: all valid paths above append an octet */
  }

  /* If no CIDR spec was given, infer width from net class. */
  if (bits == -1) {
    if (first >= 240) {        /* Class E */
      bits = 32;
    } else if (first >= 224) { /* Class D */
      bits = 8;
    } else if (first >= 192) { /* Class C */
      bits = 24;
    } else if (first >= 128) { /* Class B */
      bits = 16;
    } else {                   /* Class A */
      bits = 8;
    }
    /* If imputed mask is narrower than specified octets, widen. */
    if (bits < (int)(ares_buf_len(octets) * 8)) {
      bits = (int)ares_buf_len(octets) * 8;
    }
    /*
     * If there are no additional bits specified for a class D
     * address adjust bits to 4.
     */
    if (bits == 8 && first == 224) {
      bits = 4;
    }
  }

  /* Extend network to cover the actual mask. IPv4 prefixes are at most 32
   * bits, so four octets are always enough and the length multiply cannot
   * wrap. */
  while (ares_buf_len(octets) < 4 && bits > (int)(ares_buf_len(octets) * 8)) {
    status = append_octet(octets, size, 0);
    if (status == ARES_EBADRESP) {
      goto emsgsize;
    }
    if (status != ARES_SUCCESS) {
      SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;             /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  {
    size_t         blen  = 0;
    unsigned char *bytes = ares_buf_finish_bin(octets, &blen);

    if (bytes == NULL) {
      SET_SOCKERRNO(ENOMEM); /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;             /* LCOV_EXCL_LINE: OutOfMemory */
    }
    octets = NULL;
    if (blen > size) {
      ares_free(bytes); /* LCOV_EXCL_LINE: DefensiveCoding */
      goto emsgsize;    /* LCOV_EXCL_LINE: DefensiveCoding */
    }
    if (blen > 0) {
      memcpy(dst, bytes, blen);
    }
    ares_free(bytes);
  }
  result = bits;
  goto done;

enoent:
  SET_SOCKERRNO(ENOENT);
  result = -1;
  goto done;

emsgsize:
  SET_SOCKERRNO(EMSGSIZE);
  result = -1;

done:
  ares_buf_destroy(in);
  ares_buf_destroy(octets);
  return result;
}

static int getbits(ares_buf_t *src, size_t *bitsp)
{
  size_t        n;
  size_t        val;
  unsigned char ch;

  val = 0;
  n   = 0;
  while (take_byte(src, &ch)) {
    if (!ares_isdigit(ch)) {
      return 0;
    }
    if (n++ != 0 && val == 0) { /* no leading zeros */
      return 0;
    }
    val *= 10;
    val += (size_t)(ch - '0');
    if (val > 128) { /* range */
      return 0;
    }
  }
  if (n == 0) {
    return 0;
  }
  *bitsp = val;
  return 1;
}

static int ares_inet_pton6(const char *src, unsigned char *dst)
{
  ares_buf_t   *in = NULL;
  unsigned char tmp[NS_IN6ADDRSZ];
  size_t        tp;
  size_t        colon_at = 0;
  size_t        tok;
  size_t        len;
  size_t        n;
  size_t        i;
  int           saw_xdigit;
  int           count_xdigit;
  unsigned int  val;
  unsigned char ch;
  int           hv;
  ares_bool_t   have_colon = ARES_FALSE;
  int           result     = -1;

  memset(tmp, 0, sizeof(tmp));
  tp = 0;

  in = open_text(src, &len);
  if (in == NULL) {
    fail_open(len);
    return -1;
  }

  /* Leading :: requires some special handling. */
  if (ares_buf_begins_with(in, (const unsigned char *)":", 1)) {
    if (ares_buf_consume(in, 1) != ARES_SUCCESS ||
        !ares_buf_begins_with(in, (const unsigned char *)":", 1)) {
      goto enoent;
    }
  }

  tok          = ares_buf_get_position(in);
  saw_xdigit   = 0;
  count_xdigit = 0;
  val          = 0;
  while (take_byte(in, &ch)) {
    hv = hex_value(ch);
    if (hv >= 0) {
      if (count_xdigit >= 4) {
        goto enoent;
      }
      val <<= 4;
      val  |= (unsigned int)hv;
      if (val > 0xffff) {
        goto enoent; /* LCOV_EXCL_LINE: DefensiveCoding */
      }
      saw_xdigit = 1;
      count_xdigit++;
      continue;
    }
    if (ch == ':') {
      tok = ares_buf_get_position(in);
      if (!saw_xdigit) {
        if (have_colon) {
          goto enoent;
        }
        colon_at   = tp;
        have_colon = ARES_TRUE;
        continue;
      } else if (ares_buf_len(in) == 0) {
        goto enoent;
      }
      if (tp + NS_INT16SZ > NS_IN6ADDRSZ) {
        goto enoent;
      }
      tmp[tp++]    = (unsigned char)((val >> 8) & 0xff);
      tmp[tp++]    = (unsigned char)(val & 0xff);
      saw_xdigit   = 0;
      count_xdigit = 0;
      val          = 0;
      continue;
    }
    if (ch == '.' && (tp + NS_INADDRSZ) <= NS_IN6ADDRSZ &&
        ares_inet_net_pton_ipv4(src + tok, tmp + tp, NS_INADDRSZ, ARES_FALSE) >
          0) {
      tp         += NS_INADDRSZ;
      saw_xdigit  = 0;
      break; /* '\0' was seen by inet_pton4(). */
    }
    goto enoent;
  }
  if (saw_xdigit) {
    if (tp + NS_INT16SZ > NS_IN6ADDRSZ) {
      goto enoent;
    }
    tmp[tp++] = (unsigned char)((val >> 8) & 0xff);
    tmp[tp++] = (unsigned char)(val & 0xff);
  }
  if (have_colon) {
    /*
     * Since some memmove()'s erroneously fail to handle
     * overlapping regions, we'll do the shift by hand.
     */
    if (tp == NS_IN6ADDRSZ) {
      goto enoent;
    }
    n = tp - colon_at;
    for (i = 1; i <= n; i++) {
      tmp[NS_IN6ADDRSZ - i] = tmp[colon_at + n - i];
      tmp[colon_at + n - i] = 0;
    }
    tp = NS_IN6ADDRSZ;
  }
  if (tp != NS_IN6ADDRSZ) {
    goto enoent;
  }

  memcpy(dst, tmp, NS_IN6ADDRSZ);
  result = 1;
  goto done;

enoent:
  SET_SOCKERRNO(ENOENT);
  result = -1;

done:
  ares_buf_destroy(in);
  return result;
}

static int ares_inet_net_pton_ipv6(const char *src, unsigned char *dst,
                                   size_t size)
{
  ares_buf_t                *in = NULL;
  struct ares_in6_addr       in6;
  int                        ret;
  size_t                     bits;
  size_t                     bytes;
  size_t                     len;
  size_t                     addr_len;
  char                       addr[INET6_ADDRSTRLEN + sizeof("/128")];
  const unsigned char       *look;
  size_t                     look_len;
  static const unsigned char slash[1] = { '/' };

  len = ares_strlen(src);
  if (len >= sizeof(addr)) {
    SET_SOCKERRNO(EMSGSIZE);
    return -1;
  }

  in = open_text(src, &len);
  if (in == NULL) {
    fail_open(len);
    return -1;
  }

  ares_buf_tag(in);
  (void)ares_buf_consume_until_charset(in, slash, 1, ARES_FALSE);
  addr_len = ares_buf_tag_length(in);
  if (addr_len >= sizeof(addr)) {
    SET_SOCKERRNO(EMSGSIZE); /* LCOV_EXCL_LINE: DefensiveCoding */
    ares_buf_destroy(in);    /* LCOV_EXCL_LINE: DefensiveCoding */
    return -1;               /* LCOV_EXCL_LINE: DefensiveCoding */
  }
  memcpy(addr, src, addr_len);
  addr[addr_len] = '\0';

  look = ares_buf_peek(in, &look_len);
  if (look != NULL && look_len > 0 && look[0] == '/') {
    if (ares_buf_consume(in, 1) != ARES_SUCCESS || !getbits(in, &bits)) {
      SET_SOCKERRNO(ENOENT);
      ares_buf_destroy(in);
      return -1;
    }
  } else {
    bits = 128;
  }
  ares_buf_destroy(in);
  in = NULL;

  ret = ares_inet_pton6(addr, (unsigned char *)&in6);
  if (ret != 1) {
    return -1;
  }

  bytes = (bits + 7) / 8;
  if (bytes > size) {
    SET_SOCKERRNO(EMSGSIZE);
    return -1;
  }
  /* Only the first (bits+7)/8 bytes carry the network, zero the remainder of
   * the caller's buffer so it never holds uninitialized data. */
  memset(dst, 0, size);
  memcpy(dst, &in6, bytes);
  return (int)bits;
}

/* Parse a network, not an address.  See ares_inet_net_pton.h for the
 * contract and how it differs from ares_inet_pton().
 * author:
 *      Paul Vixie (ISC), June 1996
 */
int ares_inet_net_pton(int af, const char *src, void *dst, size_t size)
{
  switch (af) {
    case AF_INET:
      return ares_inet_net_pton_ipv4(src, dst, size, ARES_TRUE);
    case AF_INET6:
      return ares_inet_net_pton_ipv6(src, dst, size);
    default:
      return -1;
  }
}

/*
 * int
 * inet_pton(af, src, dst)
 *      convert an address (not a network) from presentation to network
 *      format, like POSIX inet_pton().  A "/bits" prefix length denotes a
 *      prefix, not an address (RFC 4291 Section 2.3 vs. the address text
 *      forms of Section 2.2), and is rejected; dst is always fully written
 *      on success (4 bytes for AF_INET, 16 bytes for AF_INET6).
 *      For a network with a prefix length, use ares_inet_net_pton().
 * return:
 *      1 on success, 0 if src is not a valid address for af (as POSIX
 *      inet_pton() does for any unparsable input), or -1 with errno set to
 *      EAFNOSUPPORT if af is not supported.
 */
int ares_inet_pton(int af, const char *src, void *dst)
{
  int result;

  if (af == AF_INET) {
    result =
      ares_inet_net_pton_ipv4(src, dst, sizeof(struct in_addr), ARES_FALSE);
  } else if (af == AF_INET6) {
    result = ares_inet_pton6(src, dst);
  } else {
    SET_SOCKERRNO(EAFNOSUPPORT);
    return -1;
  }
  /* Neither parser can fail for a system reason: any failure (ENOENT, or
   * EMSGSIZE for too many IPv4 octets as in "1.2.3.4.5") means src is not a
   * valid address. */
  return (result > -1) ? 1 : 0;
}

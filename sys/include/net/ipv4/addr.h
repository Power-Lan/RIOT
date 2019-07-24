/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_ipv4_addr   IPv4 addresses
 * @ingroup     net_ipv4
 * @brief       IPv4 address types and helper function
 * @{
 *
 * @file
 * @brief   IPv4 address type and helper functions definitions
 *
 * @author  Martine Lenders <mlenders@inf.fu-berlin.de>
 */
#ifndef NET_IPV4_ADDR_H
#define NET_IPV4_ADDR_H

#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include "byteorder.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Maximum length of an IPv4 address as string.
 */
#define IPV4_ADDR_MAX_STR_LEN       (sizeof("255.255.255.255"))

/**
 * @brief   Static initializer for the unspecified IPv4 address (0.0.0.0)
 *
 */
#define IPV4_ADDR_UNSPECIFIED               {{ 0x00, 0x00, 0x00, 0x00 }}

/**
 * @brief   Static initializer for the loopback IPv4 address (127.0.0.1)
 *
 */
#define IPV4_ADDR_LOOPBACK                  {{ 0x7F, 0x00, 0x00, 0x01 }}

/**
 * @brief Data type to represent an IPv4 address.
 */
typedef union {
    uint8_t u8[4];          /**< as 4 8-bit unsigned integer */
    network_uint32_t u32;   /**< as 32-bit unsigned integer */
} ipv4_addr_t;

/**
 * @see @ref IPV4_ADDR_UNSPECIFIED
 */
extern const ipv4_addr_t ipv4_addr_unspecified;

/**
 * @see @ref IPV4_ADDR_LOOPBACK
 */
extern const ipv4_addr_t ipv4_addr_loopback;

/**
 * @brief   Checks if @p addr is unspecified (all zero).
 *
 * @param[in] addr  An IPv4 address.
 *
 * @return  true, if @p addr is unspecified address
 * @return  false, otherwise.
 */
static inline bool ipv4_addr_is_unspecified(const ipv4_addr_t *addr)
{
    return (memcmp(addr, &ipv4_addr_unspecified, sizeof(ipv4_addr_t)) == 0);
}

/**
 * @brief   Checks if @p addr is a loopback address.
 *
 * @param[in] addr  An IPv4 address.
 *
 * @return  true, if @p addr is loopback address,
 * @return  false, otherwise.
 */
static inline bool ipv4_addr_is_loopback(const ipv4_addr_t *addr)
{
    return (memcmp(addr, &ipv4_addr_loopback, sizeof(ipv4_addr_t)) == 0);
}

/**
 * @brief   Check if @p addr is a multicast address.
 *
 *
 * @param[in] addr  An IPv4 address.
 *
 * @return  true, if @p addr is multicast address,
 * @return  false, otherwise.
 */
static inline bool ipv4_addr_is_multicast(const ipv4_addr_t *addr)
{
    return (addr->u8[0] >= 224 && addr->u8[0] < 240);
}

/**
 * @brief   Checks if two IPv4 addresses are equal.
 *
 * @param[in] a     An IPv4 address.
 * @param[in] b     Another IPv4 address.
 *
 * @return  true, if @p a and @p b are equal
 * @return  false, otherwise.
 */
static inline bool ipv4_addr_equal(ipv4_addr_t *a, ipv4_addr_t *b)
{
    return (a->u32.u32 == b->u32.u32);
}

/**
 * @brief   Converts an IPv4 address to its string representation
 *
 * @param[out] result       The resulting string representation of at least
 *                          @ref IPV4_ADDR_MAX_STR_LEN.
 * @param[in] addr          An IPv4 address
 * @param[in] result_len    Length of @p result
 *
 * @return  @p result, on success
 * @return  NULL, if @p result_len was lesser than IPV4_ADDR_MAX_STR_LEN
 * @return  NULL, if @p result or @p addr was NULL
 */
char *ipv4_addr_to_str(char *result, const ipv4_addr_t *addr, uint8_t result_len);

/**
 * @brief   Converts an IPv4 address string representation to a byte-represented
 *          IPv4 address
 *
 * @param[in] result    The resulting byte representation
 * @param[in] addr      An IPv4 address string representation
 *
 * @return  @p result, on success
 * @return  NULL, if @p addr was malformed
 * @return  NULL, if @p result or @p addr was NULL
 */
ipv4_addr_t *ipv4_addr_from_str(ipv4_addr_t *result, const char *addr);

#ifdef __cplusplus
}
#endif

#endif /* NET_IPV4_ADDR_H */
/** @} */

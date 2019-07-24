/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for
 * more details.
 */

/**
 * @{
 *
 * @file
 *
 * @author      Martine Lenders <mlenders@inf.fu-berlin.de>
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "net/ipv4/addr.h"

#ifdef MODULE_FMT
#include "fmt.h"
#else
#include <stdio.h>
#endif

const ipv6_addr_t ipv4_addr_unspecified = IPV4_ADDR_UNSPECIFIED;
const ipv6_addr_t ipv4_addr_loopback = IPV4_ADDR_LOOPBACK;

/**
 * @}
 */

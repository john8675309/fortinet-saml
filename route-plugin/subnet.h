/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FORTIGATE_SUBNET_H
#define FORTIGATE_SUBNET_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>

/* RFC 7296 INTERNAL_IP4_SUBNET: four address bytes, four netmask bytes. */
static bool decode_subnet(const uint8_t *data, size_t len,
                          uint32_t *network, unsigned *prefix)
{
    uint32_t addr, mask, inverse;
    if (len != 8 || !data) { return false; }
    memcpy(&addr, data, 4);
    memcpy(&mask, data + 4, 4);
    mask = ntohl(mask);
    inverse = ~mask;
    /* Reject noncontiguous masks and default routes. */
    if (!mask || (inverse & (inverse + 1))) { return false; }
    *network = ntohl(addr) & mask;
    *prefix = 0;
    while (mask) { (*prefix)++; mask <<= 1; }
    return true;
}
#endif

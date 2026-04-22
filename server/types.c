#include "types.h"

qr_t flags_get_qr(uint16_t flags)
{
    return (qr_t)((flags >> 15) & 1);
}

opcode_t flags_get_opcode(uint16_t flags)
{
    int mask = 0x7800;
    switch ((flags & mask) >> 11) {
    case 0:
        return OPCODE_QUERY;
    case 1:
        return OPCODE_IQUERY;
    case 2:
        return OPCODE_STATUS;
    case 4:
        return OPCODE_NOTIFY;
    case 5:
        return OPCODE_UPDATE;
    case 6:
        return OPCODE_DSO;
    default:
        return OPCODE_UNKNOWN;
    }
}

aa_t flags_get_aa(uint16_t flags)
{
    return (aa_t)((flags >> 10) & 1);
}

tc_t flags_get_tc(uint16_t flags)
{
    return (tc_t)((flags >> 9) & 1);
}

rd_t flags_get_rd(uint16_t flags)
{
    return (rd_t)((flags >> 8) & 1);
}

ra_t flags_get_ra(uint16_t flags)
{
    return (ra_t)((flags >> 7) & 1);
}

rcode_t flags_get_rcode(uint16_t flags)
{
    int mask = 0xF;
    return (rcode_t)(flags & mask);
}

void flags_set_qr(uint16_t* flags, qr_t qr)
{
    int mask = 0x8000;
    *flags = (*flags & ~mask) | ((uint16_t)qr << 15);
}

void flags_set_opcode(uint16_t* flags, opcode_t opcode)
{
    int mask = 0x7800;
    *flags = (*flags & ~mask) | ((uint16_t)opcode << 11);
}

void flags_set_aa(uint16_t* flags, aa_t aa)
{
    int mask = 0x400;
    *flags = (*flags & ~mask) | ((uint16_t)aa << 10);
}

void flags_set_tc(uint16_t* flags, tc_t tc)
{
    int mask = 0x200;
    *flags = (*flags & ~mask) | ((uint16_t)tc << 9);
}

void flags_set_rd(uint16_t* flags, rd_t rd)
{
    int mask = 0x100;
    *flags = (*flags & ~mask) | ((uint16_t)rd << 8);
}

void flags_set_ra(uint16_t* flags, ra_t ra)
{
    int mask = 0x80;
    *flags = (*flags & ~mask) | ((uint16_t)ra << 7);
}

void flags_set_z(uint16_t* flags)
{
    int mask = 0x70;
    *flags = (*flags & ~mask) | ((uint16_t)0 << 5);
}

void flags_set_rcode(uint16_t* flags, rcode_t rcode)
{
    int mask = 0xF;
    *flags = (*flags & ~mask) | (uint16_t)rcode;
}

qtype_t get_qtype(uint16_t qtype)
{
    switch (qtype) {
    case 1:
        return QTYPE_A;
    default:
        return QTYPE_ANY;
    }
}

qclass_t get_qclass(uint16_t qclass)
{
    switch (qclass) {
    case 1:
        return QCLASS_IN;
    default:
        return QCLASS_ANY;
    }
}

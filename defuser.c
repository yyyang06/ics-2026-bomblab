#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t lo = (uint32_t)challenge;
    uint32_t hi = (uint32_t)(challenge >> 32);
    uint32_t a = hi ^ (lo + UINT32_C(0x1f33));
    uint32_t b = (lo * 3u + (uint32_t)(challenge >> 16)) ^ UINT32_C(0x81b1);
    uint32_t v = (b + a * 8u) ^ UINT32_C(0x8dac);
    return write_answer(out, cap, &v, 1);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t v[6];
    v[0] = (uint32_t)((challenge >> 12) & 15u) * 3u;
    for (unsigned i = 1; i < 6; ++i)
        v[i] = (v[i-1] * 5u - i) ^
               ((uint32_t)((challenge >> (6u + 3u*i)) & 63u) + 12u);
    return write_answer(out, cap, v, 6);
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t v[2], x = (uint32_t)(challenge >> 3) ^ (uint32_t)(challenge >> 32);
    v[0] = (uint32_t)challenge & 7u;
    /* Jump table at 0x405820: cases 1, 0, 4, 2, 6, 3, 7, 5. */
    switch (v[0]) {
    case 0: v[1] = 5u*x + 0xa8b4u; break;
    case 1: v[1] = 5u*x + 0x1f6adu; break;
    case 2: v[1] = (x ^ 0x79b7u) + (x >> 1); break;
    case 3: v[1] = (x ^ 0x3b4du) + (x >> 2); break;
    case 4: v[1] = (x * 4u) ^ 0x2d60u; break;
    case 5: v[1] = (x * 4u) ^ 0x0f2du; break;
    case 6: v[1] = 3u*x + 0xb69fu; break;
    default: v[1] = 5u*x + 0x27628u; break;
    }
    return write_answer(out, cap, v, 2);
}

static uint32_t walk(uint32_t target, uint32_t low, uint32_t high, uint32_t salt) {
    uint32_t mid = low + ((high - low) >> 1);
    if (target == mid) return (mid + 0x6au) ^ salt;
    if (target < mid)
        return (walk(target, low, mid - 1u, salt) * 3u) ^ (mid + salt) ^ 0x19u;
    return (walk(target, mid + 1u, high, salt) * 3u) ^ (mid + salt) ^ 2u;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t salt = (uint32_t)(challenge >> 7) ^ (uint32_t)(challenge >> 32);
    uint32_t v = walk((uint32_t)challenge & 127u, 0, 127, salt);
    return write_answer(out, cap, &v, 1);
}

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    static const struct { uint32_t value, id; unsigned next; } nodes[12] = {
        {0xdef6u,0x883u,6}, {0xa39eu,0x720u,9},
        {0xb730u,0x92au,5}, {0x3708u,0x361u,10},
        {0x9d44u,0x030u,0}, {0x4927u,0x50cu,7},
        {0x3da2u,0x681u,1}, {0xc6e4u,0x20eu,11},
        {0x7188u,0x13au,12}, {0x61d6u,0xb89u,3},
        {0x6a32u,0xa7cu,2}, {0xe91cu,0x429u,8}
    };
    static const unsigned starts[8] = {4,0,6,1,9,3,10,2};
    unsigned node = starts[challenge & 7u];
    unsigned count = 1u + (unsigned)((challenge >> 3) & 3u);
    uint32_t v[2] = {
        (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32) ^ 0x5100u, 0
    };
    for (unsigned i = 0; i < count; ++i) {
        v[0] = ((v[0] + nodes[node].value) * 5u) ^ nodes[node].id;
        v[1] = nodes[node].id;
        node = nodes[node].next;
    }
    return write_answer(out, cap, v, 2);
}

static uint32_t operation(unsigned index, uint32_t x) {
    /* Function pointer table at 0x405e00: ops 0,5,1,4,4,2,0,3. */
    switch (index) {
    case 0: case 6: return ((x << 1) | (x >> 31)) ^ 0xf675u;
    case 1: return (4u*x + 0xb38cu) ^ (7u*x);
    case 2: return (x >> 7) | (x << 25);
    case 3: case 4: return (x ^ 0x586cu) + (x << 5);
    case 5: return (x + 0x3295u) ^ (x >> 3);
    default: return (x ^ (x >> 7)) + 0x17b9u;
    }
}

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    uint32_t x = (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32);
    x = operation((unsigned)(challenge & 7u), x) ^ 0x1222u;
    x = operation((unsigned)((challenge >> 3) & 7u), x) + 0x9393u;
    return write_answer(out, cap, &x, 1);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    uint32_t index = (uint32_t)context & 3u;
    uint32_t a = (uint32_t)challenge ^ (uint32_t)(challenge >> 32);
    uint32_t b = (uint32_t)context ^ (uint32_t)(context >> 32);
    uint32_t x = a ^ b;
    uint32_t y = ((x >> 1) | (x << 31)) ^ UINT32_C(0x1c80) ^
                 (index * UINT32_C(0x6872)) ^ (uint32_t)(context >> 16);
    uint32_t z = y ^ (b + index + UINT32_C(0x74f2) + (a >> 1));
    int n;
    if (!out || !cap) return 1;
    /* secret_gate requires OPEN at offsets 32..35; integers start at 36. */
    n = snprintf(out, cap, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOPEN%" PRIu32
                 " %" PRIu32 " %" PRIu32, index, y, z);
    return n < 0 || (size_t)n >= cap;
}

/**
 * Fast unit tests for otls_wire_format (no MP-SPDZ VM, no .mpc compile).
 * Run: make otls-wire-format-test.x && ./otls-wire-format-test.x
 */
#include "otls_wire_format.hpp"

#include <openssl/rand.h>

#include <cstring>
#include <iostream>
#include <stdexcept>

using otls_wire::add_mod256;
using otls_wire::be_words_to_le32;
using otls_wire::digest_to_words32;
using otls_wire::pack_bytes;
using otls_wire::scalar_le_to_be_words;
using otls_wire::split_scalar_three_shares;
using otls_wire::unpack_uint64_be_words;

static int failures = 0;

#define CHECK(cond, msg) \
    do \
    { \
        if (!(cond)) \
        { \
            std::cerr << "FAIL: " << msg << " at " << __LINE__ << "\n"; \
            failures++; \
        } \
    } while (0)

static void test_scalar_roundtrip()
{
    uint8_t le32[32];
    RAND_bytes(le32, 32);
    auto w = scalar_le_to_be_words(le32);
    CHECK(w.size() == 4, "scalar_le_to_be_words size");
    uint8_t out[32];
    be_words_to_le32(w, out);
    CHECK(std::memcmp(le32, out, 32) == 0, "scalar LE <-> BE words");
}

static void test_pack_unpack()
{
    std::vector<uint8_t> data(100);
    RAND_bytes(data.data(), data.size());
    auto words = pack_bytes(data, 20);
    CHECK((int) words.size() == 20, "pack_bytes pads to max_words");
    std::vector<uint64_t> u;
    for (long x : words)
        u.push_back((uint64_t) (int64_t) x);
    auto back = unpack_uint64_be_words(u, data.size());
    CHECK(back == data, "pack_bytes / unpack_uint64 roundtrip");
}

static void test_split_three_shares_recombines()
{
    uint8_t priv[32];
    RAND_bytes(priv, 32);
    auto words12 = split_scalar_three_shares(priv);
    CHECK(words12.size() == 12, "split_scalar_three_shares length");

    uint8_t r0[32], r1[32], r2[32];
    be_words_to_le32({ words12[0], words12[1], words12[2], words12[3] }, r0);
    be_words_to_le32({ words12[4], words12[5], words12[6], words12[7] }, r1);
    be_words_to_le32({ words12[8], words12[9], words12[10], words12[11] }, r2);

    uint8_t t[32], sum[32];
    add_mod256(r0, r1, t);
    add_mod256(t, r2, sum);
    CHECK(std::memcmp(priv, sum, 32) == 0, "r0+r1+r2 == priv (mod 2^256)");
}

static void test_digest_words_roundtrip()
{
    std::vector<uint8_t> d(32);
    RAND_bytes(d.data(), 32);
    auto lw = digest_to_words32(d);
    CHECK(lw.size() == 4, "digest_to_words32 size");
    std::vector<uint64_t> u;
    for (long x : lw)
        u.push_back((uint64_t) (int64_t) x);
    auto back = unpack_uint64_be_words(u, 32);
    CHECK(back == d, "digest words roundtrip");
}

int main()
{
    test_scalar_roundtrip();
    test_pack_unpack();
    test_split_three_shares_recombines();
    test_digest_words_roundtrip();

    if (failures != 0)
    {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cerr << "otls_wire_format_test: all checks passed\n";
    return 0;
}

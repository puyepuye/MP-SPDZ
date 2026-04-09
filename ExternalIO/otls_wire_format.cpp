#include "otls_wire_format.hpp"

#include <openssl/rand.h>

#include <stdexcept>

namespace otls_wire
{

void add_mod256(const uint8_t* a, const uint8_t* b, uint8_t* out)
{
    uint16_t c = 0;
    for (int i = 0; i < 32; i++)
    {
        c = (uint16_t) c + a[i] + b[i];
        out[i] = (uint8_t) (c & 0xff);
        c >>= 8;
    }
}

void sub_mod256(const uint8_t* k, const uint8_t* s, uint8_t* out)
{
    int borrow = 0;
    for (int i = 0; i < 32; i++)
    {
        int v = (int) k[i] - (int) s[i] - borrow;
        if (v < 0)
        {
            v += 256;
            borrow = 1;
        }
        else
            borrow = 0;
        out[i] = (uint8_t) v;
    }
}

std::vector<uint64_t> scalar_le_to_be_words(const uint8_t* le32)
{
    std::vector<uint64_t> w(4);
    for (int i = 0; i < 4; i++)
    {
        uint64_t x = 0;
        for (int j = 0; j < 8; j++)
            x = (x << 8) | le32[i * 8 + j];
        w[i] = x;
    }
    return w;
}

void be_words_to_le32(const std::vector<uint64_t>& words4, uint8_t out[32])
{
    if (words4.size() < 4)
        throw std::runtime_error("be_words_to_le32: need 4 words");
    for (int i = 0; i < 4; i++)
    {
        uint64_t w = words4[i];
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (uint8_t) ((w >> (8 * (7 - j))) & 0xff);
    }
}

std::vector<long> pack_bytes(const std::vector<uint8_t>& data, int max_words)
{
    std::vector<long> words;
    for (size_t i = 0; i < data.size(); i += 8)
    {
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j)
        {
            w <<= 8;
            size_t idx = i + j;
            if (idx < data.size())
                w |= data[idx];
        }
        words.push_back((long) w);
    }
    while ((int) words.size() < max_words)
        words.push_back(0);
    if ((int) words.size() > max_words)
        words.resize(max_words);
    return words;
}

std::vector<uint64_t> split_scalar_three_shares(const uint8_t* priv_le32)
{
    uint8_t r0[32], r1[32], r2[32], sum01[32];
    if (RAND_bytes(r0, 32) != 1 || RAND_bytes(r1, 32) != 1)
        throw std::runtime_error("RAND_bytes failed");
    add_mod256(r0, r1, sum01);
    sub_mod256(priv_le32, sum01, r2);

    std::vector<uint64_t> out;
    auto w0 = scalar_le_to_be_words(r0);
    auto w1 = scalar_le_to_be_words(r1);
    auto w2 = scalar_le_to_be_words(r2);
    out.insert(out.end(), w0.begin(), w0.end());
    out.insert(out.end(), w1.begin(), w1.end());
    out.insert(out.end(), w2.begin(), w2.end());
    return out;
}

std::vector<long> digest_to_words32(const std::vector<uint8_t>& d)
{
    auto u = scalar_le_to_be_words(d.data());
    std::vector<long> w;
    for (uint64_t x : u)
        w.push_back((long) (int64_t) x);
    return w;
}

std::vector<uint8_t> unpack_uint64_be_words(const std::vector<uint64_t>& vals, size_t length)
{
    std::vector<uint8_t> out;
    out.reserve(vals.size() * 8);
    for (uint64_t w : vals)
    {
        for (int i = 7; i >= 0; --i)
            out.push_back((w >> (i * 8)) & 0xff);
    }
    if (out.size() > length)
        out.resize(length);
    return out;
}

} // namespace otls_wire

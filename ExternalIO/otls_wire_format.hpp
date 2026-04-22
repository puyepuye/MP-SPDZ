/** Wire-format helpers shared by otls-external-io-client and unit tests (no MP-SPDZ VM). */
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace otls_wire
{

void add_mod256(const uint8_t* a, const uint8_t* b, uint8_t* out);
void sub_mod256(const uint8_t* k, const uint8_t* s, uint8_t* out);

/** 32-byte little-endian integer → 4 × 64-bit big-endian words (matches MPC packing). */
std::vector<uint64_t> scalar_le_to_be_words(const uint8_t* le32);

/** Inverse: four BE words → 32 LE bytes. */
void be_words_to_le32(const std::vector<uint64_t>& words4, uint8_t out[32]);

/** TLS record / MPC buffer packing: bytes → sint/regint words (BE uint64 per 8-byte chunk). */
std::vector<long> pack_bytes(const std::vector<uint8_t>& data, int max_words);

/** Three additive shares mod 2^256 → 12 × uint64 BE words (field private inputs). */
std::vector<uint64_t> split_scalar_three_shares(const uint8_t* priv_le32);

/** SHA-256 digest → 4 × int64 words for send_public_inputs_raw64. */
std::vector<long> digest_to_words32(const std::vector<uint8_t>& d);

/** Unpack BE uint64 words to bytes (same layout as gfp unpack_words_fp for values &lt; 2^64). */
std::vector<uint8_t> unpack_uint64_be_words(const std::vector<uint64_t>& words, size_t length);

} // namespace otls_wire

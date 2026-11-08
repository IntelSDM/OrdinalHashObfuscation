#pragma once

#include <cstdint>
#include <cstdlib>
#include <emmintrin.h>
#include <wmmintrin.h>

struct Hash128
{
    uint64_t Lo;
    uint64_t Hi;
};

#if defined(__clang__) || defined(__GNUC__)
#  define MMO_ATTR_AES __attribute__((target("aes")))
#else
#  define MMO_ATTR_AES
#endif

struct MMOMasterKey
{
    Hash128 Salt;
    Hash128 Kpad;
    Hash128 Rk[4];
};

inline MMOMasterKey GMMO = {
    {0xA1A1A1A1A1A1A1A1ULL, 0xB1B1B1B1B1B1B1B1ULL},
    {0xC1C1C1C1C1C1C1C1ULL, 0xD1D1D1D1D1D1D1D1ULL},
    {{0xE111111111111111ULL, 0xF111111111111111ULL},
     {0xE222222222222222ULL, 0xF222222222222222ULL},
     {0xE333333333333333ULL, 0xF333333333333333ULL},
     {0xE444444444444444ULL, 0xF444444444444444ULL}}
};

inline uint64_t MMORand64()
{
    return (((uint64_t)rand()) << 32) ^ (uint64_t)rand();
}

inline void MMOInit()
{
    GMMO.Salt.Lo = MMORand64();
    GMMO.Salt.Hi = MMORand64();
    GMMO.Kpad.Lo = MMORand64();
    GMMO.Kpad.Hi = MMORand64();
    for (int i = 0; i < 4; ++i)
    {
        GMMO.Rk[i].Lo = MMORand64();
        GMMO.Rk[i].Hi = MMORand64();
    }
}

inline __m128i LoadHash128AsXmm(const Hash128& h)
{
    return _mm_set_epi64x((long long)h.Hi, (long long)h.Lo);
}

MMO_ATTR_AES inline uint64_t CompileMMO(uint64_t input)
{
    const __m128i input128 = _mm_set_epi64x(0, (long long)input);
    const __m128i kpad = LoadHash128AsXmm(GMMO.Kpad);
    const __m128i key = _mm_xor_si128(kpad, input128);

    __m128i state = LoadHash128AsXmm(GMMO.Salt);
    for (int r = 0; r < 4; ++r)
    {
        __m128i rkxorkey = _mm_xor_si128(LoadHash128AsXmm(GMMO.Rk[r]), key);
        state = (r == 3) ? _mm_aesenclast_si128(state, rkxorkey) : _mm_aesenc_si128(state, rkxorkey);
    }
    state = _mm_xor_si128(state, LoadHash128AsXmm(GMMO.Salt));

    return (uint64_t)_mm_cvtsi128_si64(state);
}

inline uint64_t EncodeMMOInput(uint64_t sitesalt, uint8_t i, uint8_t v, uint8_t r)
{
    return sitesalt ^ ((uint64_t)i << 56) ^ ((uint64_t)v << 48) ^ ((uint64_t)r << 40);
}
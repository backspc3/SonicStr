#ifndef SONICSTR_H
#define SONICSTR_H

#include <immintrin.h>
#include <iostream>

#define SONICSTR_INLINE     inline
#define SONICSTR_NOEXCEPT   noexcept

namespace Sonic
{

// Internal comparison function which tries to use SIMD operations for string comparison.
static SONICSTR_INLINE bool StrCmp( const char* aStr, const char* bStr, size_t aLen )
{
#ifdef __AVX2__
    // 32 byte blocks.
    while (aLen > 32)
    {
        // AND(&) left and right values ( _A str chunk && _B str chunk )
        // to extract mask:

        //   +-----------+    +-----------+
        //   | 0100 0110 |    | 0100 0110 |
        //   |           |    |           |
        //   |     &     |    |     &     |
        //   |           |    |           |
        //   | 0100 0110 |    | 1000 0110 |
        //   +-----------+    +-----------+
        //         |                |
        //         |                |
        //     0100 0110        0000 0110

        // So if result of AND is equal to either of inputs it means
        // the chunks are equal.

        // We run the resulting output and either left or right through
        // the cmpeq routine, which will for each byte in the vector
        // either output 0 or 0xff and add it. If the inputs are equal
        // value must be 0xffffffff.

        // Load 32 chars of both _A and _B.
        __m256i left    = _mm256_loadu_si256((__m256i* const)aStr);
        __m256i right   = _mm256_loadu_si256((__m256i* const)bStr);

        __m256i res_and = _mm256_and_si256(left, right);
        __m256i cmp     = _mm256_cmpeq_epi8(res_and, left);

        if (_mm256_movemask_epi8(cmp) != 0xffffffff)
            return false;

        aLen -= 32;
        aStr += 32;
        bStr += 32;
    }
#endif//__AVX2__

#ifdef __SSE2__
    while (aLen > 16)
    {
        // Works like AVX but with 128 bits instead of 256.
        __m128i left    = _mm_loadu_epi8((const void*)aStr);
        __m128i right   = _mm_loadu_epi8((const void*)bStr);

        __m128i res_and = _mm_and_si128(left, right);
        __m128i cmp     = _mm_cmpeq_epi8(res_and, left);

        if (_mm_movemask_epi8(cmp) != 0xFFFF)
            return false;

        // 16 bytes at a time.
        aLen -= 16;
        aStr += 16;
        bStr += 16;
    }
#endif//__SSE2__

    // 8 byte blocks.
    // We can process in block of 64 bits.
    while(aLen > 8)
    {
        // Cast to int64 and extract 8 bytes or 'chars' as 64 bit block.
        const unsigned long long left    = *((const unsigned long long* const)aStr);
        const unsigned long long right   = *((const unsigned long long* const)bStr);

        // If left masked by right is not equal to left
        // we know this block is not EQUAL.
        if(left != right)
            return false;

        //....
        aLen -= 8;
        aStr += 8;
        bStr += 8;
    }

    // 4 byte blocks.
    while(aLen > 4)
    {
        // Do the same as above but cast to integer and process in groups of 4 bytes.
        const unsigned int left    = *((unsigned int* const)aStr);
        const unsigned int right   = *((unsigned int* const)bStr);

        if(left != right)
            return false;

        //....
        aLen -= 4;
        aStr += 4;
        bStr += 4;
    }

    // Remaining size 2 bytes not worth?
    // Finish off any remaining bytes linearly.
    while (aLen > 0)
    {
        if ((*aStr != *bStr))
            return false;
        aLen--;
        aStr++;
        bStr++;
    }

    return true;
}

}

#endif // SONICSTR_H

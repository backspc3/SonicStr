#ifndef SONICSTR_H
#define SONICSTR_H

#include <immintrin.h>
#include <cstring>
#include <bit>

#define SONICSTR_INLINE     inline
#define SONICSTR_NOEXCEPT   noexcept
#define SONICSTR_CONSTEXPR  constexpr

namespace Sonic
{

static constexpr size_t npos = -1;

// Internal comparison function which tries to use SIMD operations for string comparison.
static SONICSTR_INLINE SONICSTR_CONSTEXPR bool simd_str_cmp( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT
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
        const __m256i left    = _mm256_loadu_si256((__m256i* const)aStr);
        const __m256i right   = _mm256_loadu_si256((__m256i* const)bStr);

        const __m256i res_and = _mm256_and_si256(left, right);
        const __m256i cmp     = _mm256_cmpeq_epi8(res_and, left);

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
        const __m128i left    = _mm_loadu_epi8((const void*)aStr);
        const __m128i right   = _mm_loadu_epi8((const void*)bStr);

        const __m128i res_and = _mm_and_si128(left, right);
        const __m128i cmp     = _mm_cmpeq_epi8(res_and, left);

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
        const unsigned int left    = *((const unsigned int* const)aStr);
        const unsigned int right   = *((const unsigned int* const)bStr);

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


template <typename T>
static SONICSTR_INLINE SONICSTR_CONSTEXPR T clear_leftmost_set(const T value) SONICSTR_NOEXCEPT
{
    return value & (value - 1);
}


template <typename T>
static SONICSTR_INLINE SONICSTR_CONSTEXPR unsigned get_first_bit_set(const T value) SONICSTR_NOEXCEPT
{
    return std::countr_zero(value);
}

// If we have AVX2 Instruction set defined, Sonic str wwill default
// to avx algo. If we cannot find AVX2 instruction set, we will go with
// SWAR method. 
// Returns either index into haystack of needle if found. 
// or
// -1 as size_t or largest possible size_t if not found.

// Based on:
// http://0x80.pl/articles/simd-strfind.html
static SONICSTR_INLINE size_t simd_swar_str_contains_needle( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT
{
#ifdef __AVX2__

    // Vectors holding first and last characters of needle
    const __m256i needle_first_char_v = _mm256_set1_epi8( needle[0] );              // At begin - 0
    const __m256i needle_last_char_v  = _mm256_set1_epi8( needle[needle_len - 1]);  // At end   - Len - 1
    
    // Iterate in blocks of 32.
    for(size_t i = 0; i < len; i += 32)
    {
        // Extract chunks
        const __m256i str_block_first = _mm256_loadu_si256( (const __m256i*) str + i  );
        const __m256i str_block_last  = _mm256_loadu_si256( (const __m256i*) str + i + needle_len - 1);
    
        // Compare extracted chunks with our character vectors
        // holdin the first and last letters of the needle.
        const __m256i equality_first = _mm256_cmpeq_epi8( needle_first_char_v, str_block_first );
        const __m256i equality_last  = _mm256_cmpeq_epi8( needle_last_char_v, str_block_last );

        // With this mask we extract the positions where we match with out needles first/last characters.    
        unsigned int mask = _mm256_movemask_epi8( _mm256_and_si256( equality_first, equality_last ) );
    
        // While mask contains any set bits it means there are still possible locations
        // where we can find the needle.
        while(mask != 0)
        {
            // Extract index or position from the first found set bit.
            const auto bit_pos = ::Sonic::get_first_bit_set( mask );
            
            // If needle maatches we have found it inside the chunk.
            if( memcmp( str + i + bit_pos + 1, needle + 1, needle_len - 2 ) == 0)
                return i + bit_pos;
        
            // If not, we clear given flagged position removing its set state.
             mask = ::Sonic::clear_leftmost_set(mask);
        }
    }

    // If we reach this, it means needle was not found :(
    // Highest possible size_t value.
    return ::Sonic::npos;
#else
    // If we cant find AVX instruction set, fallback to SWAR for now...
    
    // Construct "vectors" containing the first and last characters of our needle.
    const unsigned long long needle_first_char_v = 0x0101010101010101llu * (unsigned char)needle[0];
    const unsigned long long needle_last_char_v  = 0x0101010101010101llu * (unsigned char)needle[ needle_len - 1 ];

    unsigned long long* str_block_first = (unsigned long long*)(str);
    unsigned long long* str_block_last  = (unsigned long long*)(str + needle_len - 1);    

    // Iterate in 8 byte (64 bit) blocks/chunks.
    for(size_t i = 0; i < len; i += 8, str_block_first++, str_block_last++)
    {
    
        const unsigned long long equality = (*str_block_first ^ needle_first_char_v) | ( *str_block_last ^ needle_last_char_v );
    
        const unsigned long long t0 = (~equality & 0x7f7f7f7f7f7f7f7fllu) + 0x0101010101010101llu;
        const unsigned long long t1 = (~equality & 0x8080808080808080llu);
    
        unsigned long long zeros = t0 & t1;
        size_t j = 0;
        
        while( zeros )
        {
            if(zeros & 0x80)
            {
                const char* sub_str = (char*)str_block_first + j + 1;
                if(memcmp( sub_str, needle + 1, needle_len - 2 ) == 0)
                    return i + j;
            }
            
            zeros   >>= 8;
            j       += 1;
        }
    }

    // Highest possible size_t value.
    return ::Sonic::npos;
#endif
}

// Searches for first ocurrence of given char in string.
static SONICSTR_INLINE size_t simd_swar_str_chr( const char* str, size_t len, char c ) SONICSTR_NOEXCEPT
{

    // Build a vector formed with given char.
    // Then iterate blocks.
    // AND both vector and block
    // If can find ocurrances in mask
    // return leftmost ocurrance of character.

    const char* const start_ptr = str;

    // First attemp at finding.
#ifdef  __AVX2__

    // Populate vector with to search character
    const __m256i avx_search_char_v = _mm256_set1_epi8( c );

    while(len > 32)
    {
        // Extract current block and populate vector.
        const __m256i current_block_vector = _mm256_loadu_si256( (const __m256i*)str );
        // compare our character vector with current block.
        const __m256i equality = _mm256_cmpeq_epi8( avx_search_char_v, current_block_vector );
        // generate mask out of comparison result
        const unsigned int mask = _mm256_movemask_epi8( equality );
    
        // if mask if not zero, we have found character == c
        // so we return first bit set.
        if(mask != 0)
        {
            const auto bit_pos = ::Sonic::get_first_bit_set( mask ); 
            return (size_t)bit_pos;
        }
    
        str += 32;
        len -= 32;
    }

#endif//__AVX2__

#ifdef  __SSE2__
    
    const __m128i sse_search_char_v = _mm_set1_epi8( c );

    while(len > 16)
    {
        const __m128i current_block_v = _mm_loadu_epi8( (const void*)str );
        const __m128i equality = _mm_cmpeq_epi( sse_search_char_v, current_block_v );
    
        const unsigned int mask = _mm_movemask_epi8(equality); 
        
        if(mask != 0)
        {
            const auto bit_pos = ::Sonic::get_first_bit_set( mask ); 
            return (size_t)bit_pos;
        }
    
        str += 16;
        len -= 16;
    }

#endif//__SSE2__

    /// SWAR BLOCK.
    const unsigned long long swar_search_char_v = 0x0101010101010101llu * (unsigned char)c;
    
    while(len > 8)
    {    
        const unsigned long long current_block_v = *((const unsigned long long* const)str);
        const unsigned long long mask = swar_search_char_v & current_block_v;
        
        if(mask != 0)
        {
            const auto bit_pos = ::Sonic::get_first_bit_set( mask ); 
            return (size_t)bit_pos;
        }
    
        str += 8;
        len -= 8;
    }

    // Make sure to linearly check remaining bytes...
    while(len > 0)
    {
        if(*str++ == c)
            return (str - start_ptr);
        len--;
    }
 
    // If cant find, return ::Sonic::npos or highest possible size_t val.
    return ::Sonic::npos;
}

// We dont do any sanity checks. We dont check if any
// of the forwarded strings are NULL. We also expect
// both strings to be the same length...
// Careful!!!! DANGEROUS!
static SONICSTR_INLINE SONICSTR_CONSTEXPR bool str_cmp( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT
{
    // Compare first character, if different simply ignore
    // and move on....
    if(*aStr != *bStr)
        return false;
        
    return simd_str_cmp( aStr, bStr, aLen );
}

static SONICSTR_INLINE char* str_chr( const char* str, size_t len, char c ) SONICSTR_NOEXCEPT
{
    const size_t idx = simd_swar_str_chr( str, len, c );
    return ( idx != ::Sonic::npos ) ? (char*)(str + idx) : nullptr; 
}

// Looks for needle of len ´needle_len´ in string of len ´len´.
// If needle is found, will return pointer to provided string
// at begin of found needle, else will return nullptr.
static SONICSTR_INLINE char* str_str( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT
{
    // Call to find needle. using underlying Sonic function.
    size_t idx = ::Sonic::simd_swar_str_contains_needle( str, len, needle, needle_len );

    // If needle is found, return pointer to string at found needle position.
    // If needle is not found, return nullptr.
    return (idx != ::Sonic::npos) ? (char*)(str + idx) : nullptr;
}


static SONICSTR_INLINE SONICSTR_CONSTEXPR char* str_str_s( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT
{
    // Sanity checks for safe str str version.
    if(!str || !needle || ( needle_len > len ) || str == needle)
        return nullptr;

    // Use underlying STR STR func.
    return ::Sonic::str_str( str, len, needle, needle_len );
}

// Safe sanity check version.
static SONICSTR_INLINE SONICSTR_CONSTEXPR bool str_cmp_s( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT
{
    // Sanity checks.
    if(!aStr || !bStr)
        return false;
    
    // I hope the compiler inlines this <3
    return ::Sonic::str_cmp( aStr, bStr, aLen );
}

}

#endif // SONICSTR_H

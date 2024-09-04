// Internal comparison function which tries to use SIMD operations for string comparison.
SONICSTR_INLINE SONICSTR_CONSTEXPR bool simd_str_cmp( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT
{
#ifdef AVX2_SUPPORTED
    // 32 byte blocks.
    while (aLen > 32)
    {
        // Load 32 chars of both _A and _B.
        const __m256i left    = _mm256_loadu_si256((__m256i* const)aStr);
        const __m256i right   = _mm256_loadu_si256((__m256i* const)bStr);
        // COMPARE.
        const __m256i cmp     = _mm256_cmpeq_epi8(left, right);

        // MASKOUT.
        if (_mm256_movemask_epi8(cmp) != 0xffffffff)
            return false;

        aLen -= 32;
        aStr += 32;
        bStr += 32;
    }
#endif//__AVX2__

#ifdef SSE2_SUPPORTED
    while (aLen > 16)
    {
        // Works like AVX but with 128 bits instead of 256.
        const __m128i left    = _mm_loadu_epi8((const void*)aStr);
        const __m128i right   = _mm_loadu_epi8((const void*)bStr);
        // COMPARE
        const __m128i cmp     = _mm_cmpeq_epi8(left, right);

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
        const uint64_t left    = *((const uint64_t* const)aStr);
        const uint64_t right   = *((const uint64_t* const)bStr);

        // COMPARE...
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
        const uint32_t left    = *((const uint32_t* const)aStr);
        const uint32_t right   = *((const uint32_t* const)bStr);

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

// If we have AVX2 Instruction set defined, Sonic str wwill default
// to avx algo. If we cannot find AVX2 instruction set, we will go with
// SWAR method. 
// Returns either index into haystack of needle if found. 
// or
// -1 as size_t or largest possible size_t if not found.

// Based on:
// http://0x80.pl/articles/simd-strfind.html
SONICSTR_INLINE size_t simd_swar_str_contains_needle( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT
{
#ifdef AVX2_SUPPORTED

    // Vectors holding first and last characters of needle
    const __m256i needle_first_char_v = _mm256_set1_epi8( needle[0] );              // At begin -> 0
    const __m256i needle_last_char_v  = _mm256_set1_epi8( needle[needle_len - 1]);  // At end   -> Len - 1
    
    // Iterate in blocks of 32.
    for(size_t i = 0; i < len; i += 32)
    {
        // Extract chunks
        //const __m256i str_block_first = _mm256_loadu_si256( (const __m256i*) str + i  );
        //const __m256i str_block_last  = _mm256_loadu_si256( (const __m256i*) str + i + needle_len - 1);

        const __m256i str_block_first = _mm256_loadu_si256( (const __m256i*)(str + i) );
        const __m256i str_block_last  = _mm256_loadu_si256( (const __m256i*)(str + i + needle_len - 1) );

    
        // Compare extracted chunks with our character vectors
        // holdin the first and last letters of the needle.
        const __m256i equality_first = _mm256_cmpeq_epi8( needle_first_char_v, str_block_first );
        const __m256i equality_last  = _mm256_cmpeq_epi8( needle_last_char_v, str_block_last );

        // With this mask we extract the positions where we match with out needles first/last characters.    
        uint32_t mask = _mm256_movemask_epi8( _mm256_and_si256( equality_first, equality_last ) );
    
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
    const uint64_t needle_first_char_v = 0x0101010101010101llu * (unsigned char)needle[0];
    const uint64_t needle_last_char_v  = 0x0101010101010101llu * (unsigned char)needle[ needle_len - 1 ];

    uint64_t* str_block_first = (uint64_t*)(str);
    uint64_t* str_block_last  = (uint64_t*)(str + needle_len - 1);    

    // Iterate in 8 byte (64 bit) blocks/chunks.
    for(size_t i = 0; i < len; i += 8, str_block_first++, str_block_last++)
    {
    
        const uint64_t equality = (*str_block_first ^ needle_first_char_v) | ( *str_block_last ^ needle_last_char_v );
    
        const uint64_t t0 = (~equality & 0x7f7f7f7f7f7f7f7fllu) + 0x0101010101010101llu;
        const uint64_t t1 = (~equality & 0x8080808080808080llu);
    
        uint64_t zeros = t0 & t1;
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
SONICSTR_INLINE size_t simd_swar_str_chr( const char* str, size_t len, char c ) SONICSTR_NOEXCEPT
{

    // Build a vector formed with given char.
    // Then iterate blocks.
    // AND both vector and block
    // If can find ocurrances in mask
    // return leftmost ocurrance of character.

    const char* const start_ptr = str;

    // First attemp at finding.
#ifdef  AVX2_SUPPORTED

    // Populate vector with to search character
    const __m256i avx_search_char_v = _mm256_set1_epi8( c );

    while(len > 32)
    {
        // Extract current block and populate vector.
        const __m256i current_block_vector = _mm256_loadu_si256( (const __m256i*)str );
        // compare our character vector with current block.
        const __m256i equality = _mm256_cmpeq_epi8( avx_search_char_v, current_block_vector );
        // generate mask out of comparison result
        const uint32_t mask = _mm256_movemask_epi8( equality );
    
        // if mask if not zero, we have found character == c
        // so we return first bit set.
        if(mask != 0)
        {
            //const auto bit_pos = ::Sonic::get_first_bit_set( mask ); 
            //return (size_t)bit_pos;
            return ::Sonic::get_first_bit_set(mask);
        }
    
        str += 32;
        len -= 32;
    }

#endif//__AVX2__

#ifdef  SSE2_SUPPORTED

    const __m128i sse_search_char_v = _mm_set1_epi8( c );

    while(len > 16)
    {
        const __m128i current_block_v = _mm_loadu_epi8( (const void*)str );
        const __m128i equality = _mm_cmpeq_epi( sse_search_char_v, current_block_v );
    
        const uint32_t mask = _mm_movemask_epi8(equality); 
        
        if(mask != 0)
        {
            const auto bit_pos = ::Sonic::get_first_bit_set( mask ); 
            return (size_t)bit_pos;
        }
    
        str += 16;
        len -= 16;
    }

#endif//__SSE2__
/*
    // I think this doesnt work...
    /// @ TODO(BAK): IMPLEMENT SWAR BLOCK.
    const uint64_t swar_search_char_v = 0x0101010101010101llu * (unsigned char)c;
    
    while(len > 8)
    {    
        const uint64_t current_block_v = *((const uint64_t* const)str);
        const uint64_t mask = swar_search_char_v ^ current_block_v;
        
        if(mask != 0)
        {
            const auto bit_pos = ::Sonic::get_first_bit_set( mask ); 
            return (size_t)bit_pos;
        }
    
        str += 8;
        len -= 8;
    
*/
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

SONICSTR_INLINE size_t simd_swar_str_len( const char* str ) SONICSTR_NOEXCEPT
{

    size_t len = 0;

#ifdef AVX2_SUPPORTED

    // Load 32 bytes at once
    // We do not care if mem loading is out of bounds, since
    // we are not writing in memory, we are simply reading and 
    // querying for NULL bytes. So if string is of size 6 + 1(NULL BYTE) lets say
    // we load it:
    
    // 'H' 'E' 'L' 'L' 'O' '!' '0' ... (garbage)
    // VECTOR=( H E L L O ! 0 G x Z 0 g H f Z ...)
    // still easy to find - ^
    // Since we are querying for first appearing 0 byte
    // we simply dont care about all that extra garbage
    // we load.

    const __m256i zero_vec = _mm256_setzero_si256();
    // I dont know how to do this... safety check????
    while(*str != 0)
    {
        const __m256i str_vec  = _mm256_loadu_si256( (const __m256i*)str );        
        const __m256i equality = _mm256_cmpeq_epi8( zero_vec, str_vec );
        const uint32_t mask = _mm256_movemask_epi8( equality );
        if(mask != 0)
            return len + ::Sonic::get_first_bit_set(mask);
        str += 32;
        len += 32;
    }
    return 0;
    // I trust that we have SSE 2 on most modern x86 CPUS.
#elif defined(SSE2_SUPPORTED)

    const __m128i zero_vec = _mm_setzero_si128();
    // I dont know how to do this... safety check????
    while(*str != 0)
    {
        const __m128i str_vec  = _mm_loadu_epi8( (const void*)str );        
        const __m128i equality = _mm_cmpeq_epi8( zero_vec, str_vec );
        const uint32_t mask = _mm_movemask_epi8( equality );
        if(mask != 0)
            return len + ::Sonic::get_first_bit_set(mask);
        str += 16;
        len += 16;
    }
    
    return 0;
#else

    // @ TODO: SWAR impl using zero in word trick:
    // https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord
    const uint64_t zero_vec = 0;

    while(*str != 0)
    {
        const uint64_t str_vec = *((const uint64_t* const)str);
        const uint64_t mask = (((str_vec) - 0x0101010101010101llu) & ~(str_vec) & 0x8080808080808080llu);
        //#define haszero(v) (((v) - 0x01010101UL) & ~(v) & 0x80808080UL)
        
        if(mask != 0)
            return len + (std::countr_zero(mask) / 8);
    
        str += 8;
        len += 8;
    }

    return 0;
#endif//
}

// Hashes DATA STREAM.
// https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
SONICSTR_INLINE uint64_t hash_fnv1a( const char* data, size_t datalen ) SONICSTR_NOEXCEPT
{
    uint64_t hash = 0xcbf29ce484222325; // FNV_offset_basis
    for(size_t i = 0; i < datalen; ++i)
    {
        // XOR hash value with
        // current data byte.
        hash ^= data[i];
        // Multiply by magic prime
        // number.
        hash *= 0x100000001b3; // FNV_prime 
    }
    return hash;
}

// We dont do any sanity checks. We dont check if any
// of the forwarded strings are NULL. We also expect
// both strings to be the same length...
// Careful!!!! DANGEROUS!
SONICSTR_INLINE SONICSTR_CONSTEXPR bool str_cmp( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT
{
    // Compare first character, if different simply ignore
    // and move on....
    if(*aStr != *bStr)
        return false;
        
    return simd_str_cmp( aStr, bStr, aLen );
}

SONICSTR_INLINE size_t str_len( const char* str ) SONICSTR_NOEXCEPT
{
    return simd_swar_str_len( str );
}

// Checks for NULL INPUT...
SONICSTR_INLINE size_t str_len_s( const char* str ) SONICSTR_NOEXCEPT
{
    if(!str || *str == 0)
        return 0;
        
    return simd_swar_str_len( str );
}

SONICSTR_INLINE char* str_chr( const char* str, size_t len, char c ) SONICSTR_NOEXCEPT
{
    const size_t idx = simd_swar_str_chr( str, len, c );
    return ( idx != ::Sonic::npos ) ? (char*)(str + idx) : nullptr; 
}

// Looks for needle of len ´needle_len´ in string of len ´len´.
// If needle is found, will return pointer to provided string
// at begin of found needle, else will return nullptr.
SONICSTR_INLINE char* str_str( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT
{
    // Call to find needle. using underlying Sonic function.
    size_t idx = ::Sonic::simd_swar_str_contains_needle( str, len, needle, needle_len );

    // If needle is found, return pointer to string at found needle position.
    // If needle is not found, return nullptr.
    return (idx != ::Sonic::npos) ? (char*)(str + idx) : nullptr;
}


SONICSTR_INLINE SONICSTR_CONSTEXPR char* str_str_s( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT
{
    // Sanity checks for safe str str version.
    if(!str || !needle || ( needle_len > len ) || str == needle)
        return nullptr;

    // Use underlying STR STR func.
    return ::Sonic::str_str( str, len, needle, needle_len );
}

// Safe sanity check version.
SONICSTR_INLINE SONICSTR_CONSTEXPR bool str_cmp_s( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT
{
    // Sanity checks.
    if(!aStr || !bStr)
        return false;
    
    // I hope the compiler inlines this <3
    return ::Sonic::str_cmp( aStr, bStr, aLen );
}
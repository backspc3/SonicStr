#ifndef SONICSTR_H
#define SONICSTR_H

// Checks for SSE2 and AVX2 ....!!!
#if defined(_MSC_VER) // Check if using MSVC
    #if defined(_M_IX86_FP) && _M_IX86_FP >= 2
        #define SSE2_SUPPORTED
    #endif
#elif defined(__GNUC__) // Check if using GCC
    #if defined(__SSE2__)
        #define SSE2_SUPPORTED
    #endif
#endif

#if defined(_MSC_VER) 
    #if defined(__AVX2__)
        #define AVX2_SUPPORTED
    #endif
#elif defined(__GNUC__)
    #if defined(__AVX2__)
        #define AVX2_SUPPORTED
    #endif
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define SONICSTR_INLINE __attribute__((always_inline))
#elif defined(_MSC_VER) && !defined(__clang__)
    #define SONICSTR_INLINE __forceinline
#else
    #define SONICSTR_INLINE inline
#endif

#include <immintrin.h>
#include <stdint.h> // For sized integer types.
#include <string.h>
#include <bit>

// Enables ops using std::string.
#ifdef SONICSTR_ENABLE_STL_STRING
#include <string>
#endif//SONICSTR_ENABLE_STL_STRING

#define SONICSTR_NOEXCEPT   noexcept
#define SONICSTR_CONSTEXPR  constexpr
#define SONICSTR_ALIGN( A ) alignas(A)

#ifndef SONICSTR_MALLOC
#define SONICSTR_MALLOC malloc
#endif

#ifndef SONICSTR_FREE
#define SONICSTR_FREE free
#endif

namespace Sonic
{

// -1 as size_t.
static constexpr size_t npos = (size_t)-1;

// Internal comparison function which tries to use SIMD operations for string comparison.
static SONICSTR_INLINE SONICSTR_CONSTEXPR bool simd_str_cmp( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT
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
static SONICSTR_INLINE size_t simd_swar_str_chr( const char* str, size_t len, char c ) SONICSTR_NOEXCEPT
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

static SONICSTR_INLINE size_t simd_swar_str_len( const char* str ) SONICSTR_NOEXCEPT
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
static SONICSTR_INLINE uint64_t hash_fnv1a( const char* data, size_t datalen ) SONICSTR_NOEXCEPT
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
static SONICSTR_INLINE SONICSTR_CONSTEXPR bool str_cmp( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT
{
    // Compare first character, if different simply ignore
    // and move on....
    if(*aStr != *bStr)
        return false;
        
    return simd_str_cmp( aStr, bStr, aLen );
}

static SONICSTR_INLINE size_t str_len( const char* str ) SONICSTR_NOEXCEPT
{
    return simd_swar_str_len( str );
}

// Checks for NULL INPUT...
static SONICSTR_INLINE size_t str_len_s( const char* str ) SONICSTR_NOEXCEPT
{
    if(!str || *str == 0)
        return 0;
        
    return simd_swar_str_len( str );
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

// To iterate strings and other thingies.
template<typename type_t>
struct RawPtrIterator
{
    using iterator          = RawPtrIterator<type_t>;
    // Iterator tags... Useful for <algorithm> funcs
    using iterator_category = std::forward_iterator_tag;
    using difference_type   = std::ptrdiff_t;
    using value_type        = type_t;
    using pointer           = value_type*;
    using reference         = value_type&;

    // Construct iterator from given ptr.
    explicit RawPtrIterator( pointer p ) : m_ptr(p) {}

    RawPtrIterator(const iterator& other)
      : m_ptr(other.m_ptr) {}
    
    iterator& operator=(const iterator& other)
    {
        m_ptr = other.m_ptr;
	return *this;
    }

    const reference operator*()  const { return *m_ptr; }
    const pointer   operator->() const { return  m_ptr; }

    iterator& operator++()
    {
        m_ptr++;
	return *this;
    }

    iterator operator++(int) 
    {
      iterator tmp = *this;
      ++(*this);
      return tmp;
    }

    friend bool operator== (const iterator& a, const iterator& b) { return a.m_ptr == b.m_ptr; };
    friend bool operator!= (const iterator& a, const iterator& b) { return a.m_ptr != b.m_ptr; };

private:
    pointer m_ptr;
};


// Forward declare for string ops.
struct StringBase;

// Holds weak view into a Sonic string. This serves an important purpose:
// -  It makes copying Sonic strings more lightweight, allowing for
//    all the required operations we may desire, without carrying the burden
//    of the SSO data that bloats original Sonic strings.
//
// It is important to note that stringviews do not manage any lifetimes meaning:
// - They do not allocate anything when created.
// - They do not deallocate anything when destroyed.
// - They do not in any way prevent the destruction of the original data.
// - They do not prevent other threads of execution from destroying the
//   original/parent string which actually holds/manages the data which the view
//   points into.
// - They dont allow to modify the original string data, only gives us a view into
//   said data.
//
// All this together means we can pass StringViews as values without worrying about copying or anything.
struct StringView
{
    StringView( const StringBase& other )
    {
        construct_pointer_and_len(other);        
    }


    SONICSTR_INLINE StringView( const StringView& other ) SONICSTR_NOEXCEPT
        : m_data( other.m_data), m_len( other.m_len )
    {
    }

    SONICSTR_INLINE StringView& operator=( const StringView& other) SONICSTR_NOEXCEPT
    {
        m_data = other.m_data; 
        m_len  = other.m_len;
        return *this;
    }

    SONICSTR_INLINE StringView( StringView&& other ) SONICSTR_NOEXCEPT
        : m_data( std::move(other.m_data) ), 
          m_len(  std::move(other.m_len) )
    {
        other.m_data = nullptr;
    }


    SONICSTR_INLINE StringView& operator=( StringView&& other) SONICSTR_NOEXCEPT
    {
        m_data = std::move(other.m_data); 
        m_len  = std::move(other.m_len);
        other.m_data = nullptr;
        return *this;
    }

    // You can iterate string views too.
    SONICSTR_INLINE ::Sonic::RawPtrIterator<const char> begin() const noexcept { return ::Sonic::RawPtrIterator(m_data); }
    SONICSTR_INLINE ::Sonic::RawPtrIterator<const char> end()   const noexcept { return ::Sonic::RawPtrIterator(m_data + m_len); }

    SONICSTR_INLINE SONICSTR_CONSTEXPR const char* const c_str() const SONICSTR_NOEXCEPT { return static_cast<const char* const>(m_data); }
    SONICSTR_INLINE SONICSTR_CONSTEXPR size_t len() const SONICSTR_NOEXCEPT { return m_len; }

    template<typename type_t>
    SONICSTR_INLINE bool contains(type_t& substr, size_t pos = 0) const SONICSTR_NOEXCEPT
    {
        auto at = find( substr, pos );
        return at != Sonic::npos;    
    }

    // C string substring search.
    SONICSTR_INLINE size_t find(const char* substr, size_t pos = 0) const SONICSTR_NOEXCEPT
    {
        return ::Sonic::simd_swar_str_contains_needle( m_data + pos, m_len - pos, substr, ::Sonic::str_len(substr) );
    }

    // Other Sonic strings.
    SONICSTR_INLINE size_t find(StringView substr, size_t pos = 0) const SONICSTR_NOEXCEPT
    {
        return ::Sonic::simd_swar_str_contains_needle( m_data + pos, m_len - pos, substr.c_str(), substr.len() );
    }

    // Characters.
    SONICSTR_INLINE size_t find(char c, size_t pos = 0) const SONICSTR_NOEXCEPT
    {
        return ::Sonic::simd_swar_str_chr( m_data + pos, m_len - pos, c );
    }


private:
    SONICSTR_INLINE SONICSTR_CONSTEXPR void construct_pointer_and_len( const StringBase& other ) SONICSTR_NOEXCEPT;

    const char*    m_data;
    unsigned short m_len;
};

// hash using fnv1a SIMD.
static SONICSTR_INLINE uint64_t hash( ::Sonic::StringView str ) SONICSTR_NOEXCEPT
{
    return hash_fnv1a( str.c_str(), str.len() );
}

// String base defines the base interface from which all template specialized Sonic strings
// derive from. The way sonic string works is based on Ocornuts Str: https://github.com/ocornut/str

// We have a base class which manages some string data. Said string data has two possible states:
// - "local" or non heap allocated.
// - Heap allocated.

// When we say "local" we mean that the internal data pointer will point to some statically allocated
// data contained by the string itself, allowing for the creation and destruction of strings with no
// heap in between. This is called SSO or small string optimization.
// In this specific instance, we use a base class which holds a member variable called SSO_SIZE, which is provided
// by the "child" class. This allows for customization of how much data we want to allow strings to hold before doing
// heap allocations.
// We basically trade off the size of the string, for the avoidance of dynamic memory allocations. This is useful in 
// those cases where we may want to avoid heap allocations where possible.
struct StringBase
{

public:

    // This number is used to construct the growth factor of the string on heap grows.
    // In this case we have a amortized growth of 1.5 -> (SELF + SELF / 2).
    // In the case of 2.0 rate -> (SElF + SELF / 1 ).
    static const SONICSTR_CONSTEXPR size_t grow_divisor = 2;

    explicit SONICSTR_INLINE SONICSTR_CONSTEXPR StringBase( unsigned short sz ) SONICSTR_NOEXCEPT
        : m_sso_size(sz), m_data(nullptr), m_len(0)
    {}

    SONICSTR_INLINE StringBase( const StringBase& other ) SONICSTR_NOEXCEPT
        : m_sso_size( other.m_sso_size ) 
    {
        set_str( other );
    }

    SONICSTR_INLINE StringBase& operator=( const StringBase& other) SONICSTR_NOEXCEPT
    {
        set_str( other );
        return *this;
    }

    SONICSTR_INLINE ~StringBase()
    {
        internal_free(m_data);
    }

    // Return iterator constructed at BEGIN of string.
    SONICSTR_INLINE ::Sonic::RawPtrIterator<char> begin() const SONICSTR_NOEXCEPT { return RawPtrIterator( m_data ); }
    SONICSTR_INLINE ::Sonic::RawPtrIterator<char> end()   const SONICSTR_NOEXCEPT { return RawPtrIterator( m_data + m_len ); }

    // Clears memory, without freeing anything.
    SONICSTR_INLINE void clear() SONICSTR_NOEXCEPT
    {
        memset( m_data, 0, m_cap );
        m_len = 0;
    }

    SONICSTR_INLINE char pop_back() SONICSTR_NOEXCEPT
    {
        char c = m_data[m_len];
	 m_data[--m_len] = 0;
        return c;
    }

    SONICSTR_INLINE void push_back(char c) SONICSTR_NOEXCEPT
    {
        append(c);
    }

    // Set str version which utilizes C strings.
    SONICSTR_INLINE void set_str( const char* str ) SONICSTR_NOEXCEPT
    {
        const size_t strlen = static_cast<unsigned short>( ::Sonic::str_len( str ) );
        do_set( str, strlen );
    }
    
    
    // Set str version which utilizes C strings.
    SONICSTR_INLINE void set_str( const char* str, size_t strlen ) SONICSTR_NOEXCEPT
    {
        do_set( str, strlen );
    }

    // Set str version which utilizes C strings.
    SONICSTR_INLINE void set_str( const ::Sonic::StringBase& str ) SONICSTR_NOEXCEPT
    {
        do_set( str.c_str(), str.len() );
    }
    
    
    // Set str version which utilizes C strings.
    SONICSTR_INLINE void set_str( ::Sonic::StringView str ) SONICSTR_NOEXCEPT
    {
        do_set( str.c_str(), str.len() );
    }

    SONICSTR_INLINE void do_set( const char* str, size_t strlen ) SONICSTR_NOEXCEPT
    {
        // safe internal free.
        internal_free( m_data );
        
        // Compute string length.
        m_len = (unsigned short)strlen; // Just cast...
        m_data = internal_alloc( m_len + 1 ); // No matter what, string will now have enough data, for string.
        
        // Copy data over.
        memcpy( m_data, str, m_len + 1 );    
    }
    
    // Append c string.
    SONICSTR_INLINE void append( const char* str ) SONICSTR_NOEXCEPT
    {
        const unsigned short strlen = static_cast<unsigned short>( Sonic::str_len(str) );
        do_append( str, strlen );
    }
    
    SONICSTR_INLINE void append( ::Sonic::StringBase& str ) SONICSTR_NOEXCEPT
    {
        do_append( str.c_str(), (unsigned short)str.len() );
    }
    
    SONICSTR_INLINE void append( ::Sonic::StringView str ) SONICSTR_NOEXCEPT
    {
        do_append( str.c_str(), (unsigned short)str.len() );
    }

    // Quick hack to support character appending.
    SONICSTR_INLINE void append( char c ) SONICSTR_NOEXCEPT
    {
        //char copy = c;
        do_append( static_cast<const char*>(&c), 1 );
    }

    SONICSTR_INLINE void do_append( const char* strptr, unsigned short strlen ) SONICSTR_NOEXCEPT
    {
        const unsigned short newlen = m_len + strlen;

        // If appending to local buf string.
        if(is_data_local())
        {
            char* old_ptr = m_data;        

            // Check if new string now requires heap memory.
            if(newlen > m_sso_size)
            {
                // If so, reallocate with heap mem.
                m_data = static_cast<char*>(SONICSTR_MALLOC( newlen + 1 ));
                memcpy( m_data, old_ptr, m_len );
                m_cap = newlen + 1;
            }
            
            memcpy( m_data + m_len, strptr, strlen );
            m_len = newlen;
            m_data[newlen] = 0;
        } 
        else // If buffer is already heap allocated. 
        {
            // If appending new string makes us go above capacity.
            // grow buffer amortized until it fits.
            while(newlen > m_cap) grow_amortized();
            
            memcpy( m_data + m_len, strptr, strlen );
            m_data[ newlen ] = 0;
            m_len = newlen;
        }    
    }
    
    SONICSTR_INLINE SONICSTR_CONSTEXPR bool compare(const StringBase& other) SONICSTR_NOEXCEPT
    {
        return ::Sonic::str_cmp( m_data, other.m_data, m_len );
    }

#ifdef SONICSTR_ENABLE_STL_STRING

    SONICSTR_INLINE SONICSTR_CONSTEXPR bool compare(const std::string& other) SONICSTR_NOEXCEPT
    {
        return ::Sonic::str_cmp( m_data, other.c_str(), m_len );
    }

#endif//

    // ALL FIND OVERLOADS.
    
    // C string substring search.
    SONICSTR_INLINE size_t find(const char* substr, size_t pos = 0) const SONICSTR_NOEXCEPT
    {
        return ::Sonic::simd_swar_str_contains_needle( m_data + pos, m_len - pos, substr, ::Sonic::str_len(substr) );
    }

    // Other Sonic strings.
    SONICSTR_INLINE size_t find(StringView substr, size_t pos = 0) const SONICSTR_NOEXCEPT
    {
        return ::Sonic::simd_swar_str_contains_needle( m_data + pos, m_len - pos, substr.c_str(), substr.len() );
    }

    // Characters.
    SONICSTR_INLINE size_t find(char c, size_t pos = 0) const SONICSTR_NOEXCEPT
    {
        return ::Sonic::simd_swar_str_chr( m_data + pos, m_len - pos, c );
    }
    
    // All contains overloads.

    // Templated but only works with types which have find implemented.
    template<typename type_t>
    SONICSTR_INLINE bool contains(type_t& substr, size_t pos = 0) const SONICSTR_NOEXCEPT
    {
        auto at = find( substr, pos );
        return at != Sonic::npos;    
    }
    
    SONICSTR_INLINE SONICSTR_CONSTEXPR size_t len() const SONICSTR_NOEXCEPT { return m_len; }
    SONICSTR_INLINE SONICSTR_CONSTEXPR size_t len()       SONICSTR_NOEXCEPT { return m_len; }

    //SONICSTR_INLINE SONICSTR_CONSTEXPR char*       c_str()       SONICSTR_NOEXCEPT { return m_data; }
    SONICSTR_INLINE SONICSTR_CONSTEXPR const char* c_str() const SONICSTR_NOEXCEPT { return m_data; }

    SONICSTR_INLINE SONICSTR_CONSTEXPR size_t cap()       SONICSTR_NOEXCEPT { return m_cap; }
    SONICSTR_INLINE SONICSTR_CONSTEXPR size_t cap() const SONICSTR_NOEXCEPT { return m_cap; }

    SONICSTR_INLINE SONICSTR_CONSTEXPR       char& operator[](size_t index)       SONICSTR_NOEXCEPT { return m_data[index]; }
    SONICSTR_INLINE SONICSTR_CONSTEXPR const char& operator[](size_t index) const SONICSTR_NOEXCEPT { return m_data[index]; }    
    
    SONICSTR_INLINE bool is_sso()       SONICSTR_NOEXCEPT { return is_data_local(); }

protected:

    SONICSTR_INLINE bool is_data_local() SONICSTR_NOEXCEPT
    {
        return m_data == (reinterpret_cast<char*>(this) + sizeof(StringBase));
    }

    SONICSTR_INLINE void grow_amortized() SONICSTR_NOEXCEPT
    {
        const unsigned short newsize = (unsigned short)(m_cap + (m_cap / grow_divisor));
        char* old_ptr = m_data;
        m_data = static_cast<char*>(SONICSTR_MALLOC( newsize + 1 ));
        memcpy( m_data, old_ptr, m_len );
        m_data[newsize] = 0;
        m_cap = newsize; // Just cast.... WILL CAP?
	internal_free(old_ptr); // MUST FREE old MEM.
    }

    // Allocates string storage, either returning pointer to SSO data
    // or heap allocated buffer.
    SONICSTR_INLINE char* internal_alloc( unsigned short size ) SONICSTR_NOEXCEPT
    {
        // If the requested data fits inside of SSO size
        if( size <= m_sso_size )
        {
            m_cap = m_sso_size;
            return reinterpret_cast<char*>(this) + sizeof(StringBase);
        }
    
        m_cap = size;
        return static_cast<char*>(SONICSTR_MALLOC( size ));
    }
    
    SONICSTR_INLINE void internal_free( char* data ) SONICSTR_NOEXCEPT
    {
        if(data && !is_data_local())
            SONICSTR_FREE( data );
    }

    // Align to cache-boundary for SIMD loads
    char* m_data;
    unsigned short m_len;
    unsigned short m_cap;
    unsigned short m_sso_size;
};

SONICSTR_INLINE SONICSTR_CONSTEXPR void StringView::construct_pointer_and_len( const StringBase& other ) SONICSTR_NOEXCEPT
{
    m_data = other.c_str();
    m_len = (unsigned short)other.len();
}

// Helper..
#define SonicStringConstructor( __Type ) \
    String( __Type str ) : StringBase(sz_t) \
    { \
        set_str(str); \
    }

template<unsigned short sz_t>
struct String : public StringBase
{
    static_assert( sz_t % 2 == 0 );
    
    // Empty constructor.
    String() : StringBase(sz_t)
    {}

    // All constructors must call StringBase with provided 
    // sso size.
    SonicStringConstructor(const char*)
    SonicStringConstructor(const ::Sonic::StringBase&)
    SonicStringConstructor(::Sonic::StringView)

#ifdef SONICSTR_ENABLE_STL_STRING

    String( const std::string& str ) : StringBase(sz_t)
    {
        set_str( str.c_str() );
    }

    String& operator=(const std::string& other ) SONICSTR_NOEXCEPT
    {
        set_str( other.c_str() );
        return *this;
    }

#endif//

    // Chops self by given delimiter:
    // test_str = "This is a test!".
    //
    // Chop by delimiter first i ocurrance with offset 0.
    // test_str.chop(i, 0);
    //
    // String now becomes:
    // test_str == "Th";
    template<typename type_t>
    SONICSTR_INLINE bool chop(type_t c, size_t pos = 0) SONICSTR_NOEXCEPT
    {
        size_t at = find(c, pos);

	// Found at some pos.
	if(at != ::Sonic::npos)
	{
	    // Is this illegal? I dont know...
	    m_len = (unsigned short)(at - 1);
	    // I guess this is safe since strings are always 
	    // one byte longer for NULL termination.
	    m_data[m_len] = 0;
	    return true;
	}

	// Did not find C
	return false;
    }

    // Trims string by given delimiter, equal to calling find and constructing at
    // found position.
    SONICSTR_INLINE bool trim(char c, String& out, size_t pos = 0) const SONICSTR_NOEXCEPT
    {
       // Try to find ocurrance of char.
       size_t at = find( c, pos );

       // If found something.
       if(at != ::Sonic::npos)
       {
	  char* tmp = m_data + at;
	  // Since it is extracted from original
	  // String, can assume NULL termination.
	  out = String(tmp);
	  return true;
       }

       return false;
    }

private:
    // Align to cache boundary.
    char __buf[sz_t];

};

using String8    = ::Sonic::String<8>;
using String16   = ::Sonic::String<16>;
using String32   = ::Sonic::String<32>;
using String64   = ::Sonic::String<64>;
using String128  = ::Sonic::String<128>;
using String256  = ::Sonic::String<256>;
using String512  = ::Sonic::String<512>;
using String1024 = ::Sonic::String<1024>;

}

#endif // SONICSTR_H

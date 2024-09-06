#ifndef SONICSTR_H
#define SONICSTR_H

// Check if SIMD is requested.
#if defined(SONICSTR_SIMD)
// Checks for SSE2 and AVX2 ....!!!
#if defined(_MSC_VER)
    #if defined(_M_IX86_FP) && _M_IX86_FP >= 2
        #define SSE2_SUPPORTED
    #endif
#elif defined(__GNUC__)
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
#endif//SONICSTR_SIMD

#if defined(__GNUC__) || defined(__clang__)
    #define SONICSTR_INLINE __attribute__((always_inline))
#elif defined(_MSC_VER) && !defined(__clang__)
    #define SONICSTR_INLINE __forceinline
#else
    #define SONICSTR_INLINE inline
#endif

#include <immintrin.h>  // Intrinsics SIMD stuff.
#include <stdint.h>     // For sized integer types.
#include <string.h>     // For C runtime str methods.
#include <iterator>     // For string iterator.
#include <bit>          // For std::countr_zero and std::countl_zero.

// Enables ops using std::string.
#ifdef SONICSTR_ENABLE_STL_STRING
#include <string>       // std::string.
#endif//SONICSTR_ENABLE_STL_STRING

#define SONICSTR_NOEXCEPT   noexcept
#define SONICSTR_CONSTEXPR  constexpr
#define SONICSTR_ALIGN( A ) alignas(A)

namespace Sonic
{

// -1 as size_t.
static constexpr size_t npos = static_cast<size_t>(-1);

template <typename T>
SONICSTR_INLINE SONICSTR_CONSTEXPR T clear_leftmost_set(const T value) SONICSTR_NOEXCEPT
{
    return value & (value - 1);
}


template <typename T>
SONICSTR_INLINE SONICSTR_CONSTEXPR unsigned get_first_bit_set(const T value) SONICSTR_NOEXCEPT
{
    return std::countr_zero(value);
}

SONICSTR_INLINE SONICSTR_CONSTEXPR bool simd_str_cmp( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT;
SONICSTR_INLINE size_t simd_swar_str_contains_needle( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT;
SONICSTR_INLINE size_t simd_swar_str_chr( const char* str, size_t len, char c ) SONICSTR_NOEXCEPT;
SONICSTR_INLINE size_t simd_swar_str_len( const char* str ) SONICSTR_NOEXCEPT;
SONICSTR_INLINE uint64_t hash_fnv1a( const char* data, size_t datalen ) SONICSTR_NOEXCEPT;
// We dont do any sanity checks. We dont check if any
// of the forwarded strings are NULL. We also expect
// both strings to be the same length...
// Careful!!!! DANGEROUS!
SONICSTR_INLINE SONICSTR_CONSTEXPR bool str_cmp( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT;
SONICSTR_INLINE size_t str_len( const char* str ) SONICSTR_NOEXCEPT;
// Checks for NULL INPUT...
SONICSTR_INLINE size_t str_len_s( const char* str ) SONICSTR_NOEXCEPT;
SONICSTR_INLINE char* str_chr( const char* str, size_t len, char c ) SONICSTR_NOEXCEPT;
// Looks for needle of len ´needle_len´ in string of len ´len´.
// If needle is found, will return pointer to provided string
// at begin of found needle, else will return nullptr.
SONICSTR_INLINE char* str_str( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT;
SONICSTR_INLINE SONICSTR_CONSTEXPR char* str_str_s( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT;
// Safe sanity check version.
SONICSTR_INLINE SONICSTR_CONSTEXPR bool str_cmp_s( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT;
SONICSTR_INLINE size_t str_len( const char* str ) SONICSTR_NOEXCEPT;
// Checks for NULL INPUT...
SONICSTR_INLINE size_t str_len_s( const char* str ) SONICSTR_NOEXCEPT;
SONICSTR_INLINE char* str_chr( const char* str, size_t len, char c ) SONICSTR_NOEXCEPT;
// Looks for needle of len ´needle_len´ in string of len ´len´.
// If needle is found, will return pointer to provided string
// at begin of found needle, else will return nullptr.
SONICSTR_INLINE char* str_str( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT;
SONICSTR_INLINE SONICSTR_CONSTEXPR char* str_str_s( const char* str, size_t len, const char* needle, size_t needle_len ) SONICSTR_NOEXCEPT;
// Safe sanity check version.
SONICSTR_INLINE SONICSTR_CONSTEXPR bool str_cmp_s( const char* aStr, const char* bStr, size_t aLen ) SONICSTR_NOEXCEPT;

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

    friend bool operator== (const iterator& a, const iterator& b) { return a.m_ptr == b.m_ptr; };
    friend bool operator!= (const iterator& a, const iterator& b) { return a.m_ptr != b.m_ptr; };

private:
    pointer m_ptr;
};

// Default allocator uses malloc and free.
struct StringDefaultAllocator
{

    inline void* allocate(size_t size) noexcept
    {
        return malloc(size);
    }
    
    inline void deallocate(void* ptr) noexcept
    {
        free(ptr);
    }

};

// Forward declare for string ops.
template<typename allocator_t>
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
// - They dont allow to modify the original string data, only gives us a view into
//   said data.
//
// All this together means we can pass StringViews as values without worrying about copying.
struct StringView
{

    // To allow strings with any allocator.
    template<typename allocator_t>
    StringView( const StringBase<allocator_t>& other )
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

    template<typename allocator_t>
    SONICSTR_INLINE SONICSTR_CONSTEXPR void construct_pointer_and_len( const StringBase<allocator_t>& other ) SONICSTR_NOEXCEPT;

    const char*    m_data;
    unsigned short m_len;
};

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
template<typename allocator_t = StringDefaultAllocator>
struct StringBase
{

public:

    using StringType = StringBase<allocator_t>;

    // This number is used to construct the growth factor of the string on heap grows.
    // In this case we have a amortized growth of 1.5 -> (SELF + SELF / 2).
    // In the case of 2.0 rate -> (SElF + SELF / 1 ).
    static const SONICSTR_CONSTEXPR size_t grow_divisor = 2;

    explicit SONICSTR_INLINE SONICSTR_CONSTEXPR StringBase( unsigned short sz ) SONICSTR_NOEXCEPT
        : m_sso_size(sz), m_data(nullptr), m_len(0)
    {}

    explicit SONICSTR_INLINE SONICSTR_CONSTEXPR StringBase( unsigned short sz, allocator_t alloc ) SONICSTR_NOEXCEPT
        : m_sso_size(sz), m_data(nullptr), m_len(0), m_allocator( std::move(alloc) ) // Mov???
    {}

    SONICSTR_INLINE StringBase( const StringType& other ) SONICSTR_NOEXCEPT
        : m_sso_size( other.m_sso_size ) 
    {
        set_str( other );
    }

    SONICSTR_INLINE StringType& operator=( const StringType& other) SONICSTR_NOEXCEPT
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
    SONICSTR_INLINE void set_str( const StringType& str ) SONICSTR_NOEXCEPT
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
    
    SONICSTR_INLINE void append( StringType& str ) SONICSTR_NOEXCEPT
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
                m_data = static_cast<char*>(m_allocator.allocate( newlen + 1 ));
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
    
    SONICSTR_INLINE SONICSTR_CONSTEXPR bool compare(const StringType& other) SONICSTR_NOEXCEPT
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
        m_data = static_cast<char*>(m_allocator.allocate( newsize + 1 ));
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
        return static_cast<char*>(m_allocator.allocate( size ));
    }
    
    SONICSTR_INLINE void internal_free( char* data ) SONICSTR_NOEXCEPT
    {
        if(data && !is_data_local())
            m_allocator.deallocate( data );
    }

    // Align to cache-boundary for SIMD loads
    char* m_data;
    unsigned short m_len;
    unsigned short m_cap;
    unsigned short m_sso_size;
    allocator_t m_allocator;
};

template<typename allocator_t>
SONICSTR_INLINE SONICSTR_CONSTEXPR void StringView::construct_pointer_and_len( const StringBase<allocator_t>& other ) SONICSTR_NOEXCEPT
{
    m_data = other.c_str();
    m_len = (unsigned short)other.len();
}

// Helper..
#define SonicStringConstructor( __Type ) \
    String( __Type str ) : BaseType(sz_t) \
    { \
        set_str(str); \
    }

template<unsigned short sz_t, typename allocator_t = StringDefaultAllocator>
struct String : public StringBase<allocator_t>
{
    using BaseType = StringBase<allocator_t>;

    static_assert( sz_t % 2 == 0 );
    
    // Empty constructor.
    String() : BaseType(sz_t)
    {}

    // Bring required BaseType stuff
    // to scope.
    using BaseType::set_str;
    using BaseType::m_len;
    using BaseType::m_data;
    using BaseType::find;

    SonicStringConstructor(const char*)
    SonicStringConstructor(const BaseType&)
    SonicStringConstructor(::Sonic::StringView)

    template<typename type_t>
    String( type_t str, allocator_t alloc ) : BaseType(sz_t, alloc)
    {
        set_str(str);
    }

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

// General use functions.

// hash using fnv1a SIMD.
SONICSTR_INLINE uint64_t hash( ::Sonic::StringView str ) SONICSTR_NOEXCEPT
{
    return ::Sonic::hash_fnv1a( str.c_str(), str.len() );
}

// To make main file prettier.
#include "SonicSimd.inl"

}

#endif // SONICSTR_H

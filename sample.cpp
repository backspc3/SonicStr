#define SONICSTR_ENABLE_STL_STRING
#define SONICSTR_SIMD // To enable simd???
#include "SonicStr.h"
#include "second.h"
#include <stdio.h>

inline void print_bool( bool state )
{
    printf("%s\n", state ? "true" : "false" );
} 

struct my_allocator
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

// Dummy local arena like allocator.
struct second_allocator
{

    inline void* allocate(size_t size) noexcept
    {
        return malloc(size);
    }
    
    inline void deallocate(void* ptr) noexcept
    {
        free(ptr);
    }

    char* m_start;
    char* m_cursor;
    size_t m_size;
};

struct lock_free_arena
{
    // IMplement...
};

static lock_free_arena g_Arena;

// Can simulate state-full but global like this.
struct global_string_arena
{
    // Allocate:
    // g_Arena.allocate();
    
    // Deallocate:
    // .... Nothing.
}; 

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    const char* a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char* b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    size_t alen = strlen( a );

    const char *needle = " for";
    const char *haystack = "This is a test haystack, it is longer than the needle for obv reasons!";
    
    size_t needle_len = strlen( needle );
    size_t haystack_len = strlen( haystack );

    volatile bool res = Sonic::str_cmp( a, b, alen );  
    print_bool( res );
    
    char* str_at = Sonic::str_str(haystack, haystack_len, needle, needle_len );
    char* chr_at = Sonic::str_chr(haystack, haystack_len, 'Z');
    
    print_bool(str_at);
    print_bool(chr_at);

    if(str_at)
        printf("%s\n", str_at);
        
    if(chr_at)
        printf("%c\n", *chr_at);

    const size_t nelen = Sonic::str_len( haystack );
    
    printf("SIMD: %zu, NON SIMD: %zu\n", nelen, haystack_len);
    
    Sonic::String16 sampleA("IamTheBestA");
    Sonic::String16 sampleB("IamTheBestB");
    print_bool( sampleA.compare(sampleB) );
    
    printf("SIZES: (8 - %zu)  (16 - %zu)   (32 - %zu)\n       (64 - %zu) (128 - %zu) (256 - %zu)\n", 
        sizeof(Sonic::String8), sizeof(Sonic::String16), sizeof(Sonic::String32),
        sizeof(Sonic::String64), sizeof(Sonic::String128), sizeof(Sonic::String256));

    print_bool( sampleA.contains(sampleB) );

    const char* toAP = "WeAreTheBest";
    printf("append: %zu\n", strlen(toAP));
    printf("%s | L: %zu C: %zu\n", sampleA.c_str(), sampleA.len(), sampleA.cap());        
    sampleA.append(toAP);
    printf("%s | L: %zu C: %zu\n", sampleA.c_str(), sampleA.len(), sampleA.cap());        
    sampleA.append(toAP);
    printf("%s | L: %zu C: %zu\n", sampleA.c_str(), sampleA.len(), sampleA.cap());        

    Sonic::String32 test(sampleB);

    Sonic::String32 some_str( toAP );
    Sonic::String32 out_data; // Default constructed.

    // Should not fail.
    some_str.trim( 'A', out_data );
    printf("Trimmed: %s\n", out_data.c_str());
    out_data.clear();
    out_data.set_str("I am a test string!");
    printf("Cleared and set: %s %zu\n", out_data.c_str(), out_data.len());
    out_data.set_str("STRR!");
    printf("Override set: %s %zu\n", out_data.c_str(), out_data.len());
    out_data.chop('S');
    printf("Chopped: %s %zu\n", out_data.c_str(), out_data.len());
    out_data.push_back('Z');
    out_data.push_back('z');
    out_data.push_back('Z');
    printf("Appended: %s %zu\n", out_data.c_str(), out_data.len());
    char one = out_data.pop_back();
    char two = out_data.pop_back();
    printf("Popped: %s len: %zu :::", out_data.c_str(), out_data.len());
    // Why does this not print anything?????
    printf("%c %c\n", one, two);
    printf("Before: %s\n", sampleB.c_str());
    sampleB = sampleA;
    printf("After: %s\n", sampleB.c_str());
    printf("%s\n", test.c_str());
        
    Sonic::String32 sonicstr;
    std::string stlstr("This is a test!");
    sonicstr = stlstr;
    printf("Copied STL string: %s\n", sonicstr.c_str());
    print_bool(sonicstr.compare(stlstr));

    printf("Iterated string: \n\t");
    for(auto& c : sonicstr)
    {
        printf("%c", c);
    }
    printf("\n");

    // Hash strings and string views.
    unsigned long long hash = ::Sonic::hash( sonicstr );
    printf("Hashed: %llu\n", hash);
    second::test t = second::do_test("this is a test!");

    // Can construct string using custom allocator.
    // Can also forward allocator instance in constructor.
    // Strings construct instances of their allocator types.
    // So allocators can hold local state or "global" state.
    // As such, they can make sizeof(String) grow.
    my_allocator instance;
    Sonic::String<32, my_allocator> some("custom allocator");
    Sonic::String<32, my_allocator> some_other("this is test", instance);
    Sonic::String<16> other("I am thebest");

    Sonic::String<32, second_allocator> second_alloc("second allocator");

    printf("Default alloc: %zu, \nCustom state-full dummy allocator: %zu\n", 
        sizeof(Sonic::String<32>), sizeof(Sonic::String<32, second_allocator> ));

    // String views can hold views into strings of different sizes
    // and allocator types.
    Sonic::StringView SomeView = some;
    SomeView = some_other;
    SomeView = other; 
    
    return 0;
}

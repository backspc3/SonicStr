#include "SonicStr.h"
#include <stdio.h>

inline void print_bool( bool state )
{
    printf("%s\n", state ? "true" : "false" );
} 

int main(int argc, char** argv)
{

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
    
    return 0;
}
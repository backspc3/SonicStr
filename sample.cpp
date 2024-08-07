#include "SonicStr.h"
#include <stdio.h>

inline void print_bool( bool state )
{
    printf("%s\n", state ? "true" : "false" );
} 

int main(int argc, char** argv)
{

    const char* a = "aaaaa";
    const char* b = "bbbbb";

    size_t alen = strlen( a );

    const char *needle = " for";
    const char *haystack = "This is a test haystack, it is longer than the needle for obv reasons!";
    
    size_t needle_len = strlen( needle );
    size_t haystack_len = strlen( haystack );

    volatile bool res = Sonic::str_cmp( a, b, alen );  
    print_bool( res );
    
    print_bool(Sonic::str_str(haystack, haystack_len, needle, needle_len ));
    print_bool(Sonic::str_chr(haystack, haystack_len, 'Z'));

    size_t nelen = Sonic::simd_swar_str_len( haystack );
    
    printf("SIMD: %zu, NON SIMD: %zu\n", nelen, haystack_len);
    
    return 0;
}
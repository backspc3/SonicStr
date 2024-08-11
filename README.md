# SonicStr
SIMD accelerated string operations for C++. Fast like Sonic :3

## Thingies

This small header only library defines a set of string.h adjacent methods
that are accelerated using SIMD and SWAR techniques.

It also defines a type Sonic::String<size>. 
This type is a string type, designed
to be highly customizable in its SSO optimizations. 

### Command to compile with AVX enabled / C++20 and O2 optimizations.
> cl /O2 /std:c++20 /arch:AVX2 .\sample.cpp
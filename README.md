# Work in progress ATTEMPT at fast string implementation

## SonicStr
C++ 20 string, fast like Sonic :3

### Thingies

This small header only library defines a set of string.h adjacent methods
that are implemented using SIMD and SWAR techniques.

It also defines a type Sonic::String<size>. 
This type is a string type, designed
to be highly customizable in its SSO optimizations. 

#### (FOR ME): Command to compile with AVX enabled / C++20 and O2 optimizations.
> cl /nologo /O2 /W4 /std:c++20 /arch:AVX2 .\sample.cpp .\second.cpp
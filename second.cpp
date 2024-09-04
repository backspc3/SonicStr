#include "second.h"

namespace second
{

test do_test(const char* name)
{
    test ret;
    ret.m_name = Sonic::String<32>(name);
    return ret;
}

}
#pragma once

#include "SonicStr.h"

namespace second
{

struct test
{
    Sonic::String<32> m_name;
};

test do_test(const char* name);

}
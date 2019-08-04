#pragma once

#include <ssc/crypto/operations.hh>
#include <cstdint>
#include <cstring>

#define MS_API
#ifdef _WIN64
    #if defined( SSC_EXPORTS )
        #define MS_API __declspec(dllexport)
    #else
        #define MS_API __declspec(dllimport)
    #endif
#endif

namespace ssc
{
    class MS_API Terminal
    {
    public:
        /* CONSTRUCTORS */
        Terminal();
        ~Terminal();
        void get_pw(char       * pw_buffer,
                    int const    max_pw_size,
                    int const    min_pw_size);
        void notify(char const * notice);
    private:
#if   defined(__gnu_linux__)
        int std_height;
        int std_width;
#elif !defined(_WIN64)
    #error "ssc::Terminal only defined for Gnu/Linux and MS Windows"
#endif
    };/* ! class ssc::Terminal */
}/* ! namespace ssc */

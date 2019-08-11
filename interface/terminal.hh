#pragma once

#include <cstdint>
#include <cstring>
#include <ssc/crypto/operations.hh>
#include <ssc/general/symbols.hh>

namespace ssc
{
    class DLL_PUBLIC Terminal
    {
    public:
        /* CONSTRUCTORS */
        Terminal();
        ~Terminal();
        // Returns password size
        int get_pw(char    * pw_buffer,
                   int const max_pw_size,
                   int const min_pw_size);
        void notify(char const * notice);
    private:
#if defined( __gnu_linux__ )
        DLL_LOCAL int std_height;
        DLL_LOCAL int std_width;
#elif !defined( _WIN64 )
    #error "ssc::Terminal only defined for Gnu/Linux and MS Windows"
#endif
    };/* ! class ssc::Terminal */
}/* ! namespace ssc */

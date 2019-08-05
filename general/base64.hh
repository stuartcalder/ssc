#pragma once
#include <cstdint>
#include <cstring>

#define DLL_API
#if defined( _WIN32 )
    #if defined( BUILD_DLL )
        #define DLL_API __declspec(dllexport)
    #else
        #define DLL_API __declspec(dllimport)
    #endif
#endif

/*
 
   [76543210][76543210][76543210]   3 octets
   [543210][543210][543210][543210] 4 hextets
    54321054  32105432  10543210
    |         |         |
    |         |         3rd octet
    |         2nd octet
    first octet

*/
namespace ssc
{
    DLL_API constexpr size_t calculate_b64_r648_size(size_t size_in);
    DLL_API void b64_r648_encode(const uint8_t * const in, char * const out, const size_t size_in);
    DLL_API void b64_r648_decode(const char * const in, uint8_t * const out, const size_t size_in);
}

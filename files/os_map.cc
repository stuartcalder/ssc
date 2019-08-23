#include <ssc/general/integers.hh>
#include <ssc/files/os_map.hh>

extern "C" {
#if defined( __gnu_linux__ )
#   include <sys/mman.h>
#elif defined( _WIN64 )
#   include <windows.h>
#   include <memoryapi.h>
#else
#   error "Only defined for Gnu/Linux and Win64"
#endif
}/* ! extern "C" */

namespace ssc
{
    void map_file (OS_Map & os_map, bool const readonly)
    {
#if   defined( __gnu_linux__ )
        decltype(PROT_READ) const readwrite_flag = ( readonly ? PROT_READ : (PROT_READ | PROT_WRITE) );
        os_map.ptr = static_cast<u8_t *>(mmap( 0, os_map.size, readwrite_flag, MAP_SHARED, os_map.os_file, 0 ));
        if ( os_map.ptr == MAP_FAILED )
        {
            fputs( "Error: Failed to open map\n", stderr );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        decltype(PAGE_READONLY) page_readwrite_flag;
        decltype(FILE_MAP_READ) map_readwrite_flag;
        if ( readonly )
        {
            page_readwrite_flag = PAGE_READONLY;
            map_readwrite_flag = FILE_MAP_READ;
        }
        else
        {
            page_readwrite_flag = PAGE_READWRITE;
            map_readwrite_flag = (FILE_MAP_READ | FILE_MAP_WRITE);
        }

        DWORD high_bits = static_cast<DWORD>(os_map.size >> 32);
        DWORD low_bits  = static_cast<DWORD>(os_map.size);
        os_map.win64_filemapping = CreateFileMappingA( os_map.os_file, NULL, page_readwrite_flag, high_bits, low_bits, NULL );

        if ( os_map.win64_filemapping == NULL )
        {
            fputs( "Error: Unalbe to memory-map file\n", stderr );
            exit( EXIT_FAILURE );
        }
        os_map.ptr = static_cast<u8_t *>(MapViewOfFile( os_map.win64_filemapping, map_readwrite_flag, 0, 0, os_map.size ));
        if ( os_map.ptr == NULL )
        {
            fputs( "Error: Failed to MapViewOfFile()\n", stderr );
            exit( EXIT_FAILURE );
        }
#else
    #error "map_file only defined for Gnu/Linux and Win64"
#endif
    }/* ! map_file */


    void unmap_file (OS_Map const & os_map)
    {
        using namespace std;
#if   defined( __gnu_linux__ )
        if ( munmap( os_map.ptr, os_map.size ) == -1 )
        {
            fputs( "Error: Failed to unmap file\n", stderr );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        if ( UnmapViewOfFile( static_cast<LPCVOID>(os_map.ptr) ) == 0 )
        {
            fputs( "Error: Failed to unmap file\n", stderr );
            exit( EXIT_FAILURE );
        }
        close_os_file( os_map.win64_filemapping );
#else
    #error "unmap_file only defined for Gnu/Linux and Win64"
#endif
    }/* ! unmap_file */


    void sync_map (OS_Map const & os_map)
    {
        using namespace std;
#if   defined( __gnu_linux__ )
        if ( msync( os_map.ptr, os_map.size, MS_SYNC ) == -1 )
        {
            fputs( "Error: Failed to sync mmap()\n", stderr );
            exit( EXIT_FAILURE );
        }
#elif defined( _WIN64 )
        if ( FlushViewOfFile( static_cast<LPCVOID>(os_map.ptr), os_map.size ) == 0 )
        {
            fputs( "Error: Failed to FlushViewOfFile()\n", stderr );
            exit( EXIT_FAILURE );
        }
#else
    #error "sync_map only defined for Gnu/Linux and Win64"
#endif
    }/* ! sync_map */


}/* ! namespace ssc */

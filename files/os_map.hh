#pragma once
#include <ssc/files/files.hh>
#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>

namespace ssc
{
    struct DLL_PUBLIC OS_Map
    {
        u8_t    * ptr;
        u64_t     size;
        OS_File_t os_file;
#ifdef _WIN64
        OS_File_t win64_filemapping;
#endif
    };

    void DLL_PUBLIC map_file   (OS_Map & os_map, bool const readonly);
    void DLL_PUBLIC unmap_file (OS_Map const & os_map);
    void DLL_PUBLIC sync_map   (OS_Map const & os_map);
}/* ! namespace ssc */

#include <ssc/files/files.hh>
#include <ssc/general/integers.hh>

#if   defined(__gnu_linux__)
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <unistd.h>
#elif defined(_WIN64)
    #include <windows.h>
#if 0 // Test without including these first
    #include <fileapi.h>
    #include <winbase.h>
#endif
#else
    #error "Only defined for Gnu/Linux"
#endif

namespace ssc
{
#if   defined(__gnu_linux__)
    std::size_t get_file_size(const int file_d)
    {
        using namespace std;
        
        struct stat s;
        if ( fstat( file_d, &s ) == -1 )
        {
            fprintf( stderr, "Unable to fstat file descriptor #%d\n", file_d );
            exit( EXIT_FAILURE );
        }
        return static_cast<std::size_t>(s.st_size);
        using namespace std;
        using namespace std;
    }
#elif defined(_WIN64)
    std::size_t get_file_size(HANDLE handle)
    {
        using namespace std;

        LARGE_INTEGER l_i;
        if ( GetFileSizeEx( handle, &l_i ) == 0 )
        {
            fputs( "Error: GetFileSizeEx() failed\n", stderr );
            exit( EXIT_FAILURE );
        }
        return static_cast<size_t>(l_i.QuadPart);
    }
#endif
    
    std::size_t get_file_size(std::FILE * const file)
    {
        using namespace std;
        
        size_t num_bytes = 0;
        fpos_t position;
        if ( fgetpos( file, &position ) == -1 )
        {
            fprintf( stderr, "Failed to get file position\n" );
            exit( EXIT_FAILURE );
        }
        while ( fgetc( file ) != EOF )
            ++num_bytes;
        if ( fsetpos( file, &position ) == -1 )
        {
            fprintf( stderr, "Failed to set file position to its original position\n" );
            exit( EXIT_FAILURE );
        }
        return num_bytes;
    }
    
    std::size_t get_file_size(const char * filename)
    {
        using namespace std;
        
#if defined(__gnu_linux__)
        struct stat s;
        if ( stat( filename, &s ) != 0 )
        {
            fprintf( stderr, "Failed to stat info about %s\n", filename );
            exit( EXIT_FAILURE );
        }
        return static_cast<size_t>(s.st_size);
#else // All other platforms
        size_t num_bytes = 0;
        FILE * stream = fopen( filename, "rb" );
        if ( stream == nullptr )
        {
            fprintf( stderr, "Failed to open file %s\n", filename );
            exit( EXIT_FAILURE );
        }
        while ( fgetc( stream ) != EOF )
            ++num_bytes;
        if ( fclose( stream ) == -1 )
        {
            fprintf( stderr, "Failed to close file %s\n", filename );
            exit( EXIT_FAILURE );
        }
        return num_bytes;
#endif
    } /* ! get_file_size(const char * filename) */
    
    bool file_exists(const char * filename)
    {
        using namespace std;
        
        bool exists = false;
        FILE * test = fopen( filename, "rb" );
        if ( test != nullptr )
        {
            fclose( test );
            exists = true;
        }
        return exists;
    }
    
    void check_file_name_sanity(const std::string & str,
                                const std::size_t min_size)
    {
        if ( str.size() < min_size )
        {
            std::fprintf( stderr, "Error: Filename %s must have at least %zu character(s)\n",
                          str.c_str(), min_size );
            std::exit( EXIT_FAILURE );
        }
    }

    void enforce_file_existence(char const * const __restrict filename,
                                bool const                    force_to_exist,
                                char const * const __restrict opt_error_msg)
    {
        bool const exists = file_exists( filename );
        if ( exists )
        {
            if ( force_to_exist )
                return;
            else
            {// Error: File exists when it shouldn't
                if ( opt_error_msg == nullptr )
                    std::fprintf( stderr, "Error: The file '%s' seems to already exist.\n", filename );
                else
                    std::fputs( opt_error_msg, stderr );
            }
        }
        else
        { // doesn't exist
            if ( force_to_exist )
            {// Error: File doesn't exist when it should
                if ( opt_error_msg == nullptr )
                    std::fprintf( stderr, "Error: The file '%s' doesn't seem to exist.\n", filename );
                else
                    std::fputs( opt_error_msg, stderr );
            }
            else
                return;
        }
        std::exit( EXIT_FAILURE );
    }
}

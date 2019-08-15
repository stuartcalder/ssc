#include "parse_string.hh"

namespace ssc
{
    bool enforce_integer(std::string & str)
    {
        bool success = true;
        std::string s;
        for ( char const ch : str )
            if ( isdigit( ch ) )
                s+= ch;
        if ( s.empty() )
            success = false;
        else
            str = s;
        return success;
    }
}/* ! namespace ssc */

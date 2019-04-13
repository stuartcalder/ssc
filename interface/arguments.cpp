#include <cstring>
#include <cstdio>
#include <cstdlib>
#include "arguments.hpp"

static inline bool is_hyphenated_switch(const char * const string) {
  return string[0] == '-';
}
static inline bool is_allowed_switch(const char * const sw,
                                     const char ** allowed,
                                     const int num_allowed)
{
  for( int i = 0; i < num_allowed; ++i )
    if( std::strcmp( sw, allowed[i] ) == 0 )
      return true;
  return false;
}

bool sanitize_arguments(const char **arguments,
                        const char **allowed_switches,
                        const int num_args,
                        const int num_allowed_switches)
{
  for( int i = 0; i < num_args; ++i )
  {
    // Is the argument a switch?
    if( is_hypenated_switch( arguments[i] ) )
    {
      // Is it an allowed hyphenated switch?
      if( ! is_allowed_switch( arguments[i], allowed_switches, num_allowed_switches ) )
      {
        std::fprintf( stderr, "Illegal argument: %s\n", arguments[i] );
        exit( 1 );
      }
      ++i; // It was an allowed switch, so the next element must be an argument
    }
  }
}

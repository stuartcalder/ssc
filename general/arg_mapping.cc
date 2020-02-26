/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#include <ssc/general/arg_mapping.hh>

namespace ssc
{
    void Arg_Mapping::clear()
    {
        mapping.clear();
    }
    
    void Arg_Mapping::parse_c_args(const int argc, const char * argv[])
    {
        /* Vectorize the arguments */
        std::vector< std::string > vec;
        for( int i = 0; i < argc; ++i )
            vec.push_back( argv[i] );
        /* Iterate through */
        std::pair< std::string, std::string > temp_pair;
        for( decltype(vec.size()) i = 0; i < vec.size(); ++i )
        {
            // is this string an option?
            if( is_option( vec[i] ) )
            {
                // it is an option, put it in the `first` of the temp_pair
                temp_pair.first = vec[i];
                // is the next string (if there is one) an option, or an argument to this option?
                if( (i + 1) < vec.size() && (! is_option( vec[i + 1] )) )
                {
                    temp_pair.second = vec[i + 1];
                    ++i; // we consumed one more string than we would have otherwise, so increment.
                }
            }
            // the string from vec[] wasn't an option, therefore it is a floating argument.
            else
            {
                temp_pair.second = vec[i];
            }
            // Commit what was just iterated over into the `mapping` private variable of the class.
            mapping.push_back( std::move( temp_pair ) );
            // Clear whatever was or wasn't in the temp_pair and continue on through the arguments.
            temp_pair.first.clear();
            temp_pair.second.clear();
        }/* end for( decltype(vec.size()) i = 0; i < vec.size(); ++i ) */
    }
    
    bool Arg_Mapping::is_option(const std::string & str) const
    {
        bool status = true;
        if( str.size() <= 1 )
            status = false;
        else if( str[0] != '-' )
            status = false;
        return status;
    }
    
    void Arg_Mapping::print_mapping() const
    {
        /* Determine longest string length out of all of them
           to use as the minimum field width */
        decltype(mapping)::size_type min_field_size = 0;
        for( const auto & pair : mapping )
        {
            if( pair.first.size() > min_field_size )
                min_field_size = pair.first.size();
            if( pair.second.size() > min_field_size )
                min_field_size = pair.second.size();
        }
        /* Print out everything */
        for( const auto & pair : mapping )
        {
            std::printf( "{ %*s, %*s }\n",
                         static_cast<int>(min_field_size), pair.first.c_str(),
                         static_cast<int>(min_field_size), pair.second.c_str() );
        }
    }
    
    Arg_Mapping::Arg_Mapping(const int argc, const char * argv[])
    {
        parse_c_args( argc, argv );
    }
    
    auto Arg_Mapping::get() const
        -> const Arg_Map_t &
    {
        return mapping;
    }
    
    auto Arg_Mapping::consume()
        -> Arg_Map_t
    {
        return mapping;
    }
}

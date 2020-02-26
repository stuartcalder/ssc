/*
Copyright (c) 2019-2020 Stuart Steven Calder
All rights reserved.
See accompanying LICENSE file for licensing information.
*/
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <ssc/general/error_conditions.hh>
#ifdef __gnu_linux__
#	include <endian.h>
#endif

namespace ssc
{
    struct Endian
    {
        static constexpr const bool Host_Is_Big_Endian = [](){
                                                             uint32_t i = 1;
                                                             auto test = reinterpret_cast<uint8_t *>(&i);
                                                             return (*test) == 0;
                                                         }();
        static constexpr const bool Host_Is_Little_Endian = !(Host_Is_Big_Endian);
        template< typename uint_t >
        static uint_t host_to_le(const uint_t h) const;
        template< typename uint_t >
        static uint_t host_to_be(const uint_t h) const;
        template< typename uint_t >
        static uint_t be_to_host(const uint_t b) const;
        template< typename uint_t >
        static uint_t le_to_host(const uint_t l) const;
    };
    template< typename uint_t >
    uint_t Endian::host_to_le<uint_t>(const uint_t h) const
    {
#ifndef __gnu_linux__
#   error "host_to_le() only defined for gnu/linux!"
#endif
        if      constexpr ( sizeof(uint_t) == 1 )
                              return h;
        else if constexpr ( sizeof(uint_t) == 2 )
                              return htole16( h );
        else if constexpr ( sizeof(uint_t) == 4 )
                              return htole32( h );
        else if constexpr ( sizeof(uint_t) == 8 )
                              return htole64( h );
        else
            {
		    errx( "Error: Illegal sized uint_t in host_to_le\n" );
#if 0
                std::fprintf( stderr, "Illegal sized uint_t in host_to_le\n" );
                std::exit( EXIT_FAILURE );
#endif
            }
    }
    template< typename uint_t >
    uint_t Endian::host_to_be<uint_t>(const uint_t h) const
    {
#if ! defined(__gnu_linux__)
    #error "host_to_be() only defined for gnu/linux!"
#endif
        if      constexpr ( sizeof(uint_t) == 1 )
                              return h;
        else if constexpr ( sizeof(uint_t) == 2 )
                              return htobe16( h );
        else if constexpr ( sizeof(uint_t) == 4 )
                              return htobe32( h );
        else if constexpr ( sizeof(uint_t) == 8 )
                              return htobe64( h );
        else
            {
		    errx( "Error: Illegal sized uint_t in host_to_be\n" );
#if 0
                std::fprintf( stderr, "Illegal sized uint_t in host_to_be\n" );
                std::exit   ( EXIT_FAILURE );
#endif
            }
    }
    template< typename uint_t >
    uint_t Endian::be_to_host<uint_t>(const uint_t b) const
    {
#if ! defined(__gnu_linux__)
    #error "be_to_host() only defined for gnu/linux!"
#endif
        if      constexpr ( sizeof(uint_t) == 1 )
                              return b;
        else if constexpr ( sizeof(uint_t) == 2 )
                              return be16toh( b );
        else if constexpr ( sizeof(uint_t) == 4 )
                              return be32toh( b );
        else if constexpr ( sizeof(uint_t) == 8 )
                              return be64toh( b );
        else
            {
		    errx( "Error: Illegal sized uint_t in be_to_host\n" );
#if 0
                std::fprintf( stderr, "Illegal sized uint_t in be_to_host\n" );
                std::exit   ( EXIT_FAILURE );
#endif
            }
    }
    template< typename uint_t >
    uint_t Endian::le_to_host<uint_t>(const uint_t l) const
    {
#if ! defined(__gnu_linux__)
    #error "le_to_host() only defined for gnu/linux!"
#endif
        if      constexpr ( sizeof(uint_t) == 1 )
                              return l;
        else if constexpr ( sizeof(uint_t) == 2 )
                              return le16toh( l );
        else if constexpr ( sizeof(uint_t) == 4 )
                              return le32toh( l );
        else if constexpr ( sizeof(uint_t) == 8 )
                              return le64toh( l );
        else
            {
		    errx( "Error: Illegal sized uint_t in le_to_host\n" );
#if 0
                std::fprintf( stderr, "Illegal sized uint_t in le_to_host\n" );
                std::exit   ( EXIT_FAILURE );
#endif
            }
    }
}

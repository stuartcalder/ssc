/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#include <ssc/general/c_argument_map.hh>
#include <ssc/general/error_conditions.hh>
#include <cstdlib>
#include <cstring>
using namespace ssc;

C_Argument_Map::C_Argument_Map (int const argc, char const *argv[])
{
	/* Allocate memory for c_strings and sizes */
	if( argc == 0 )
		errx( "Error: Invalid arg count in C_Argument_Map\n" );
	if( argc > Max_Argument_Count )
		errx( "Error: Invalid arg count in C_Argument_Map\n" );
	count = argc - 1;
	if( count == 0 )
		return;
	char const **args = argv + 1;
	c_strings = static_cast<char const**>(std::malloc( sizeof(char*) * count ));
	if( c_strings == nullptr )
		errx( "Error: malloc() failure in C_Argument_Map\n" );
	sizes = static_cast<size_t*>(std::malloc( sizeof(size_t) * count ));
	if( sizes == nullptr )
		errx( "Error: malloc() failure in C_Argument_Map\n" );
	/* Assign all the strings in args to the positions in c_strings, and store
	 * their sizes. */
	max_string_size = 0;
	std::memcpy( c_strings, args, (sizeof(char*) * count) );
	for( int i = 0; i != count; ++i ) {
		sizes[ i ] = std::strlen( c_strings[ i ] );
		if( sizes[ i ] > max_string_size )
			max_string_size = sizes[ i ];
	}
}

C_Argument_Map::~C_Argument_Map ()
{
	std::free( c_strings );
	std::free( sizes );
}

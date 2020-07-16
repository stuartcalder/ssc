/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#include <ssc/general/c_argument_map.hh>
#include <shim/errors.h>
#include <cstdlib>
#include <cstring>
using namespace ssc;

C_Argument_Map::C_Argument_Map (int const argc, char const *argv[])
{
	static constexpr auto &Bad_Arg_Count = "Error: Invalid arg count in C_Argument_Map\n";
	/* Allocate memory for c_strings and sizes */
	if( argc == 0 )
		SHIM_ERRX (Bad_Arg_Count);
	if( argc > Max_Argument_Count )
		SHIM_ERRX (Bad_Arg_Count);
	count = argc - 1;
	if( count == 0 )
		return;
	char const **args = argv + 1;
	c_strings = static_cast<char const**>(std::malloc( sizeof(char*) * count ));
	if( c_strings == nullptr )
		SHIM_ERRX (SHIM_ERR_STR_ALLOC_FAILURE);
	sizes = static_cast<size_t*>(std::malloc( sizeof(size_t) * count ));
	if( sizes == nullptr )
		SHIM_ERRX (SHIM_ERR_STR_ALLOC_FAILURE);
	/* Assign all the strings in args to the positions in c_strings, and store
	 * their sizes. */
	max_string_size = 0;
	std::memcpy( c_strings, args, (sizeof(char*) * count) );
	for( int i = 0; i < count; ++i ) {
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

bool
C_Argument_Map::argument_cmp (int const                   index,
			      char const * SHIM_RESTRICT  c_str,
		              size_t const                c_str_size)
{
	if( sizes[ index ] != c_str_size )
		return false;
	return std::strcmp( c_strings[ index ], c_str ) == 0;
}

bool
C_Argument_Map::next_string_is_valid (int const index)
{
	return ((index + 1) < count) && c_strings[ index + 1 ];
}

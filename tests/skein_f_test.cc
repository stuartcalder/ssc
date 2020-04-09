#include <ssc/crypto/skein.hh>
// New versions
#include <ssc/crypto/skein_f.hh>
#include <ssc/general/print.hh>

using namespace std;
using namespace ssc;


int main()
{
	alignas(u64_t) u8_t  output [64];
	alignas(u64_t) u8_t  to_hash[] = { 0xff, 0xff, 0xa2, 0x99, 0xff };
	alignas(u64_t) u8_t  hash_key[64] = { 0 };

	{
		using Skein_f = Skein_F<512>;
		Skein_f::Data_t skein_data;
		Skein_f::hash_native( &skein_data, output, to_hash, sizeof(to_hash) );
		puts( "The output of hashing with Skein-512 in native mode is..." );
		print_integral_buffer<u8_t>( output, sizeof(output) );
		Skein_f::hash( &skein_data, output, to_hash, sizeof(to_hash), sizeof(output) );
		puts( "\n\nThe output of hashing with Skein-512 in general mode is..." );
		print_integral_buffer<u8_t>( output, sizeof(output) );
		puts( "\n\nThe output of keyed-hashing with Skein-512 is..." );
		Skein_f::mac( &skein_data, output, to_hash, hash_key, sizeof(output), sizeof(to_hash) );
		print_integral_buffer<u8_t>( output, sizeof(output) );
	}
	{// Original nastyness
		using Threefish_t = Threefish<512>;
		using UBI_t = Unique_Block_Iteration<512>;
		using Skein_t = Skein<512>;
		_CTIME_CONST (int) Buf_Size = Threefish_t::Buffer_Bytes + UBI_t::Buffer_Bytes;
		alignas(u64_t) u8_t big_buffer [Buf_Size];
		Threefish_t threefish{ reinterpret_cast<u64_t*>(big_buffer) };
		UBI_t       ubi      { &threefish, (big_buffer + Threefish_t::Buffer_Bytes) };
		Skein_t     skein    { &ubi };
		skein.hash( output, to_hash, sizeof(to_hash), sizeof(output) );
		printf( "\n\nThe output of the original is...\n" );
		print_integral_buffer<u8_t>( output, sizeof(output) );
		printf( "\n\nThe output of the original keyed-hashing is...\n" );
		skein.message_auth_code( output, to_hash, hash_key, sizeof(to_hash), sizeof(hash_key), sizeof(output) );
		print_integral_buffer<u8_t>( output, sizeof(output) );
	}
#if 0
	{
		using Skein_f = Skein_F<256>;
		Skein_f::Data_t skein_data;
		alignas(u64_t) u8_t output [Skein_f::State_Bytes];
		u8_t const to_hash = 0xff;
		Skein_f::hash_native( &skein_data, output, &to_hash, sizeof(to_hash) );
		puts( "\n\nThe output of hashing 0xff with Skein-256 in native mode is...\n\n" );
		print_integral_buffer<u8_t>( output, sizeof(output) );
		Skein_f::hash( &skein_data, output, &to_hash, sizeof(to_hash), sizeof(output) );
		puts( "\n\nThe output of hashing 0xff with Skein-256 in general mode is...\n\n" );
		print_integral_buffer<u8_t>( output, sizeof(output) );
	}
#endif
#if 0
	{
		using Skein_f = Skein_F<1024,Key_Schedule_E::Pre_Compute>;
		Skein_f::Data_t skein_data;
		alignas(u64_t) u8_t output [Skein_f::State_Bytes];
		u8_t const to_hash = 0xff;
		Skein_f::hash_native( &skein_data, output, &to_hash, sizeof(to_hash) );
		puts( "The output of hashing 0xff with Skein-1024 in native mode is..." );
		print_integral_buffer<u8_t>( output, sizeof(output) );
		Skein_f::hash( &skein_data, output, &to_hash, sizeof(to_hash), sizeof(output) );
		puts( "\n\nThe output of hashing 0xff with Skein-1024 in general mode is..." );
		print_integral_buffer<u8_t>( output, sizeof(output) );
	}
#endif

	return 0;
}

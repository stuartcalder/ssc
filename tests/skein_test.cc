#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/print.hh>
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/unique_block_iteration.hh>
#include <ssc/crypto/skein.hh>

int main() {
	using namespace std;
	using namespace ssc;

	static_assert		(CHAR_BIT == 8);
	_CTIME_CONST(int)	State_Bits = 512;
	_CTIME_CONST(int)	State_Bytes = State_Bits / CHAR_BIT;
	_CTIME_CONST(int)	Tweak_Bits = 128;
	_CTIME_CONST(int)	Tweak_Bytes = Tweak_Bits / CHAR_BIT;

	using Threefish_t = Threefish<State_Bits>;
	using UBI_t       = Unique_Block_Iteration<Threefish_t, State_Bits>;
	using Skein_t     = Skein<State_Bits>;

	u8_t	crypto_buffer	[Threefish_t::Buffer_Bytes + UBI_t::Buffer_Bytes];

	u8_t	input[]	= { 0xff };
	u8_t	native_output		[State_Bytes];
	u8_t	general_output		[State_Bytes];

	Threefish_t threefish{ reinterpret_cast<u64_t *>(crypto_buffer) };
	UBI_t	    ubi{ &threefish, (crypto_buffer + Threefish_t::Buffer_Bytes) };
	Skein_t	    skein{ &ubi };

	skein.hash_native( native_output, input, sizeof(input) );
	skein.hash( general_output, input, sizeof(input), sizeof(general_output) );

	printf(   "Native hash of 0xff is: " );
	print_integral_buffer<u8_t>( native_output, sizeof(native_output) );
	printf( "\nGeneral has of 0xff is: " );
	print_integral_buffer<u8_t>( general_output, sizeof(general_output) );
	putchar( '\n' );
}

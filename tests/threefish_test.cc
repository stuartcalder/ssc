#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/print.hh>
#include <ssc/crypto/threefish.hh>

#ifndef CTIME_CONST
#	define CTIME_CONST(type) static constexpr const type
#else
#	error "Already defined"
#endif

int main() {
	using namespace std;
	using namespace ssc;
	static_assert (CHAR_BIT == 8);
	CTIME_CONST(int)	State_Bits = 512;
	using Threefish_t = Threefish<State_Bits>;
	CTIME_CONST(int)	State_Bytes = State_Bits / CHAR_BIT;
	CTIME_CONST(int)	Tweak_Bits  = 128;
	CTIME_CONST(int)	Tweak_Bytes = Tweak_Bits / CHAR_BIT;

	u8_t	test_key	[State_Bytes] = { 0 };
	u8_t	test_tweak	[Tweak_Bytes] = { 0 };
	u8_t	test_plaintext	[State_Bytes] = { 0 };
	u8_t	test_ciphertext [State_Bytes] = { 0 };

	Threefish_t threefish{ test_key, test_tweak };
	threefish.cipher( test_ciphertext, test_plaintext );
	puts(   "The plaintext: " );
	print_integral_buffer<u8_t>( test_plaintext, sizeof(test_plaintext) );
	puts( "\nThe ciphertext: ");
	print_integral_buffer<u8_t>( test_ciphertext, sizeof(test_ciphertext) );
	putchar( '\n' );
}

#undef CTIME_CONST

#include <ssc/crypto/threefish.hh>
#include <ssc/general/print.hh>
#include <ssc/general/integers.hh>

#ifndef CTIME_CONST
#	define CTIME_CONST(type) static constexpr const type
#else
#	error 'Already defined'
#endif

int main() {
	using namespace std;
	using namespace ssc;
	static_assert		(CHAR_BIT == 8);
	CTIME_CONST(int)	State_Bits = 512;
	CTIME_CONST(int)	State_Bytes = State_Bits / CHAR_BIT;
	CTIME_CONST(int)	Tweak_Bits = 128;
	CTIME_CONST(int)	Tweak_Bytes = Tweak_Bits / CHAR_BIT;

	using Threefish_t = Threefish<State_Bits>;

	u8_t	crypto_buffer	[Threefish_t::Buffer_Bytes];
	u8_t	test_plaintext	[State_Bytes] = { 0 };
	u8_t	test_ciphertext [State_Bytes] = { 0 };
	u8_t	test_key	[State_Bytes] = { 0 };
	u8_t	test_tweak	[Tweak_Bytes] = { 0 };

	Threefish_t threefish{ reinterpret_cast<u64_t *>(crypto_buffer), test_key, test_tweak };
	threefish.cipher( test_ciphertext, test_plaintext );
	printf(   "The plaintext was: " );
	print_integral_buffer<u8_t>( test_plaintext, sizeof(test_plaintext) );
	printf( "\nThe ciphertext was: " );
	print_integral_buffer<u8_t>( test_ciphertext, sizeof(test_ciphertext) );
	putchar( '\n' );
}
#undef CTIME_CONST

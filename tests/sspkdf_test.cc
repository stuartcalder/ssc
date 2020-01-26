#include <ssc/crypto/sspkdf.hh>
#include <ssc/crypto/implementation/sspkdf.hh>

#ifndef CTIME_CONST
#	define CTIME_CONST(type) static constexpr const type
#else
#	error 'Already defined'
#endif

int main() {
	using namespace ssc;
	using namespace ssc::crypto_impl;
	static_assert (CHAR_BIT == 8);
	CTIME_CONST(int)	State_Bits = 512;
	using Threefish_t = Threefish<State_Bits>;
	using UBI_t       = Unique_Block_Iteration<Threefish_t, State_Bits>;
	using Skein_t     = Skein<State_Bits>;
	CTIME_CONST(int)	State_Bytes = State_Bits / CHAR_BIT;
	CTIME_CONST(int)	Salt_Bytes  = 128 / CHAR_BIT;
	CTIME_CONST(int)	Test_Iter_Count   = 10;
	CTIME_CONST(int)	Test_Concat_Count = 10;
	CTIME_CONST(auto &)	Test_Password = "test_password";
	CTIME_CONST(int)	Test_Password_Length = sizeof(Test_Password) - 1;

	sspkdf( output, skein, Test_Password, Test_Password_Length, test_salt, Test_Iter_Count, Test_Concat_Count );
	print_integral_buffer<u8_t>( output, sizeof(output) );
}

#undef CTIME_CONST

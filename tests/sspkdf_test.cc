#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/print.hh>
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/unique_block_iteration.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/sspkdf.hh>

#ifndef CTIME_CONST
#	define CTIME_CONST(type) static constexpr const type
#else
#	error "Already defined"
#endif

int main() {
	using namespace ssc;
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
#if 0
	CTIME_CONST(int)	Crypto_Buf_Size = Threefish_t::Buffer_Bytes + UBI_t::Buffer_Bytes;
#endif

#if 0
	u8_t	crypt_buf [Crypto_Buf_Size];
#endif
	u8_t	output    [State_Bytes];
	u8_t	test_salt [Salt_Bytes] = { 0 };

#if 0
	u64_t	* const threefish_data = reinterpret_cast<u64_t *>(crypt_buf);
	u8_t	* const ubi_data       = crypt_buf + Threefish_t::Buffer_Bytes;

	Threefish_t threefish{ threefish_data };
	UBI_t	    ubi      { &threefish, ubi_data };
	Skein_t	    skein    { &ubi };
#endif
	sspkdf( output, Test_Password, Test_Password_Length, test_salt, Test_Iter_Count, Test_Concat_Count );
	print_integral_buffer<u8_t>( output, sizeof(output) );
}

#undef CTIME_CONST

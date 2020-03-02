#include <ssc/crypto/threefish.hh>
#include <ssc/general/print.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/macros.hh>
#include <ssc/general/abstract.hh>

#include <cstring>

int main() {
	using namespace std;
	using namespace ssc;

	static_assert		(CHAR_BIT == 8);

	_CTIME_CONST(int)	Crypto_Buffer_Size = Return_Largest( Threefish<256>::Buffer_Bytes,
			                                             Threefish<512>::Buffer_Bytes,
								     Threefish<1024>::Buffer_Bytes );
	static_assert (Crypto_Buffer_Size == Threefish<1024>::Buffer_Bytes);

	_CTIME_CONST(int)	Biggest_Block_Size = Return_Largest( Threefish<256>::Block_Bytes,
			                                             Threefish<512>::Block_Bytes,
								     Threefish<1024>::Block_Bytes );
	static_assert (Biggest_Block_Size == Threefish<1024>::Block_Bytes);

	_CTIME_CONST(int)	Tweak_Bits = 128;
	_CTIME_CONST(int)	Tweak_Bytes = Tweak_Bits / CHAR_BIT;

	alignas(sizeof(u64_t)) u8_t crypto_buffer   [Crypto_Buffer_Size] = { 0 };
	alignas(sizeof(u64_t)) u8_t test_plaintext  [Biggest_Block_Size] = { 0 };
	alignas(sizeof(u64_t)) u8_t test_ciphertext [Biggest_Block_Size] = { 0 };
	alignas(sizeof(u64_t)) u8_t test_key        [Biggest_Block_Size] = { 0 };
	alignas(sizeof(u64_t)) u8_t test_tweak      [Tweak_Bytes] = { 0 };

	// Threefish<256> Test Vectors
	{//threefish-256
		Threefish<256> threefish{ reinterpret_cast<u64_t*>(crypto_buffer), test_key, test_tweak };
		threefish.cipher( test_ciphertext, test_plaintext );
		{//test-vector 0
			_CTIME_CONST(u8_t) expected_output [Threefish<256>::Block_Bytes] = {
				0x84,0xda,0x2a,0x1f,0x8b,0xea,0xee,0x94,
				0x70,0x66,0xae,0x3e,0x31,0x03,0xf1,0xad,
				0x53,0x6d,0xb1,0xf4,0xa1,0x19,0x24,0x95,
				0x11,0x6b,0x9f,0x3c,0xe6,0x13,0x3f,0xd8
			};
			if (memcmp( expected_output, test_ciphertext, sizeof(expected_output) ) == 0) {
				puts( "Threefish<256> test-vector 0 Passed!" );
				puts( "key:   0x0000000000000000000000000000000000000000000000000000000000000000\n"
				      "tweak: 0x00000000000000000000000000000000\n"
				      "ptext: 0x0000000000000000000000000000000000000000000000000000000000000000\n"
				      "ctext: 0x84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8" );
			} else {
				puts( "WARNING: Threefish<256> test-vector 0 FAILED.\n"
				      "Expected output:" );
				puts( "key:   0x0000000000000000000000000000000000000000000000000000000000000000\n"
				      "tweak: 0x00000000000000000000000000000000\n"
				      "ptext: 0x0000000000000000000000000000000000000000000000000000000000000000\n"
				      "ctext: 0x84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8" );
				puts( "Actual output:" );
				print_integral_buffer<u8_t>( test_ciphertext, Threefish<256>::Block_Bytes );
				return EXIT_FAILURE;
			}
		}
		{//test-vector 1
			_CTIME_CONST(u8_t) new_key [Threefish<256>::Block_Bytes] = {
				0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
				0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
				0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
				0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
			};
			_CTIME_CONST(u8_t) new_tweak [Tweak_Bytes] = {
				0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
				0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
			};
			_CTIME_CONST(u8_t) new_ptext [Threefish<256>::Block_Bytes] = {
				0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,
				0xf7,0xf6,0xf5,0xf4,0xf3,0xf2,0xf1,0xf0,
				0xef,0xee,0xed,0xec,0xeb,0xea,0xe9,0xe8,
				0xe7,0xe6,0xe5,0xe4,0xe3,0xe2,0xe1,0xe0
			};
			_CTIME_CONST(u8_t) expected_output [Threefish<256>::Block_Bytes] = {
				0xe0,0xd0,0x91,0xff,0x0e,0xea,0x8f,0xdf,
				0xc9,0x81,0x92,0xe6,0x2e,0xd8,0x0a,0xd5,
				0x9d,0x86,0x5d,0x08,0x58,0x8d,0xf4,0x76,
				0x65,0x70,0x56,0xb5,0x95,0x5e,0x97,0xdf
			};
			threefish.rekey( new_key, new_tweak );
			threefish.cipher( test_ciphertext, new_ptext );
			if (memcmp( expected_output, test_ciphertext, sizeof(expected_output) ) == 0) {
				puts( "Threefish<256> test-vector 1 Passed!" );
				puts( "key:   0x101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f\n"
				      "tweak: 0x000102030405060708090a0b0c0d0e0f\n"
				      "ptext: 0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0\n"
				      "ctext: 0xe0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df" );
			} else {
				puts( "WARNING: Threefish<256> test-vector 1 FAILED.\n"
				      "Expected output:" );
				puts( "key:   0x101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f\n"
				      "tweak: 0x000102030405060708090a0b0c0d0e0f\n"
				      "ptext: 0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0\n"
				      "ctext: 0xe0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df" );
				puts( "Actual output:" );
				print_integral_buffer<u8_t>( test_ciphertext, Threefish<256>::Block_Bytes );
				return EXIT_FAILURE;
			}
		}
		puts( "End of Threefish-256 test vectors" );
	}/*threefish-256*/
	{//threefish-512
		Threefish<512> threefish{ reinterpret_cast<u64_t*>(crypto_buffer), test_key, test_tweak };
		threefish.cipher( test_ciphertext, test_plaintext );
		{//test-vector 0
			_CTIME_CONST(u8_t) expected_output [Threefish<512>::Block_Bytes] = {
				0xb1,0xa2,0xbb,0xc6,0xef,0x60,0x25,0xbc,0x40,0xeb,0x38,0x22,0x16,0x1f,0x36,0xe3,
				0x75,0xd1,0xbb,0x0a,0xee,0x31,0x86,0xfb,0xd1,0x9e,0x47,0xc5,0xd4,0x79,0x94,0x7b,
				0x7b,0xc2,0xf8,0x58,0x6e,0x35,0xf0,0xcf,0xf7,0xe7,0xf0,0x30,0x84,0xb0,0xb7,0xb1,
				0xf1,0xab,0x39,0x61,0xa5,0x80,0xa3,0xe9,0x7e,0xb4,0x1e,0xa1,0x4a,0x6d,0x7b,0xbe
			};
			if (memcmp( expected_output, test_ciphertext, sizeof(expected_output) ) == 0) {
				puts( "Threefish<512> test-vector 0 Passed!" );
				puts( "key:   0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n"
				      "tweak: 0x00000000000000000000000000000000\n"
				      "ptext: 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n"
				      "ctext: 0xb1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe" );
			} else {
				puts( "WARNING: Threefish<512> test-vector 0 FAILED>\n"
				      "Expected output:" );
				puts( "key:   0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n"
				      "tweak: 0x00000000000000000000000000000000\n"
				      "ptext: 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n"
				      "ctext: 0xb1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe" );
				puts( "Actual output:" );
				print_integral_buffer<u8_t>( test_ciphertext, Threefish<512>::Block_Bytes );
				return EXIT_FAILURE;
			}
		}/*test-vector 0*/
		{//test-vector 1
			_CTIME_CONST(u8_t) new_key [Threefish<512>::Block_Bytes] = {
				0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
				0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
				0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
				0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
			};
			_CTIME_CONST(u8_t) new_tweak [Tweak_Bytes] = {
				0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
				0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
			};
			_CTIME_CONST(u8_t) new_ptext [Threefish<512>::Block_Bytes] = {
				0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,0xf7,0xf6,0xf5,0xf4,0xf3,0xf2,0xf1,0xf0,
				0xef,0xee,0xed,0xec,0xeb,0xea,0xe9,0xe8,0xe7,0xe6,0xe5,0xe4,0xe3,0xe2,0xe1,0xe0,
				0xdf,0xde,0xdd,0xdc,0xdb,0xda,0xd9,0xd8,0xd7,0xd6,0xd5,0xd4,0xd3,0xd2,0xd1,0xd0,
				0xcf,0xce,0xcd,0xcc,0xcb,0xca,0xc9,0xc8,0xc7,0xc6,0xc5,0xc4,0xc3,0xc2,0xc1,0xc0
			};
			_CTIME_CONST(u8_t) expected_output [Threefish<512>::Block_Bytes] = {
				0xe3,0x04,0x43,0x96,0x26,0xd4,0x5a,0x2c,0xb4,0x01,0xca,0xd8,0xd6,0x36,0x24,0x9a,
				0x63,0x38,0x33,0x0e,0xb0,0x6d,0x45,0xdd,0x8b,0x36,0xb9,0x0e,0x97,0x25,0x47,0x79,
				0x27,0x2a,0x0a,0x8d,0x99,0x46,0x35,0x04,0x78,0x44,0x20,0xea,0x18,0xc9,0xa7,0x25,
				0xaf,0x11,0xdf,0xfe,0xa1,0x01,0x62,0x34,0x89,0x27,0x67,0x3d,0x5c,0x1c,0xaf,0x3d
			};
			threefish.rekey( new_key, new_tweak );
			threefish.cipher( test_ciphertext, new_ptext );
			if (memcmp( expected_output, test_ciphertext, sizeof(expected_output) ) == 0) {
				puts( "Threefish<512> test-vector 1 Passed!" );
				puts( "key:   0x101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f\n"
				      "tweak: 0x000102030405060708090a0b0c0d0e0f\n"
				      "ptext: 0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0\n"
				      "ctext: 0xe304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d" );
			} else {
				puts( "WARNING: Threefish<512> test-vector 1 FAILED.\n"
				      "Expected output:" );
				puts( "key:   0x101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f\n"
				      "tweak: 0x000102030405060708090a0b0c0d0e0f\n"
				      "ptext: 0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0\n"
				      "ctext: 0xe304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d" );
				puts( "Actual output:" );
				print_integral_buffer<u8_t>( test_ciphertext, Threefish<512>::Block_Bytes );
				return EXIT_FAILURE;
			}
		}/*test-vector 1*/
	}/*threefish-512*/
	{//threefish-1024
	}/*threefish-1024*/
#if 0
	{// First test vector.
		_CTIME_CONST(u8_t) Null_Vector [State_Bytes] = {
			
		};


		threefish.cipher( test_ciphertext, test_plaintext );
		printf(   "The plaintext was: " );
		print_integral_buffer<u8_t>( test_plaintext, sizeof(test_plaintext) );
		printf( "\nThe ciphertext was: " );
		print_integral_buffer<u8_t>( test_ciphertext, sizeof(test_ciphertext) );
		putchar( '\n' );
		if (memcmp( test_ciphertext, Null_Vector ) != 0) {
			printf( "WARNING: TEST VECTOR FAILURE FOR 'Null_Vector'\n" );
			return EXIT_FAILURE;
		}
	}
#endif
	return EXIT_SUCCESS;
}


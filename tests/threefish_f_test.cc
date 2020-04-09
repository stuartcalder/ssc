#include <ssc/crypto/threefish_f.hh>
#include <ssc/general/print.hh>
using namespace std;
using namespace ssc;

int main()
{
	{// Precomputed Testing
		using Threefish_f = Threefish_F<512>;
		Threefish_f::Data_t data;
		alignas(u64_t) u64_t key   [Threefish_f::External_Key_Words] = { 0 };
		alignas(u64_t) u64_t tweak [Threefish_f::External_Tweak_Words] = { 0 };
		alignas(u64_t) u8_t  text  [Threefish_f::Block_Bytes] = { 0 };

		Threefish_f::rekey( &data, key, tweak );
		Threefish_f::cipher( &data, text, text );
		printf( "Size of Threefish-512 Precomputed Data_t: %zu\n", sizeof(data) );
		puts(
			"Threefish-512 (Precomputed Keyschedule)\n"
			"Key: all 0\n"
			"Tweak: all 0\n"
			"Plaintext: all 0\n"
			"Expected Ciphertext:\n"
			"b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe\n"
			"Actual Ciphertext:"
		);
		print_integral_buffer<u8_t>( text, sizeof(text) );
		Threefish_f::inverse_cipher( &data, text, text );
		puts( "\nInverse Ciphertext:" );
		print_integral_buffer<u8_t>( text, sizeof(text) );

		{
			u8_t ch = 0x10;
			for( int i = 0; i < Threefish_f::Block_Bytes; ++i ) {
				reinterpret_cast<u8_t*>(key)[ i ] = ch;
				++ch;
			}
			ch = 0x00;
			for( int i = 0; i < Threefish_f::Tweak_Bytes; ++i ) {
				reinterpret_cast<u8_t*>(tweak)[ i ] = ch;
				++ch;
			}
			ch = 0xff;
			for ( int i = 0; i < sizeof(text); ++i ) {
				text[ i ] = ch;
				--ch;
			}
		}
		Threefish_f::rekey( &data, key, tweak );
		puts(
			"\n\nThreefish-512 (Precomputed Keyschedule)\n"
			"Key:"
		);
		print_integral_buffer<u8_t>( reinterpret_cast<u8_t*>(key), Threefish_f::Block_Bytes );
		puts( "\nTweak:" );
		print_integral_buffer<u8_t>( reinterpret_cast<u8_t*>(tweak), Threefish_f::Tweak_Bytes );
		puts( "\nPlaintext:" );
		print_integral_buffer<u8_t>( text, sizeof(text) );
		Threefish_f::cipher( &data, text, text );
		puts(
			"\nExpected Ciphertext:\n"
			"e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d\n"
			"Actual Ciphertext:"
		);
		print_integral_buffer<u8_t>( text, sizeof(text) );
		Threefish_f::inverse_cipher( &data, text, text );
		puts( "\nInverse Ciphertext:" );
		print_integral_buffer<u8_t>( text, sizeof(text) );
		puts( "" );
	}// End precomputed testing
	{// Runtime testing
		using Threefish_f = Threefish_F<512,Key_Schedule_E::Runtime_Compute>;
		Threefish_f::Data_t data;
		alignas(u64_t) u64_t key   [Threefish_f::External_Key_Words] = { 0 };
		alignas(u64_t) u64_t tweak [Threefish_f::External_Tweak_Words] = { 0 };
		alignas(u64_t) u8_t  text  [Threefish_f::Block_Bytes] = { 0 };

		Threefish_f::rekey( &data, key, tweak );
		Threefish_f::cipher( &data, text, text );
		printf( "\n\nSize of Threefish-512 Runtime Data_t: %zu\n", sizeof(data) );
		puts(
			"Threefish-512 (Runtime Keyschedule)\n"
			"Key: all 0\n"
			"Tweak: all 0\n"
			"Plaintext: all 0\n"
			"Expected Ciphertext:\n"
			"b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe\n"
			"Actual Ciphertext:"
		);
		print_integral_buffer<u8_t>( text, sizeof(text) );
		Threefish_f::inverse_cipher( &data, text, text );
		puts( "\nInverse Ciphertext:" );
		print_integral_buffer<u8_t>( text, sizeof(text) );

		{
			u8_t ch = 0x10;
			for( int i = 0; i < Threefish_f::Block_Bytes; ++i ) {
				reinterpret_cast<u8_t*>(key)[ i ] = ch;
				++ch;
			}
			ch = 0x00;
			for( int i = 0; i < Threefish_f::Tweak_Bytes; ++i ) {
				reinterpret_cast<u8_t*>(tweak)[ i ] = ch;
				++ch;
			}
			ch = 0xff;
			for ( int i = 0; i < sizeof(text); ++i ) {
				text[ i ] = ch;
				--ch;
			}
		}
		Threefish_f::rekey( &data, key, tweak );
		puts(
			"\n\nThreefish-512 (Runtime Keyschedule)\n"
			"Key:"
		);
		print_integral_buffer<u8_t>( reinterpret_cast<u8_t*>(key), Threefish_f::Block_Bytes );
		puts( "\nTweak:" );
		print_integral_buffer<u8_t>( reinterpret_cast<u8_t*>(tweak), Threefish_f::Tweak_Bytes );
		puts( "\nPlaintext:" );
		print_integral_buffer<u8_t>( text, sizeof(text) );
		Threefish_f::cipher( &data, text, text );
		puts(
			"\nExpected Ciphertext:\n"
			"e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d\n"
			"Actual Ciphertext:"
		);
		print_integral_buffer<u8_t>( text, sizeof(text) );
		Threefish_f::inverse_cipher( &data, text, text );
		puts( "\nInverse Ciphertext:" );
		print_integral_buffer<u8_t>( text, sizeof(text) );
		puts( "" );
	}// End precomputed testing

	return 0;
}

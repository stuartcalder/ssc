#include <utility>
#include <chrono>
#include <iostream>

#include <ssc/general/print.hh>
#include <ssc/general/integers.hh>
#include <ssc/crypto/skein_prng.hh>
#include <ssc/crypto/entropy_pool.hh>
#include <ssc/crypto/operations.hh>
using namespace ssc;
using namespace std;

int
main (void) {
	using Skein_t	     = Skein<512>;
	using Skein_PRNG_t   = Skein_PRNG<512>;
	using Entropy_Pool_t = Entropy_Pool<Skein_PRNG_t, 2048 * 8, 512>;
	u8_t * buffer = new u8_t [64'000'000];


	auto start = chrono::steady_clock::now();
	// Test entropy pool...
	Entropy_Pool_t entropy_pool{ Skein_PRNG_t{} };
	auto end   = chrono::steady_clock::now();
	cout << "Took " << chrono::duration_cast<chrono::milliseconds>(end - start).count() << " milliseconds to construct Entropy_Pool_t.\n";
	Skein_t skein;
	start = chrono::steady_clock::now();
	skein.hash( buffer, (entropy_pool.get( 64 )), 64, 64'000'000 );
	end   = chrono::steady_clock::now();
	print_integral_buffer<u8_t>( buffer, 64'000'000 );
	cout << "Took " << chrono::duration_cast<chrono::milliseconds>(end - start).count() << " milliseconds to hash 64'000'000 bytes.\n";

	zero_sensitive( buffer, 64'000'000 );
	delete[] buffer;
	return EXIT_SUCCESS;
}

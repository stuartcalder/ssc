/*
Copyright (c) 2019 Stuart Steven Calder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma once

#include <cstdlib>
#include <cstring>

#include <utility>
#include <mutex>
#include <atomic>
#include <thread>

#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/memory/os_memory_locking.hh>

namespace ssc {

	template <typename PRNG_t, size_t Pool_Bits, size_t Max_Bits_Per_Call>
	class Entropy_Pool {
		public:
			/* Compile-Time Assertions & Data */
			static_assert (CHAR_BIT == 8);				// Chars must be 8 bits.
			static_assert (Pool_Bits % CHAR_BIT == 0);		// Pool_Bits must be divisible into bytes. 
			static_assert (Max_Bits_Per_Call % CHAR_BIT == 0);	// Max_Bits_Per_call must be divisibile into bytes.
			static_assert (Pool_Bits >= (5 * Max_Bits_Per_Call));	// Must Have at 64 bytes of headroom between the size of the pool

			enum class Thread_Status_e {
				None, Running, Finished
			};
			static constexpr size_t const Pool_Bytes = Pool_Bits / CHAR_BIT;
			static constexpr size_t const Max_Bytes_Per_Call = Max_Bits_Per_Call / CHAR_BIT;
			static constexpr size_t const Num_Calls_Ahead = 8;
			static constexpr int    const Num_Consec_Prng_Calls = 100;
			static constexpr size_t const Bytes_Left_Before_Reset = Max_Bytes_Per_Call * Num_Calls_Ahead;
			static_assert (Pool_Bytes > Bytes_Left_Before_Reset);
			/* Constructors / Destructor */
			Entropy_Pool() = delete;
			Entropy_Pool(PRNG_t &&);
			~Entropy_Pool();
			u8_t *get(int const requested_bytes);
		private:
			u8_t *pool;
			u8_t *reset_buffer;
			u8_t *current;
			u8_t *to_return;
			std::mutex pool_reset_mutex
			std::mutex prng_mutex;
			std::atomic<Thread_Status_e> reset_thread_status;
			std::atomic<Thread_Status_e> prng_thread_status;
			std::atomic_int bytes_left;
			std::atomic_int prng_calls_left;
			std::thread reset_thread;
			std::thread prng_thread;
			PRNG_t prng;
			/* Private Functions */
			void reset_pool_ (void);
			void reset_prng_ (void);
	};/*class Entropy_Pool*/

	template <typename PRNG_t, size_t Pool_Bits, size_t Max_Bits_Per_Call>
	Entropy_Pool<PRNG_t,Pool_Bits,Max_Bits_Per_Call>::Entropy_Pool(PRNG_t &&rng)
		: prng{ rng }, bytes_left{ Pool_Bytes }, reset_thread_status{ Thread_Status_e::None },
		  prng_thread_status{ Thread_Status_e::None }, prng_calls_left{ Num_Consec_Prng_Calls }
	{
		// Dynamically allocate space for the pool.
		pool = new(nothrow) u8_t [Pool_Bytes];
		if (pool == nullptr) {
			std::fputs( "Failed to dynamically allocate Entropy_Pool buffer memory\n", stderr );
			std::exit( EXIT_FAILURE );
		}
		// Dynamically allocate space for the reset buffer.
		reset_buffer = new(nothrow) u8_t [Pool_Bytes];
		if (reset_buffer == nullptr) {
			std::fputs( "Failed to dynamically allocate Entropy_Pool buffer memory\n", stderr );
			std::exit( EXIT_FAILURE );
		}
		// Initialize the current pointer to the beginning of the pool.
		current = pool;
		// Initialize the pool using the PRNG.
		prng.get( pool        , Pool_Bytes );
		// Initialize the reset buffer using the PRNG.
		prng.get( reset_buffer, Pool_Bytes );
	}/*Entropy_Pool{}*/

	template <typename PRNG_t, size_t Pool_Bits, size_t Max_Bits_Per_Call>
	Entropy_Pool<PRNG_t,Pool_Bits,Max_Bits_Per_Call>::~Entropy_Pool (void) {
		if (reset_thread.joinable())
			reset_thread.join();
		if (prng_thread.joinable())
			prng_thread.join();
		zero_sensitive( pool        , Pool_Bytes );
		zero_sensitive( reset_buffer, Pool_Bytes );
		delete[] pool;
		delete[] reset_buffer;
	}/*~Entropy_Pool{}*/

	template <typename PRNG_t, size_t Pool_Bits, size_t Max_Bits_Per_Call>
	void
	Entropy_Pool<PRNG_t,Pool_Bits,Max_Bits_Per_Call>::reset_pool_ (void) {
		{
			std::scoped_lock lock{ pool_reset_mutex };
			std::swap( pool, reset_buffer ); 
			current = pool;
			to_return = current;
			bytes_left = Pool_Bytes;
		}
		{
			std::scoped_lock lock{ prng_mutex };
			prng.get( reset_buffer, Pool_Bytes );
			--prng_calls_left;
		}
		reset_thread_status = Thread_Status_e::Finished;
	}/*reset_pool()*/

	template <typename PRNG_t, size_t Pool_Bits, size_t Max_Bits_Per_Call>
	void
	Entropy_Pool<PRNG_t,Pool_Bits,Max_Bits_Per_Call>::reset_prng_ (void) {
		{
			std::scoped_lock lock{ prng_mutex };
			prng.os_reseed();
			prng_calls_left = Num_Consec_Prng_Calls;
		}
		prng_thread_status = Thread_Status_e::Finished;
	}

	template <typename PRNG_t, size_t Pool_Bits, size_t Max_Bits_Per_Call>
	u8_t *
	get (int const requested_bytes) {
		bool enough_bytes;
		{
			std::scoped_lock lock{ pool_reset_mutex };
			enough_bytes = (bytes_left > Bytes_Left_Before_Reset);
			to_return = current;
		}
		if (!enough_bytes) {
			// We will switch the pointers `pool` and `reset_buffer` soon. Running out of entropy in `pool`.
			if (reset_thread_status != Thread_Status_e::Running) {
				// If the thread is not running... (It has either finished, or it was never started)
				if (reset_thread_status == Thread_Status_e::Finished) {
					// If the thread finished, join it.
					if (reset_thread.joinable())
						reset_thread.join();
				}
				// Open a new thread to reset the pool.
				reset_thread_status = Thread_Status_e::Running;
				reset_thread = std::thread{ reset_pool_ };
			}
			// If there are not enough bytes to complete the call...
			if (bytes_left < Max_Bytes_Per_Call) {
				//If the reset thread is currently executing, or has finished executing, then join the reset thread,
				//guaranteeing that there will be `Max_Bytes_Per_Call` bytes available.
				if (reset_thread.joinable()) {
					reset_thread.join();
				}
			}
		}
		//At this point there is guaranteed to be enough bytes to finish the get() call.
		if (prng_calls_left <= 0) {
			if (prng_thread_status != Thread_Status_e::Running) {
				if (prng_thread.joinable()) {
					prng_thread.join();
				}
				prng_thread_status = Thread_Status_e::Running;
				prng_thread = std::thread{ reset_prng_ };
			}
		}
		{
			std::scoped_lock lock{ pool_reset_mutex };
			current    += requested_bytes;
			bytes_left -= requested_bytes;
		}
		return to_return;
	}/*get()*/
}/*namespace ssc*/

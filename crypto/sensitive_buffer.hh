#pragma once

#ifdef __SSC_ENABLE_EXPERIMENTAL
#	include <cstring>
#	include <climits>

#	include <ssc/general/integers.hh>
#	include <ssc/general/macros.hh>
#	include <ssc/crypto/operations.hh>
#	include <ssc/memory/os_memory_locking.hh>

namespace ssc {
	template <typename Int_t, size_t Num_Elements, bool Mem_Lock = true>
	class Sensitive_Buffer {
		public:
			static_assert (CHAR_BIT == 8);
			static constexpr size_t Num_Bytes = sizeof(Int_t) * Num_Elements;

			Sensitive_Buffer  (void);

			Sensitive_Buffer  (Int_t);

			~Sensitive_Buffer (void);

			inline Int_t *
			get (void);

			inline Int_t &
			operator[] (size_t const);

			constexpr size_t
			num_elements (void);
		private:
			Int_t	buf	[Num_Elements];
	};

	template <typename Int_t, size_t Num_Elements, bool Mem_Lock>
	Sensitive_Buffer<Int_t,Num_Elements,Mem_Lock>::Sensitive_Buffer (void)
	{
#	ifdef __SSC_MemoryLocking__
		if constexpr(Mem_Lock)
			lock_os_memory( buf, sizeof(buf) );
#	endif
	}

	template <typename Int_t, size_t Num_Elements, bool Mem_Lock>
	Sensitive_Buffer<Int_t,Num_Elements,Mem_Lock>::Sensitive_Buffer (Int_t starting_value)
	{
#	ifdef __SSC_MemoryLocking__
		if constexpr(Mem_Lock)
			lock_os_memory( buf, sizeof(buf) );
#	endif
		std::memset( buf, starting_value, sizeof(buf) );
	}

	template <typename Int_t, size_t Num_Elements, bool Mem_Lock>
	Sensitive_Buffer<Int_t,Num_Elements,Mem_Lock>::~Sensitive_Buffer (void)
	{
		zero_sensitive( buf, sizeof(buf) );
#	ifdef __SSC_MemoryLocking__
		if constexpr(Mem_Lock)
			unlock_os_memory( buf, sizeof(buf) );
#	endif
	}

	template <typename Int_t, size_t Num_Elements, bool Mem_Lock>
	Int_t *
	Sensitive_Buffer<Int_t,Num_Elements,Mem_Lock>::get (void) {
		return buf;
	}

	template <typename Int_t, size_t Num_Elements, bool Mem_Lock>
	Int_t &
	Sensitive_Buffer<Int_t,Num_Elements,Mem_Lock>::operator[] (size_t const index) {
		return buf[ index ];
	}

	template <typename Int_t, size_t Num_Elements, bool Mem_Lock>
	constexpr size_t
	Sensitive_Buffer<Int_t,Num_Elements,Mem_Lock>::num_elements (void) {
		return Num_Elements;
	}
}/*namespace ssc*/
#endif/*#ifdef __SSC_ENABLE_EXPERIMENTAL*/

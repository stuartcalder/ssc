#pragma once

#ifdef __SSC_ENABLE_EXPERIMENTAL
#	include <cstring>
#	include <climits>

#	include <ssc/general/integers.hh>
#	include <ssc/general/symbols.hh>
#	include <ssc/general/error_conditions.hh>
#	include <ssc/crypto/operations.hh>
#	include <ssc/memory/os_memory_locking.hh>

#	ifndef DEFAULT_ARG
#		ifdef __SSC_MemoryLocking__
#			define DEFAULT_ARG = true
#		else
#			define DEFAULT_ARG = false
#		endif
#	else
#		error 'Already defined'
#	endif

namespace ssc {
	template <typename Int_t>
	class Sensitive_Dynamic_Buffer {
		public:
			Sensitive_Dynamic_Buffer (bool DEFAULT_ARG);

			Sensitive_Dynamic_Buffer (size_t const, bool const DEFAULT_ARG);

			~Sensitive_Dynamic_Buffer (void);

			inline Int_t *
			get (void);

			inline Int_t &
			operator[] (size_t const);

			inline size_t
			size (void) const;

			void
			reset (size_t const);
		private:
			Int_t *pointer;
			size_t num_bytes;
#	ifdef __SSC_MemoryLocking__
			bool const do_memory_locking;
#	endif
	};

	template <typename Int_t>
	Sensitive_Dynamic_Buffer<Int_t>::Sensitive_Dynamic_Buffer (bool lock)
#	ifdef __SSC_MemoryLocking__
		: pointer{ nullptr }, num_bytes{ 0 }, do_memory_locking{ lock }
#	else
		: pointer{ nullptr }, num_bytes{ 0 }
#	endif
	{
	}

	template <typename Int_t>
	Sensitive_Dynamic_Buffer<Int_t>::Sensitive_Dynamic_Buffer (size_t const num_elements, bool const lock)
#	ifdef __SSC_MemoryLocking__
		: do_memory_locking{ lock }
#	endif
	{
		num_bytes = num_elements * sizeof(Int_t);
		Int_t *p = new(std::nothrow) Int_t [num_elements];
		if (p == nullptr)
			errx( "Failed to allocate memory in Sensitive_Dynamic_Buffer\n" );
		pointer = p;
#	ifdef __SSC_MemoryLocking__
		if (do_memory_locking)
			lock_os_memory( pointer, num_bytes );
#	endif
	}

	template <typename Int_t>
	Sensitive_Dynamic_Buffer<Int_t>::~Sensitive_Dynamic_Buffer (void)
	{
		zero_sensitive( pointer, num_bytes );
#	ifdef __SSC_MemoryLocking__
		if (do_memory_locking)
			unlock_os_memory( pointer, num_bytes );
#	endif
		delete[] pointer;
	}

	template <typename Int_t>
	Int_t *
	Sensitive_Dynamic_Buffer<Int_t>::get (void)
	{
		return pointer;
	}

	template <typename Int_t>
	Int_t &
	Sensitive_Dynamic_Buffer<Int_t>::operator[] (size_t index)
	{
		return pointer[ index ];
	}

	template <typename Int_t>
	size_t
	Sensitive_Dynamic_Buffer<Int_t>::size (void) const
	{
		return size;
	}

	template <typename Int_t>
	void
	Sensitive_Dynamic_Buffer<Int_t>::reset (size_t const num_elements)
	{
		if (pointer != nullptr) {
			zero_sensitive( pointer, num_bytes );
#	ifdef __SSC_MemoryLocking__
			if (do_memory_locking)
				unlock_os_memory( pointer, num_bytes );
#	endif
			delete[] pointer;
		}
		
		num_bytes = num_elements * sizeof(Int_t);
		Int_t *p = new(std::nothrow) Int_t [num_elements];
		if (p == nullptr)
			errx( "Failed to allocate memory in Sensitive_Dynamic_Buffer::reset\n" );
		pointer = p;
#	ifdef __SSC_MemoryLocking__
		if (do_memory_locking)
			lock_os_memory( pointer, num_bytes );
#	endif
	}
	
}/*namespace ssc*/
#endif/*#ifdef __SSC_ENABLE_EXPERIMENTAL*/
#undef DEFAULT_ARG

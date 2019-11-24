#pragma once

#include <ssc/general/symbols.hh>
#include <ssc/general/integers.hh>

#include <string>

namespace ssc {
	struct DLL_PUBLIC Input {
		std::string	input_filename;
		std::string	output_filename;
		u32_t		number_sspkdf_iterations;
		u32_t		number_sspkdf_concatenations;
		bool		supplement_os_entropy;
	};
}/*namespace ssc*/

/* Copyright (c) 2019-2020 Stuart Steven Calder
 * All rights reserved.
 * See accompanying LICENSE file for licensing information.
 */
#pragma once
#if   !defined (__SSC_DRAGONFLY_V1__)
#	define  __SSC_DRAGONFLY_V1__
#else
#	error '__SSC_DRAGONFLY_V1__ already defined!'
#endif
/* SSC General */
#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/print.hh>
/* SSC File I/O */
#include <ssc/files/os_map.hh>
/* SSC Crypto */
#include <ssc/crypto/generic_graph_hash_f.hh>
#include <ssc/crypto/bit_reversal_graph_f.hh>
#include <ssc/crypto/catena_f.hh>
#include <ssc/crypto/counter_mode_f.hh>
/* Local */
#include "common.hh"
/* C++ std */
#include <type_traits>

namespace ssc::crypto_impl::dragonfly_v1
{

	/*  Anatomy of a DRAGONFLY_V1 header
	 *  |
	 *  | Plaintext portion of the header
	 *  |
	 *  v
	 *  <Dragonfly_V1_ID> <file_size><g_low><g_high><lambda><use_phi><threefish_tweak><salt><nonce>
	 *  <      17       > <    8    ><  1  ><   1  ><   1  ><   1   ><       16      >< 32 >< 32  >
	 *
	 *  <padding_bytes><reserved>
	 *  <      8      ><   8    >
	 *  ^
	 *  |
	 *  | Ciphertext portion of the header, begins right after the end of the plaintext portion.
	 */
	static_assert (CHAR_BIT == 8);
	using CTR_f      = Counter_Mode_F<Block_Bits>;
	using CTR_Data_t = typename CTR_f::Data;
	_CTIME_CONST (auto&) Dragonfly_V1_ID    = "SSC_DRAGONFLY_V1";
	enum Int_Constants : int {
		Block_Bits = 512,
		Block_Bytes = Block_Bits / CHAR_BIT,
		Salt_Bits  = 256,
		Salt_Bytes = Salt_Bits / CHAR_BIT,
		Max_Password_Bits = (Max_Password_Chars * CHAR_BIT),
		Plaintext_Header_Bytes = sizeof(Dragonfly_V1_ID) + sizeof(u64_t) + (4 * sizeof(u8_t)) + Tweak_Bytes + Salt_Bytes + CTR_f::IV_Bytes,
		Ciphertext_Header_Bytes = (sizeof(u64_t) * 2),
		Total_Header_Bytes = Plaintext_Header_Bytes + Ciphertext_Header_Bytes,
		Visible_Metadata_Bytes = Total_Header_Bytes + MAC_Bytes
	};
	static_assert (Block_Bytes == MAC_Bytes);
	using BRG_f = Generic_Graph_Hash_F<Block_Bits,
	                                   Bit_Reversal_Graph_F>;
	struct Catena_Safe_Metadata {
		// Version ID String: Dragonfly_Safe_V1
		alignas(u64_t) _CTIME_CONST (u8_t) Version_ID_Hash [64] = {
			0x79,0xb5,0x79,0x1e,0x9a,0xac,0x02,0x64,
			0x2a,0xaa,0x99,0x1b,0xd5,0x47,0xed,0x14,
			0x74,0x4d,0x72,0xbf,0x13,0x22,0x54,0xc9,
			0xad,0xd6,0xb9,0xbe,0xe8,0x70,0x18,0xe2,
			0xaa,0x51,0x50,0xe2,0x1f,0xcd,0x90,0x19,
			0xb6,0x1f,0x0e,0xc6,0x05,0x00,0xd6,0xed,
			0x7c,0xf2,0x03,0x53,0xfd,0x42,0xa5,0xa3,
			0x7a,0x0e,0xbb,0xb4,0xa7,0xeb,0xdb,0xab
		};
	};
	using Catena_Safe_f = Catena_F<BRG_f,
	                               Catena_Safe_Metadata,
				       Block_Bits,
				       Salt_Bits,
				       Max_Password_Bits,
				       true,
				       false>;
	struct Catena_Strong_Metadata {
		// Version ID String: Dragonfly_Strong_V1
		alignas(u64_t) _CTIME_CONST (u8_t) Version_ID_Hash [64] = {
			0x1f,0x23,0x89,0x58,0x4a,0x4a,0xbb,0xa5,
			0x9f,0x09,0xca,0xd4,0xef,0xac,0x43,0x1d,
			0xde,0x9a,0xb0,0xf8,0x69,0xaa,0x50,0xf3,
			0xed,0xcc,0xb4,0x7d,0x6d,0x4f,0x10,0xb9,
			0x8e,0x6a,0x68,0xab,0x6e,0x53,0xbc,0xd6,
			0xcf,0xfc,0xa7,0x63,0x94,0x44,0xbd,0xc7,
			0xb9,0x6d,0x09,0xf5,0x66,0x31,0xa3,0xc5,
			0xf3,0x26,0xeb,0x6f,0xa6,0xac,0xb0,0xa6
		};
	};
	using Catena_Strong_f = Catena_F<BRG_f,
	                                 Catena_Strong_Metadata,
					 Block_Bits,
					 Salt_Bits,
					 Max_Password_Bits,
					 true,
					 true>;
	void _PUBLIC encrypt (Catena_Input const &catena_input,
			      OS_Map             &input_map,
			      OS_Map             &output_map,
			      char const         *output_filename);
	void _PUBLIC decrypt (OS_Map &input_map,
			      OS_Map &output_map,
			      char const *output_filename);
	void _PUBLIC dump_header (OS_Map &input_map,
			          char const *filename);
}/* ~ namespace ssc::crypto_impl::dragonfly_v1 */

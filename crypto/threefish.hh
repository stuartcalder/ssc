#pragma once
#include <climits>
#include <cstdlib>
#include <cstring>
#include <ssc/crypto/operations.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/symbols.hh>

namespace ssc
{
    template <std::size_t Key_Bits>
    class Threefish
    {
    public:
        /* STATIC CHECKS */
        static_assert((Key_Bits == 256 || Key_Bits == 512 || Key_Bits == 1024), "Invalid keysize");
        static_assert ((CHAR_BIT == 8), "This implementation needs 8-bit chars");
        /* PUBLIC CONSTANTS */
        static constexpr const int   Number_Words   = Key_Bits / 64;
        static constexpr const int   Number_Rounds  = [](auto nw)
                                                      {
                                                          if ( nw == 16 )
                                                              return 80;
                                                          return 72;
                                                      }( Number_Words );
        static constexpr const int   Number_Subkeys = (Number_Rounds / 4) + 1;
        static constexpr const u64_t Constant_240   = 0x1bd1'1bda'a9fc'1a22;
        /* CONSTRUCTORS / DESTRUCTORS */
        Threefish()
        {
        }
        Threefish(const u8_t * __restrict k, const u8_t * __restrict tw = nullptr)
        {
            expand_key( k, tw );
        }
        ~Threefish(); // forward declared
        /* PUBLIC FUNCTIONS */
        void cipher(const u8_t *in, u8_t *out);
        void inverse_cipher(const u8_t *in, u8_t *out);
        void rekey(const u8_t __restrict * new_key, const u8_t __restrict * new_tweak = nullptr);
    private:
        /* PRIVATE DATA */
        u64_t state        [Number_Words];
        u64_t key_schedule [Number_Subkeys * Number_Words];
        /* PRIVATE FUNCTIONS */
        void         MIX                  (u64_t * __restrict x0, u64_t * __restrict x1, const int round, const int index) const;
        void         inverse_MIX          (u64_t * __restrict x0, u64_t * __restrict x1, const int round, const int index) const;
        void         expand_key           (const u8_t * __restrict key, const u8_t * __restrict tweak);
        void         add_subkey           (const int round);
        void         subtract_subkey      (const int round);
        static u64_t get_rotate_constant  (const int round, const int index);
        void         permute_state        ();
        void         inverse_permute_state();
    };
} /* ! namespace ssc */

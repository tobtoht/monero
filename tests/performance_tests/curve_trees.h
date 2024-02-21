// Copyright (c) 2014-2023, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "rust/cxx.h"
#include "rust/monero_rust.h"

using namespace monero_rust;

static rct::key gen_enote()
{
    crypto::secret_key sk = rct::rct2sk(rct::skGen());
    crypto::public_key pk;
    crypto::secret_key_to_public_key(sk, pk);
    return rct::pk2rct(pk);
}

static rust::Slice<const uint8_t> get_rust_slice(const rct::key &key)
{
    static_assert(sizeof(key.bytes) == 32, "unexpected key byte size");
    return rust::Slice<const uint8_t>{key.bytes, sizeof(key.bytes)};
}

class test_curve_trees_fcmp
{
    public:
        static const size_t loop_count = 1;
        static const size_t NUM_ELEMS_IN_TREE = 100;

        bool init()
        {
            // Generate random enote that we will use to prove membership
            m_spending_enote = gen_enote();

            // Fill the tree with enotes. The tree will probably be written in C++ anyway,
            // so stick with inserting 1 at a time for now for simple demo
            {
                curve_trees::add_squashed_enote_to_tree(m_generators_and_tree, get_rust_slice(m_spending_enote));
                for (size_t i = 0; i < NUM_ELEMS_IN_TREE - 1; ++i)
                {
                    curve_trees::add_squashed_enote_to_tree(m_generators_and_tree, get_rust_slice(gen_enote()));
                }
            }

            m_blind = rust::Slice<const uint8_t>{curve_trees::make_blind(m_generators_and_tree).data(), 32};

            return true;
        }

        bool test()
        {
            try
            {
                // Construct the membership proof
                // TODO: move this into init() and only perf test verify
                rust::box<curve_trees::BlindedPointAndProof> membership_proof = curve_trees::prove(m_generators_and_tree,
                    m_blind,
                    get_rust_slice(m_spending_enote));

                // Verify the membership proof
                return curve_trees::verify(m_generators_and_tree, membership_proof);
            }
            catch (...) { return false; }
            return true;
        }

    private:
        // Set up generators, permissibles, tree, and whitelists vector commitments
        rust::box<curve_trees::GeneratorsAndTree> m_generators_and_tree = monero_rust::curve_trees::init();
        rct::key m_spending_enote;
        rust::Slice<const uint8_t> m_blind;
};

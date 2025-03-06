// Copyright (c) 2025, The Monero Project
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

#include "gtest/gtest.h"

#include "carrot_impl/address_device_ram_borrowed.h"
#include "carrot_impl/carrot_tx_builder_inputs.h"
#include "carrot_mock_helpers.h"

using namespace carrot;

TEST(carrot_tx_builder, make_sal_proof_legacy_to_legacy_v1_normalsend_mainaddr)
{
    mock::mock_carrot_and_legacy_keys keys;
    keys.generate(AddressDeriveType::PreCarrot);

    const cryptonote_hierarchy_address_device_ram_borrowed addr_dev(
        keys.legacy_acb.get_keys().m_account_address.m_spend_public_key,
        keys.legacy_acb.get_keys().m_view_secret_key);

    // (K^0_s, K^0_v)
    const CarrotDestinationV1 addr = keys.cryptonote_address();

    const crypto::hash signable_tx_hash = crypto::rand<crypto::hash>();

    // a
    const rct::xmr_amount amount = crypto::rand<rct::xmr_amount>();
    // z
    const rct::key amount_blinding_factor = rct::skGen();
    // k^g_o
    const crypto::secret_key sender_extension_g = mock::gen_secret_key();

    // K_o = K^0_s + k^g_o G
    rct::key onetime_address;
    rct::addKeys1(onetime_address,
        rct::sk2rct(sender_extension_g),
        rct::pk2rct(addr.address_spend_pubkey));

    // C_a = z G + a H
    const rct::key amount_commitment = rct::commit(amount, amount_blinding_factor);

    const LegacyOutputOpeningHintV1 opening_hint{
        .onetime_address = rct::rct2pk(onetime_address),
        .sender_extension_g = sender_extension_g,
        .subaddr_index = {0, 0},
        .amount = amount,
        .amount_blinding_factor = rct::rct2sk(amount_blinding_factor)
    };

    const crypto::key_image key_image = keys.derive_key_image(addr.address_spend_pubkey,
        sender_extension_g,
        crypto::null_skey,
        rct::rct2pk(onetime_address));

    // fake output amount blinding factor in a hypothetical tx where we spent the aforementioned output
    const rct::key output_amount_blinding_factor = rct::skGen();

    // make rerandomized outputs
    std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs;
    make_carrot_rerandomized_outputs_nonrefundable({opening_hint.onetime_address},
        {amount_commitment},
        {amount_blinding_factor},
        {output_amount_blinding_factor},
        rerandomized_outputs);

    ASSERT_EQ(1, rerandomized_outputs.size());

    // make SA/L proof for spending aforementioned enote
    fcmp_pp::FcmpPpSalProof sal_proof;
    make_sal_proof_legacy_to_legacy_v1(signable_tx_hash,
        rerandomized_outputs.front(),
        opening_hint,
        keys.legacy_acb.get_keys().m_spend_secret_key,
        addr_dev,
        sal_proof);

    // verify SA/L
    EXPECT_TRUE(fcmp_pp::verify_sal(signable_tx_hash,
        rerandomized_outputs.front().input,
        key_image,
        sal_proof));
}

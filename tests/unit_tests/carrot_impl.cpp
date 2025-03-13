// Copyright (c) 2024, The Monero Project
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

#include <boost/multiprecision/cpp_int.hpp>

#include "carrot_core/output_set_finalization.h"
#include "carrot_core/payment_proposal.h"
#include "carrot_impl/carrot_tx_builder_inputs.h"
#include "carrot_impl/carrot_tx_builder_utils.h"
#include "carrot_impl/carrot_tx_format_utils.h"
#include "carrot_mock_helpers.h"
#include "common/container_helpers.h"
#include "crypto/generators.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/subaddress_index.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/blockchain.h"
#include "curve_trees.h"
#include "fcmp_pp/prove.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"

using namespace carrot;

namespace
{
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static constexpr rct::xmr_amount MAX_AMOUNT_FCMP_PP = MONEY_SUPPLY /
  (FCMP_PLUS_PLUS_MAX_INPUTS + FCMP_PLUS_PLUS_MAX_OUTPUTS + 1);
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void unittest_scan_enote_set_multi_account(const std::vector<CarrotEnoteV1> &enotes,
    const encrypted_payment_id_t encrypted_payment_id,
    const epee::span<const mock::mock_carrot_and_legacy_keys * const> accounts,
    std::vector<std::vector<mock::mock_scan_result_t>> &res)
{
    res.clear();
    res.reserve(accounts.size());

    for (const auto *account : accounts)
        mock_scan_enote_set(enotes, encrypted_payment_id, *account, tools::add_element(res));
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
struct unittest_transaction_preproposal
{
    using per_payment_proposal = std::pair<CarrotPaymentProposalV1, /*is subtractble?*/bool>;
    using per_ss_payment_proposal = std::pair<CarrotPaymentProposalVerifiableSelfSendV1, /*is subtractble?*/bool>;
    using per_account = std::pair<mock::mock_carrot_and_legacy_keys, std::vector<per_payment_proposal>>;
    using per_input = std::pair<crypto::key_image, rct::xmr_amount>;

    std::vector<per_account> per_account_payments;
    std::vector<per_ss_payment_proposal> explicit_selfsend_proposals;
    size_t self_sender_index{0};
    rct::xmr_amount fee_per_weight;
    std::vector<std::uint8_t> extra_extra;

    void get_flattened_payment_proposals(std::vector<CarrotPaymentProposalV1> &normal_payment_proposals_out,
        std::vector<CarrotPaymentProposalVerifiableSelfSendV1> &selfsend_payment_proposals_out,
        std::set<size_t> &subtractable_normal_payment_proposals,
        std::set<size_t> &subtractable_selfsend_payment_proposals) const
    {
        size_t norm_idx = 0;
        for (const per_account &pa : per_account_payments)
        {
            for (const per_payment_proposal &ppp : pa.second)
            {
                normal_payment_proposals_out.push_back(ppp.first);
                if (ppp.second)
                    subtractable_normal_payment_proposals.insert(norm_idx);

                norm_idx++;
            }
        }

        for (size_t ss_idx = 0; ss_idx < explicit_selfsend_proposals.size(); ++ss_idx)
        {
            const per_ss_payment_proposal &pspp = explicit_selfsend_proposals.at(ss_idx);
            selfsend_payment_proposals_out.push_back(pspp.first);
            if (pspp.second)
                subtractable_selfsend_payment_proposals.insert(ss_idx);
        }
    }
};
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
select_inputs_func_t make_fake_input_selection_callback(size_t num_ins = 0)
{
    return [num_ins](const boost::multiprecision::int128_t &nominal_output_sum,
        const std::map<std::size_t, rct::xmr_amount> &fee_per_input_count,
        size_t,
        size_t,
        std::vector<CarrotSelectedInput> &selected_inputs)
    {
        const size_t nins = num_ins ? num_ins : 1;
        selected_inputs.clear();
        selected_inputs.reserve(nins);

        const rct::xmr_amount fee = fee_per_input_count.at(nins);
        rct::xmr_amount in_amount_sum_64 = boost::numeric_cast<rct::xmr_amount>(nominal_output_sum + fee);

        for (size_t i = 0; i < nins - 1; ++i)
        {
            const rct::xmr_amount current_in_amount = in_amount_sum_64 ? crypto::rand_idx(in_amount_sum_64) : 0;
            const crypto::key_image current_key_image = rct::rct2ki(rct::pkGen());
            selected_inputs.push_back({current_in_amount, current_key_image});
            in_amount_sum_64 -= current_in_amount;
        }

        selected_inputs.push_back({in_amount_sum_64, rct::rct2ki(rct::pkGen())});
    };
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
using CarrotEnoteVariant = tools::variant<CarrotCoinbaseEnoteV1, CarrotEnoteV1>;
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
struct CarrotOutputContextsAndKeys
{
    std::vector<CarrotEnoteVariant> enotes;
    std::vector<encrypted_payment_id_t> encrypted_payment_ids;
    std::vector<fcmp_pp::curve_trees::OutputContext> output_pairs;
};
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static const CarrotOutputContextsAndKeys generate_random_carrot_outputs(
    const mock::mock_carrot_and_legacy_keys &keys,
    const std::size_t old_n_leaf_tuples,
    const std::size_t new_n_leaf_tuples)
{
    CarrotOutputContextsAndKeys outs;
    outs.enotes.reserve(new_n_leaf_tuples);
    outs.encrypted_payment_ids.reserve(new_n_leaf_tuples);
    outs.output_pairs.reserve(new_n_leaf_tuples);

    for (std::size_t i = 0; i < new_n_leaf_tuples; ++i)
    {
        const std::uint64_t output_id = old_n_leaf_tuples + i;
        fcmp_pp::curve_trees::OutputContext output_pair{
            .output_id = output_id
        };

        CarrotPaymentProposalV1 normal_payment_proposal{
            .destination = keys.cryptonote_address(),
            .amount = rct::randXmrAmount(MAX_AMOUNT_FCMP_PP),
            .randomness = gen_janus_anchor()
        };
        CarrotPaymentProposalVerifiableSelfSendV1 selfsend_payment_proposal{
            .proposal = CarrotPaymentProposalSelfSendV1{
                .destination_address_spend_pubkey = keys.cryptonote_address().address_spend_pubkey,
                .amount = rct::randXmrAmount(MAX_AMOUNT_FCMP_PP),
                .enote_type = i % 2 ? CarrotEnoteType::CHANGE : CarrotEnoteType::PAYMENT,
                .enote_ephemeral_pubkey = gen_x25519_pubkey()
            },
            .subaddr_index = {0, 0}
        };

        bool push_coinbase = false;
        CarrotCoinbaseEnoteV1 coinbase_enote;
        RCTOutputEnoteProposal rct_output_enote_proposal;
        encrypted_payment_id_t encrypted_payment_id = null_payment_id;

        const unsigned int enote_derive_type = i % 7;
        switch (enote_derive_type)
        {
        case 0: // coinbase enote
            get_coinbase_output_proposal_v1(normal_payment_proposal,
                mock::gen_block_index(),
                coinbase_enote);
            push_coinbase = true;
            break;
        case 1: // normal enote main address
            get_output_proposal_normal_v1(normal_payment_proposal,
                mock::gen_key_image(),
                rct_output_enote_proposal,
                encrypted_payment_id);
            break;
        case 2: // normal enote subaddress
            normal_payment_proposal.destination = keys.subaddress({mock::gen_subaddress_index()});
            get_output_proposal_normal_v1(normal_payment_proposal,
                mock::gen_key_image(),
                rct_output_enote_proposal,
                encrypted_payment_id);
            break;
        case 3: // special enote main address
            get_output_proposal_special_v1(selfsend_payment_proposal.proposal,
                keys.k_view_incoming_dev,
                keys.cryptonote_address().address_spend_pubkey,
                mock::gen_key_image(),
                std::nullopt,
                rct_output_enote_proposal);
            break;
        case 4: // special enote subaddress
            selfsend_payment_proposal.subaddr_index.index = mock::gen_subaddress_index();
            selfsend_payment_proposal.proposal.destination_address_spend_pubkey
                = keys.subaddress(selfsend_payment_proposal.subaddr_index).address_spend_pubkey;
            get_output_proposal_special_v1(selfsend_payment_proposal.proposal,
                keys.k_view_incoming_dev,
                keys.cryptonote_address().address_spend_pubkey,
                mock::gen_key_image(),
                std::nullopt,
                rct_output_enote_proposal);
            break;
        case 5: // internal main address
            get_output_proposal_internal_v1(selfsend_payment_proposal.proposal,
                keys.s_view_balance_dev,
                mock::gen_key_image(),
                std::nullopt,
                rct_output_enote_proposal);
            break;
        case 6: // internal subaddress
            selfsend_payment_proposal.subaddr_index.index = mock::gen_subaddress_index();
            selfsend_payment_proposal.proposal.destination_address_spend_pubkey
                = keys.subaddress(selfsend_payment_proposal.subaddr_index).address_spend_pubkey;
            get_output_proposal_internal_v1(selfsend_payment_proposal.proposal,
                keys.s_view_balance_dev,
                mock::gen_key_image(),
                std::nullopt,
                rct_output_enote_proposal);
            break;
        }

        if (push_coinbase)
        {
            output_pair.output_pair.output_pubkey = coinbase_enote.onetime_address;
            output_pair.output_pair.commitment = rct::zeroCommitVartime(coinbase_enote.amount);
            outs.enotes.push_back(coinbase_enote);
            outs.encrypted_payment_ids.push_back(null_payment_id);
        }
        else
        {
            output_pair.output_pair.output_pubkey = rct_output_enote_proposal.enote.onetime_address;
            output_pair.output_pair.commitment = rct_output_enote_proposal.enote.amount_commitment;
            outs.enotes.push_back(rct_output_enote_proposal.enote);
        }

        outs.encrypted_payment_ids.push_back(encrypted_payment_id);
        outs.output_pairs.push_back(output_pair);
    }

    return outs;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
} //namespace
static void subtest_multi_account_transfer_over_transaction(const unittest_transaction_preproposal &tx_preproposal)
{
    // get payment proposals
    std::vector<CarrotPaymentProposalV1> normal_payment_proposals;
    std::vector<CarrotPaymentProposalVerifiableSelfSendV1> selfsend_payment_proposals;
    std::set<size_t> subtractable_normal_payment_proposals;
    std::set<size_t> subtractable_selfsend_payment_proposals;
    tx_preproposal.get_flattened_payment_proposals(normal_payment_proposals,
        selfsend_payment_proposals,
        subtractable_normal_payment_proposals,
        subtractable_selfsend_payment_proposals);

    // get self-sender account
    const mock::mock_carrot_and_legacy_keys &ss_keys =
        tx_preproposal.per_account_payments.at(tx_preproposal.self_sender_index).first;

    // make transaction proposal
    CarrotTransactionProposalV1 tx_proposal;
    make_carrot_transaction_proposal_v1_transfer(normal_payment_proposals,
        selfsend_payment_proposals,
        tx_preproposal.fee_per_weight,
        tx_preproposal.extra_extra,
        make_fake_input_selection_callback(),
        &ss_keys.s_view_balance_dev,
        &ss_keys.k_view_incoming_dev,
        ss_keys.carrot_account_spend_pubkey,
        tx_proposal);

    // make unsigned transaction
    cryptonote::transaction tx;
    make_pruned_transaction_from_carrot_proposal_v1(tx_proposal,
        &ss_keys.s_view_balance_dev,
        &ss_keys.k_view_incoming_dev,
        ss_keys.carrot_account_spend_pubkey,
        tx);

    // calculate acceptable fee margin between proposed amount and actual amount for subtractable outputs
    const size_t num_subtractable = subtractable_normal_payment_proposals.size() +
        subtractable_selfsend_payment_proposals.size();
    const rct::xmr_amount acceptable_fee_margin = num_subtractable
        ? (tx.rct_signatures.txnFee / num_subtractable) + 1
        : 0;

    // load carrot stuff from tx
    std::vector<CarrotEnoteV1> parsed_enotes;
    std::vector<crypto::key_image> parsed_key_images;
    rct::xmr_amount parsed_fee;
    std::optional<encrypted_payment_id_t> parsed_encrypted_payment_id;
    ASSERT_TRUE(try_load_carrot_from_transaction_v1(tx,
        parsed_enotes,
        parsed_key_images,
        parsed_fee,
        parsed_encrypted_payment_id));
    ASSERT_TRUE(parsed_encrypted_payment_id);

    // collect modified selfsend payment proposal cores
    std::vector<CarrotPaymentProposalSelfSendV1> modified_selfsend_payment_proposals;
    for (const auto &p : tx_proposal.selfsend_payment_proposals)
        modified_selfsend_payment_proposals.push_back(p.proposal);

    // sanity check that the enotes and pid_enc loaded from the transaction are equal to the enotes
    // and pic_enc returned from get_output_enote_proposals() when called with the modified payment
    // proposals. we do this so that the modified payment proposals from make_unsigned_transaction()
    // can be passed to a hardware device for deterministic verification of the signable tx hash
    std::vector<RCTOutputEnoteProposal> rederived_output_enote_proposals;
    encrypted_payment_id_t rederived_encrypted_payment_id;
    get_output_enote_proposals(tx_proposal.normal_payment_proposals,
        modified_selfsend_payment_proposals,
        *parsed_encrypted_payment_id,
        &ss_keys.s_view_balance_dev,
        &ss_keys.k_view_incoming_dev,
        ss_keys.carrot_account_spend_pubkey,
        parsed_key_images.at(0),
        rederived_output_enote_proposals,
        rederived_encrypted_payment_id);
    EXPECT_EQ(*parsed_encrypted_payment_id, rederived_encrypted_payment_id);
    ASSERT_EQ(parsed_enotes.size(), rederived_output_enote_proposals.size());
    for (size_t enote_idx = 0; enote_idx < parsed_enotes.size(); ++enote_idx)
    {
        EXPECT_EQ(parsed_enotes.at(enote_idx), rederived_output_enote_proposals.at(enote_idx).enote);
    }

    // collect accounts
    std::vector<const mock::mock_carrot_and_legacy_keys *> accounts;
    for (const auto &pa : tx_preproposal.per_account_payments)
        accounts.push_back(&pa.first);

    // do scanning of all accounts on every enotes
    std::vector<std::vector<mock::mock_scan_result_t>> scan_results;
    unittest_scan_enote_set_multi_account(parsed_enotes,
        *parsed_encrypted_payment_id,
        epee::to_span(accounts),
        scan_results);

    // check that the scan results for each *normal* account match the corresponding payment
    // proposals for each account. also check that the accounts can each open their corresponding
    // onetime outut pubkeys
    ASSERT_EQ(scan_results.size(), accounts.size());
    // for each normal account...
    for (size_t account_idx = 0; account_idx < accounts.size(); ++account_idx)
    {
        // skip self-sender account
        if (account_idx == tx_preproposal.self_sender_index)
            continue;

        const std::vector<mock::mock_scan_result_t> &account_scan_results = scan_results.at(account_idx);
        const auto &account_payment_proposals = tx_preproposal.per_account_payments.at(account_idx).second;
        ASSERT_EQ(account_payment_proposals.size(), account_scan_results.size());
        std::set<size_t> matched_payment_proposals;

        // for each scan result assigned to this account...
        for (const mock::mock_scan_result_t &single_scan_res : account_scan_results)
        {
            // for each normal payment proposal to this account...
            for (size_t norm_prop_idx = 0; norm_prop_idx < account_payment_proposals.size(); ++norm_prop_idx)
            {
                // calculate acceptable loss from fee subtraction
                const CarrotPaymentProposalV1 &account_payment_proposal = account_payment_proposals.at(norm_prop_idx).first;
                const bool is_subtractable = subtractable_normal_payment_proposals.count(norm_prop_idx);
                const rct::xmr_amount acceptable_fee_margin_for_proposal = is_subtractable ? acceptable_fee_margin : 0;

                // if the scan result matches the payment proposal...
                if (compare_scan_result(single_scan_res, account_payment_proposal, acceptable_fee_margin_for_proposal))
                {
                    // try opening Ko
                    const CarrotEnoteV1 &enote =  parsed_enotes.at(single_scan_res.output_index);
                    EXPECT_TRUE(accounts.at(account_idx)->can_open_fcmp_onetime_address(single_scan_res.address_spend_pubkey,
                        single_scan_res.sender_extension_g,
                        single_scan_res.sender_extension_t,
                        enote.onetime_address));

                    // if this payment proposal isn't already marked as scanned, mark as scanned
                    if (!matched_payment_proposals.count(norm_prop_idx))
                    {
                        matched_payment_proposals.insert(norm_prop_idx);
                        break;
                    }
                }
            }
        }
        // check that the number of matched payment proposals is equal to the original number of them
        // doing it this way checks that the same payment proposal isn't marked twice and another left out
        EXPECT_EQ(account_payment_proposals.size(), matched_payment_proposals.size());
    }

    // check that the scan results for the selfsend account match the corresponding payment
    // proposals. also check that the accounts can each open their corresponding onetime outut pubkeys
    const std::vector<mock::mock_scan_result_t> &account_scan_results = scan_results.at(tx_preproposal.self_sender_index);
    ASSERT_EQ(selfsend_payment_proposals.size() + 1, account_scan_results.size());
    std::set<size_t> matched_payment_proposals;
    const mock::mock_scan_result_t* implicit_change_scan_res = nullptr;
    // for each scan result assigned to the self-sender account...
    for (const mock::mock_scan_result_t &single_scan_res : account_scan_results)
    {
        bool matched_payment = false;
        // for each self-send payment proposal...
        for (size_t ss_prop_idx = 0; ss_prop_idx < selfsend_payment_proposals.size(); ++ss_prop_idx)
        {
            // calculate acceptable loss from fee subtraction
            const CarrotPaymentProposalSelfSendV1 &account_payment_proposal = selfsend_payment_proposals.at(ss_prop_idx).proposal;
            const bool is_subtractable = subtractable_selfsend_payment_proposals.count(ss_prop_idx);
            const rct::xmr_amount acceptable_fee_margin_for_proposal = is_subtractable ? acceptable_fee_margin : 0;

            // if the scan result matches the payment proposal...
            if (compare_scan_result(single_scan_res, account_payment_proposal, acceptable_fee_margin_for_proposal))
            {
                // try opening Ko
                const CarrotEnoteV1 &enote = parsed_enotes.at(single_scan_res.output_index);
                EXPECT_TRUE(ss_keys.can_open_fcmp_onetime_address(single_scan_res.address_spend_pubkey,
                    single_scan_res.sender_extension_g,
                    single_scan_res.sender_extension_t,
                    enote.onetime_address));

                // if this payment proposal isn't already marked as scanned, mark as scanned
                if (!matched_payment_proposals.count(ss_prop_idx))
                {
                    matched_payment = true;
                    matched_payment_proposals.insert(ss_prop_idx);
                    break;
                }
            }
        }

        // if this scan result has no matching payment...
        if (!matched_payment)
        {
            EXPECT_EQ(nullptr, implicit_change_scan_res); // only one non-matched scan result is allowed
            implicit_change_scan_res = &single_scan_res; // save the implicit change scan result for later 
        }
    }
    EXPECT_EQ(selfsend_payment_proposals.size(), matched_payment_proposals.size());
    EXPECT_NE(nullptr, implicit_change_scan_res);
    // @TODO: assert properties of `implicit_change_scan_res`
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_1)
{
    // two accounts, both carrot
    // 1/2 tx
    // 1 normal payment to main address
    // 0 explicit selfsend payments

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(2);
    auto &acc0 = tx_proposal.per_account_payments[0].first;
    auto &acc1 = tx_proposal.per_account_payments[1].first;
    acc0.generate();
    acc1.generate();

    // 1 normal payment
    CarrotPaymentProposalV1 &normal_payment_proposal = tools::add_element( tx_proposal.per_account_payments[0].second).first;
    normal_payment_proposal = CarrotPaymentProposalV1{
        .destination = acc0.cryptonote_address(),
        .amount = crypto::rand_idx((rct::xmr_amount) 1ull << 63),
        .randomness = gen_janus_anchor()
    };

    // specify self-sender
    tx_proposal.self_sender_index = 1;

    // specify fee per weight
    tx_proposal.fee_per_weight = 20250510;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_2)
{
    // four accounts, all carrot
    // 1/4 tx
    // 1 normal payment to main address, integrated address, and subaddress each
    // 0 explicit selfsend payments

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate();
    acc1.first.generate();
    acc2.first.generate();
    acc3.first.generate();

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 1 subaddress payment
    tools::add_element(acc0.second).first = CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // 1 main address payment
    tools::add_element(acc1.second).first = CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // 1 integrated address payment
    tools::add_element(acc3.second).first = CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_3)
{
    // four accounts, all carrot
    // 1/6 tx
    // 2 normal payment to main address, 1 integrated address, and 2 subaddress, each copied except integrated
    // 0 explicit selfsend payments

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate();
    acc1.first.generate();
    acc2.first.generate();
    acc3.first.generate();

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 2 subaddress payment
    tools::add_element(acc0.second).first = CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc0.second.push_back(acc0.second.front());
    acc0.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 2 main address payment
    tools::add_element(acc1.second).first = CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc1.second.push_back(acc1.second.front());
    acc1.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 1 integrated address payment
    tools::add_element(acc3.second).first = CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_4)
{
    // four accounts, all carrot
    // 1/8 tx
    // 2 normal payment to main address, 1 integrated address, and 2 subaddress, each copied except integrated
    // 2 explicit selfsend payments: 1 main address destination, 1 subaddress destination

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate();
    acc1.first.generate();
    acc2.first.generate();
    acc3.first.generate();

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 2 subaddress payment
    tools::add_element(acc0.second).first = CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc0.second.push_back(acc0.second.front());
    acc0.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 2 main address payment
    tools::add_element(acc1.second).first = CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc1.second.push_back(acc1.second.front());
    acc1.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 1 integrated address payment
    tools::add_element(acc3.second).first = CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // 1 main address selfsend
    tools::add_element(tx_proposal.explicit_selfsend_proposals).first.proposal = CarrotPaymentProposalSelfSendV1{
        .destination_address_spend_pubkey = acc2.first.carrot_account_spend_pubkey,
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .enote_type = CarrotEnoteType::PAYMENT,
        .internal_message = gen_janus_anchor()
    };

    // 1 subaddress selfsend
    tools::add_element(tx_proposal.explicit_selfsend_proposals).first = CarrotPaymentProposalVerifiableSelfSendV1{
        .proposal = CarrotPaymentProposalSelfSendV1{
            .destination_address_spend_pubkey = acc2.first.subaddress({{4, 19}}).address_spend_pubkey,
            .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
            .enote_type = CarrotEnoteType::CHANGE
        },
        .subaddr_index = {{4, 19}}
    };

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_5)
{
    // two accounts, both legacy
    // 1/2 tx
    // 1 normal payment to main address
    // 0 explicit selfsend payments

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(2);
    auto &acc0 = tx_proposal.per_account_payments[0].first;
    auto &acc1 = tx_proposal.per_account_payments[1].first;
    acc0.generate(AddressDeriveType::PreCarrot);
    acc1.generate(AddressDeriveType::PreCarrot);

    // 1 normal payment
    CarrotPaymentProposalV1 &normal_payment_proposal = tools::add_element( tx_proposal.per_account_payments[0].second).first;
    normal_payment_proposal = CarrotPaymentProposalV1{
        .destination = acc0.cryptonote_address(),
        .amount = crypto::rand_idx((rct::xmr_amount) 1ull << 63),
        .randomness = gen_janus_anchor()
    };

    // specify self-sender
    tx_proposal.self_sender_index = 1;

    // specify fee per weight
    tx_proposal.fee_per_weight = 20250510;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_6)
{
    // four accounts, all legacy
    // 1/4 tx
    // 1 normal payment to main address, integrated address, and subaddress each
    // 0 explicit selfsend payments

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate();
    acc1.first.generate();
    acc2.first.generate();
    acc3.first.generate();

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 1 subaddress payment
    tools::add_element(acc0.second).first = CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // 1 main address payment
    tools::add_element(acc1.second).first = CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // 1 integrated address payment
    tools::add_element(acc3.second).first = CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_7)
{
    // four accounts, all legacy
    // 1/6 tx
    // 2 normal payment to main address, 1 integrated address, and 2 subaddress, each copied except integrated
    // 0 explicit selfsend payments

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate(AddressDeriveType::PreCarrot);
    acc1.first.generate(AddressDeriveType::PreCarrot);
    acc2.first.generate(AddressDeriveType::PreCarrot);
    acc3.first.generate(AddressDeriveType::PreCarrot);

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 2 subaddress payment
    tools::add_element(acc0.second).first = CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc0.second.push_back(acc0.second.front());
    acc0.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 2 main address payment
    tools::add_element(acc1.second).first = CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc1.second.push_back(acc1.second.front());
    acc1.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 1 integrated address payment
    tools::add_element(acc3.second).first = CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_8)
{
    // four accounts, all legacy
    // 1/8 tx
    // 2 normal payment to main address, 1 integrated address, and 2 subaddress, each copied except integrated
    // 2 explicit selfsend payments: 1 main address destination, 1 subaddress destination

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate(AddressDeriveType::PreCarrot);
    acc1.first.generate(AddressDeriveType::PreCarrot);
    acc2.first.generate(AddressDeriveType::PreCarrot);
    acc3.first.generate(AddressDeriveType::PreCarrot);

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 2 subaddress payment
    tools::add_element(acc0.second).first = CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc0.second.push_back(acc0.second.front());
    acc0.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 2 main address payment
    tools::add_element(acc1.second).first = CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc1.second.push_back(acc1.second.front());
    acc1.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 1 integrated address payment
    tools::add_element(acc3.second).first = CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // 1 main address selfsend
    tools::add_element(tx_proposal.explicit_selfsend_proposals).first.proposal = CarrotPaymentProposalSelfSendV1{
        .destination_address_spend_pubkey = acc2.first.carrot_account_spend_pubkey,
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .enote_type = CarrotEnoteType::PAYMENT,
        // no internal messages for legacy self-sends
    };

    // 1 subaddress selfsend
    tools::add_element(tx_proposal.explicit_selfsend_proposals).first = CarrotPaymentProposalVerifiableSelfSendV1{
        .proposal = CarrotPaymentProposalSelfSendV1{
            .destination_address_spend_pubkey = acc2.first.subaddress({{4, 19}}).address_spend_pubkey,
            .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
            .enote_type = CarrotEnoteType::CHANGE
        },
        .subaddr_index = {4, 19}
    };

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_9)
{
    // two accounts, both carrot
    // 1/2 tx
    // 1 normal payment to main address
    // 0 explicit selfsend payments
    // subtractable

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(2);
    auto &acc0 = tx_proposal.per_account_payments[0].first;
    auto &acc1 = tx_proposal.per_account_payments[1].first;
    acc0.generate();
    acc1.generate();

    // 1 normal payment (subtractable)
    CarrotPaymentProposalV1 &normal_payment_proposal = tools::add_element( tx_proposal.per_account_payments[0].second).first;
    normal_payment_proposal = CarrotPaymentProposalV1{
        .destination = acc0.cryptonote_address(),
        .amount = crypto::rand_idx((rct::xmr_amount) 1ull << 63),
        .randomness = gen_janus_anchor()
    };
    tx_proposal.per_account_payments[0].second.back().second = true;

    // specify self-sender
    tx_proposal.self_sender_index = 1;

    // specify fee per weight
    tx_proposal.fee_per_weight = 20250510;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_10)
{
    // four accounts, all carrot
    // 1/4 tx
    // 1 normal payment to main address, integrated address, and subaddress each
    // 0 explicit selfsend payments
    // subaddress and integrated address are subtractable

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate();
    acc1.first.generate();
    acc2.first.generate();
    acc3.first.generate();

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 1 subaddress payment (subtractable)
    tools::add_element(acc0.second) = {CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};

    // 1 main address payment
    tools::add_element(acc1.second).first = CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // 1 integrated address payment
    tools::add_element(acc3.second) = {CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_11)
{
    // four accounts, all carrot
    // 1/6 tx
    // 2 normal payment to main address, 1 integrated address, and 2 subaddress, each copied except integrated
    // 0 explicit selfsend payments
    // 1 main and 1 subaddress is subtractable

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate();
    acc1.first.generate();
    acc2.first.generate();
    acc3.first.generate();

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 2 subaddress payment
    tools::add_element(acc0.second).first = CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc0.second.push_back(acc0.second.front());
    acc0.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm
    acc0.second.back().second = true;                         //set copy as subtractable

    // 2 main address payment
    tools::add_element(acc1.second).first = CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc1.second.push_back(acc1.second.front());
    acc1.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm
    acc1.second.back().second = true;                         //set copy as subtractable

    // 1 integrated address payment
    tools::add_element(acc3.second).first = CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_12)
{
    // four accounts, all carrot
    // 1/8 tx
    // 2 normal payment to main address, 1 integrated address, and 2 subaddress, each copied except integrated
    // 2 explicit selfsend payments: 1 main address destination, 1 subaddress destination
    // 1 normal main address, 1 integrated, and 1 self-send subaddress is subtractable

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate();
    acc1.first.generate();
    acc2.first.generate();
    acc3.first.generate();

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 2 subaddress payment (1 subtractable)
    tools::add_element(acc0.second) = {CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};
    acc0.second.push_back(acc0.second.front());
    acc0.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm
    acc0.second.back().second = false;                        //set not subtractable, first already is

    // 2 main address payment
    tools::add_element(acc1.second).first = CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };
    acc1.second.push_back(acc1.second.front());
    acc1.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 1 integrated address payment (subtractable)
    tools::add_element(acc3.second) = {CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};

    // 1 main address selfsend
    tools::add_element(tx_proposal.explicit_selfsend_proposals).first.proposal = CarrotPaymentProposalSelfSendV1{
        .destination_address_spend_pubkey = acc2.first.carrot_account_spend_pubkey,
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .enote_type = CarrotEnoteType::PAYMENT,
        .internal_message = gen_janus_anchor()
    };

    // 1 subaddress selfsend (subtractable)
    tools::add_element(tx_proposal.explicit_selfsend_proposals) = {CarrotPaymentProposalVerifiableSelfSendV1{
        .proposal = CarrotPaymentProposalSelfSendV1{
            .destination_address_spend_pubkey = acc2.first.subaddress({{4, 19}}).address_spend_pubkey,
            .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
            .enote_type = CarrotEnoteType::CHANGE
        },
        .subaddr_index = {4, 19}
    }, true};

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_13)
{
    // two accounts, both legacy
    // 1/2 tx
    // 1 normal payment to main address
    // 0 explicit selfsend payments
    // subtractable

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(2);
    auto &acc0 = tx_proposal.per_account_payments[0].first;
    auto &acc1 = tx_proposal.per_account_payments[1].first;
    acc0.generate(AddressDeriveType::PreCarrot);
    acc1.generate(AddressDeriveType::PreCarrot);

    // 1 normal payment (subtractable)
    CarrotPaymentProposalV1 &normal_payment_proposal = tools::add_element( tx_proposal.per_account_payments[0].second).first;
    normal_payment_proposal = CarrotPaymentProposalV1{
        .destination = acc0.cryptonote_address(),
        .amount = crypto::rand_idx((rct::xmr_amount) 1ull << 63),
        .randomness = gen_janus_anchor()
    };
    tx_proposal.per_account_payments[0].second.back().second = true;

    // specify self-sender
    tx_proposal.self_sender_index = 1;

    // specify fee per weight
    tx_proposal.fee_per_weight = 20250510;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_14)
{
    // four accounts, all legacy
    // 1/4 tx
    // 1 normal payment to main address, integrated address, and subaddress each
    // 0 explicit selfsend payments
    // 1 integrated and 1 subaddress subtractable

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate(AddressDeriveType::PreCarrot);
    acc1.first.generate(AddressDeriveType::PreCarrot);
    acc2.first.generate(AddressDeriveType::PreCarrot);
    acc3.first.generate(AddressDeriveType::PreCarrot);

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 1 subaddress payment (subtractable)
    tools::add_element(acc0.second) = {CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};

    // 1 main address payment
    tools::add_element(acc1.second).first = CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    };

    // 1 integrated address payment (subtractable)
    tools::add_element(acc3.second) = {CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_15)
{
    // four accounts, all legacy
    // 1/6 tx
    // 2 normal payment to main address, 1 integrated address, and 2 subaddress, each copied except integrated
    // 0 explicit selfsend payments
    // all subtractable

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate(AddressDeriveType::PreCarrot);
    acc1.first.generate(AddressDeriveType::PreCarrot);
    acc2.first.generate(AddressDeriveType::PreCarrot);
    acc3.first.generate(AddressDeriveType::PreCarrot);

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 2 subaddress payment (subtractable)
    tools::add_element(acc0.second) = {CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};
    acc0.second.push_back(acc0.second.front());
    acc0.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 2 main address payment (subtractable)
    tools::add_element(acc1.second) = {CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};
    acc1.second.push_back(acc1.second.front());
    acc1.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 1 integrated address payment (subtractable)
    tools::add_element(acc3.second) = {CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, multi_account_transfer_over_transaction_16)
{
    // four accounts, all legacy
    // 1/8 tx
    // 2 normal payment to main address, 1 integrated address, and 2 subaddress, each copied except integrated
    // 2 explicit selfsend payments: 1 main address destination, 1 subaddress destination
    // all subtractable

    unittest_transaction_preproposal tx_proposal;
    tx_proposal.per_account_payments = std::vector<unittest_transaction_preproposal::per_account>(4);
    auto &acc0 = tx_proposal.per_account_payments[0];
    auto &acc1 = tx_proposal.per_account_payments[1];
    auto &acc2 = tx_proposal.per_account_payments[2];
    auto &acc3 = tx_proposal.per_account_payments[3];
    acc0.first.generate(AddressDeriveType::PreCarrot);
    acc1.first.generate(AddressDeriveType::PreCarrot);
    acc2.first.generate(AddressDeriveType::PreCarrot);
    acc3.first.generate(AddressDeriveType::PreCarrot);

    // specify self-sender
    tx_proposal.self_sender_index = 2;

    // 2 subaddress payment (subtractable)
    tools::add_element(acc0.second) = {CarrotPaymentProposalV1{
        .destination = acc0.first.subaddress({{2, 3}}),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};
    acc0.second.push_back(acc0.second.front());
    acc0.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 2 main address payment (subtractable)
    tools::add_element(acc1.second) = {CarrotPaymentProposalV1{
        .destination = acc1.first.cryptonote_address(),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};
    acc1.second.push_back(acc1.second.front());
    acc1.second.back().first.randomness = gen_janus_anchor(); //mangle anchor_norm

    // 1 integrated address payment (subtractable)
    tools::add_element(acc3.second) = {CarrotPaymentProposalV1{
        .destination = acc3.first.cryptonote_address(gen_payment_id()),
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .randomness = gen_janus_anchor()
    }, true};

    // 1 main address selfsend (subtractable)
    tools::add_element(tx_proposal.explicit_selfsend_proposals) = {{CarrotPaymentProposalSelfSendV1{
        .destination_address_spend_pubkey = acc2.first.carrot_account_spend_pubkey,
        .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
        .enote_type = CarrotEnoteType::PAYMENT,
        // no internal messages for legacy self-sends
    }}, true};

    // 1 subaddress selfsend (subtractable)
    tools::add_element(tx_proposal.explicit_selfsend_proposals) = {CarrotPaymentProposalVerifiableSelfSendV1{
        .proposal = CarrotPaymentProposalSelfSendV1{
            .destination_address_spend_pubkey = acc2.first.subaddress({{4, 19}}).address_spend_pubkey,
            .amount = crypto::rand_idx<rct::xmr_amount>(1000000),
            .enote_type = CarrotEnoteType::CHANGE
        },
        .subaddr_index = {4, 19}
    }, true};

    // specify fee per weight
    tx_proposal.fee_per_weight = 314159;

    // test
    subtest_multi_account_transfer_over_transaction(tx_proposal);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, make_single_transfer_input_selector_TwoInputsPreferOldest_1)
{
    const std::vector<CarrotPreSelectedInput> input_candidates = {
        CarrotPreSelectedInput {
            .core = CarrotSelectedInput {
                .amount = 500,
                .key_image = mock::gen_key_image(),
            },
            .is_external = false,
            .block_index = 72
        },
        CarrotPreSelectedInput {
            .core = CarrotSelectedInput {
                .amount = 200,
                .key_image = mock::gen_key_image(),
            },
            .is_external = false,
            .block_index = 34
        }
    };

    const std::vector<InputSelectionPolicy> policies = { InputSelectionPolicy::TwoInputsPreferOldest };

    const uint32_t flags = 0;

    std::set<size_t> selected_input_indices;
    select_inputs_func_t input_selector = make_single_transfer_input_selector(epee::to_span(input_candidates),
        epee::to_span(policies),
        flags,
        &selected_input_indices);
    
    boost::multiprecision::int128_t nominal_output_sum = 369;

    const std::map<size_t, rct::xmr_amount> fee_by_input_count = {
        {1, 50},
        {2, 75}
    };

    const size_t num_normal_payment_proposals = 1;
    const size_t num_selfsend_payment_proposals = 1;

    ASSERT_GT(input_candidates[0].core.amount, nominal_output_sum + fee_by_input_count.crbegin()->second);

    std::vector<CarrotSelectedInput> selected_inputs;
    input_selector(nominal_output_sum,
        fee_by_input_count,
        num_normal_payment_proposals,
        num_selfsend_payment_proposals,
        selected_inputs);

    ASSERT_EQ(2, input_candidates.size());
    ASSERT_EQ(2, selected_inputs.size());
    EXPECT_NE(input_candidates.at(0).core, input_candidates.at(1).core);
    EXPECT_NE(selected_inputs.at(0), selected_inputs.at(1));
    EXPECT_TRUE((selected_inputs.at(0) == input_candidates.at(0).core) ^ (selected_inputs.at(0) == input_candidates[1].core));
    EXPECT_TRUE((selected_inputs.at(1) == input_candidates.at(0).core) ^ (selected_inputs.at(1) == input_candidates.at(1).core));
}
//----------------------------------------------------------------------------------------------------------------------
TEST(carrot_impl, receive_scan_spend_and_verify_serialized_carrot_tx)
{
    // In this test we:
    // 1. Populate a curve tree with Carrot-derived enotes to Alice
    // 2. Scan those enotes and construct a transfer-style tx to Bob
    // 3. Serialize that tx, then deserialize it
    // 4. Verify non-input consensus rules on the deserialized tx
    // 5. Verify FCMP membership in the curve tree on the deserialized tx
    // 6. Scan the deserialized tx to Bob

    mock::mock_carrot_and_legacy_keys alice;
    mock::mock_carrot_and_legacy_keys bob;
    alice.generate();
    bob.generate();

    const size_t n_inputs = crypto::rand_range<size_t>(CARROT_MIN_TX_INPUTS, FCMP_PLUS_PLUS_MAX_INPUTS);
    const size_t n_outputs = crypto::rand_range<size_t>(CARROT_MIN_TX_OUTPUTS, FCMP_PLUS_PLUS_MAX_OUTPUTS);

    const std::size_t selene_chunk_width = fcmp_pp::curve_trees::SELENE_CHUNK_WIDTH;
    const std::size_t helios_chunk_width = fcmp_pp::curve_trees::HELIOS_CHUNK_WIDTH;
    const std::size_t tree_depth = 3;
    const std::size_t n_tree_layers = tree_depth + 1;
    const size_t expected_num_selene_branch_blinds = (tree_depth + 1) / 2;
    const size_t expected_num_helios_branch_blinds = tree_depth / 2;

    LOG_PRINT_L1("Test carrot_impl.receive_scan_spend_and_verify_serialized_carrot_tx with selene chunk width "
        << selene_chunk_width << ", helios chunk width " << helios_chunk_width << ", tree depth " << tree_depth
        << ", number of inputs " << n_inputs << ", number of outputs " << n_outputs);

    // Tree params
    uint64_t min_leaves_needed_for_tree_depth = 0;
    const auto curve_trees = test::init_curve_trees_test(selene_chunk_width,
        helios_chunk_width,
        tree_depth,
        min_leaves_needed_for_tree_depth);

    // Generate enotes...
    LOG_PRINT_L1("Generating carrot-derived enotes to Alice");
    const auto new_outputs = generate_random_carrot_outputs(alice,
        0,
        min_leaves_needed_for_tree_depth
      );
    ASSERT_GT(min_leaves_needed_for_tree_depth, n_inputs);

    // generate output ids to use as inputs...
    std::set<size_t> picked_output_ids_set;
    while (picked_output_ids_set.size() < n_inputs)
        picked_output_ids_set.insert(crypto::rand_idx(min_leaves_needed_for_tree_depth));
    std::vector<size_t> picked_output_ids(picked_output_ids_set.cbegin(), picked_output_ids_set.cend());
    std::shuffle(picked_output_ids.begin(), picked_output_ids.end(), crypto::random_device{});

    // scan inputs and make key images and opening hints...
    //                                a                  z       C_a           K_o                opening hint          output id
    using input_info_t = std::tuple<rct::xmr_amount, rct::key, rct::key, crypto::public_key, OutputOpeningHintVariant, std::uint64_t>;
    LOG_PRINT_L1("Alice scanning inputs");
    std::unordered_map<crypto::key_image, input_info_t> input_info_by_ki;
    rct::xmr_amount input_amount_sum = 0;
    for (const size_t picked_output_id : picked_output_ids)
    {
        // find index into new_outputs based on picked_output_id
        size_t new_outputs_idx;
        for (new_outputs_idx = 0; new_outputs_idx < new_outputs.output_pairs.size(); ++new_outputs_idx)
        {
            if (new_outputs.output_pairs.at(new_outputs_idx).output_id == picked_output_id)
                break;
        }
        ASSERT_LT(new_outputs_idx, new_outputs.enotes.size());

        // compile information about this enote
        const CarrotEnoteVariant &enote_v = new_outputs.enotes.at(new_outputs_idx);
        OutputOpeningHintVariant opening_hint;
        std::vector<mock::mock_scan_result_t> scan_results;
        if (enote_v.is_type<CarrotEnoteV1>())
        {
            const CarrotEnoteV1 &enote = enote_v.unwrap<CarrotEnoteV1>();
            const encrypted_payment_id_t encrypted_payment_id = new_outputs.encrypted_payment_ids.at(new_outputs_idx);
            mock::mock_scan_enote_set({enote},
                encrypted_payment_id,
                alice,
                scan_results);
            ASSERT_EQ(1, scan_results.size());
            const mock::mock_scan_result_t &scan_result = scan_results.front();
            const auto subaddr_it = alice.subaddress_map.find(scan_result.address_spend_pubkey);
            ASSERT_NE(alice.subaddress_map.cend(), subaddr_it);
            opening_hint = CarrotOutputOpeningHintV1{
                .source_enote = enote,
                .encrypted_payment_id = encrypted_payment_id,
                .subaddr_index = subaddr_it->second
            };
        }
        else // is coinbase
        {
            const CarrotCoinbaseEnoteV1 &enote = enote_v.unwrap<CarrotCoinbaseEnoteV1>();
            mock::mock_scan_coinbase_enote_set({enote},
                alice,
                scan_results);
            ASSERT_EQ(1, scan_results.size());
            const mock::mock_scan_result_t &scan_result = scan_results.front();
            ASSERT_EQ(alice.cryptonote_address().address_spend_pubkey, scan_result.address_spend_pubkey);
            opening_hint = CarrotCoinbaseOutputOpeningHintV1{
                .source_enote = enote,
                .derive_type = AddressDeriveType::Carrot
            };
        }
        ASSERT_EQ(1, scan_results.size());
        const mock::mock_scan_result_t &scan_result = scan_results.front();
        const fcmp_pp::curve_trees::OutputPair &output_pair = new_outputs.output_pairs.at(new_outputs_idx).output_pair;
        const crypto::key_image ki = alice.derive_key_image(scan_result.address_spend_pubkey,
            scan_result.sender_extension_g,
            scan_result.sender_extension_t,
            output_pair.output_pubkey);

        ASSERT_EQ(0, input_info_by_ki.count(ki));

        input_info_by_ki[ki] = {scan_result.amount,
            rct::sk2rct(scan_result.amount_blinding_factor),
            output_pair.commitment,
            output_pair.output_pubkey,
            opening_hint,
            new_outputs.output_pairs.at(new_outputs_idx).output_id};
        input_amount_sum += scan_result.amount;
    }

    // generate n_outputs-1 payment proposals to bob ...
    LOG_PRINT_L1("Generating payment proposals to Bob");
    rct::xmr_amount output_amount_remaining = rct::randXmrAmount(input_amount_sum);
    std::vector<CarrotPaymentProposalV1> bob_payment_proposals;
    for (size_t i = 0; i < n_outputs - 1; ++i)
    {
        const bool use_subaddress = i % 2 == 1;
        const CarrotDestinationV1 addr = use_subaddress ?
            bob.subaddress({mock::gen_subaddress_index()}) :
            bob.cryptonote_address();
        const rct::xmr_amount amount = rct::randXmrAmount(output_amount_remaining);
        bob_payment_proposals.push_back(CarrotPaymentProposalV1{
            .destination = addr,
            .amount = amount,
            .randomness = gen_janus_anchor()
        });
        output_amount_remaining -= amount;
    }

    // make a transfer-type tx proposal
    // @TODO: this can fail sporadically if fee exceeds remaining funds
    LOG_PRINT_L1("Creating transaction proposal");
    const rct::xmr_amount fee_per_weight = 1;
    CarrotTransactionProposalV1 tx_proposal;
    make_carrot_transaction_proposal_v1_transfer(bob_payment_proposals,
        /*selfsend_payment_proposals=*/{},
        fee_per_weight,
        /*extra=*/{},
        [&input_info_by_ki]
        (
            const boost::multiprecision::int128_t&,
            const std::map<std::size_t, rct::xmr_amount>&,
            const std::size_t,
            const std::size_t,
            std::vector<CarrotSelectedInput>& key_images_out)
        {
            key_images_out.clear();
            key_images_out.reserve(input_info_by_ki.size());
            for (const auto &info : input_info_by_ki)
            {
                key_images_out.push_back(CarrotSelectedInput{
                    .amount = std::get<0>(info.second),
                    .key_image = info.first
                });
            }
        },
        &alice.s_view_balance_dev,
        &alice.k_view_incoming_dev,
        alice.carrot_account_spend_pubkey,
        tx_proposal);

    ASSERT_EQ(n_outputs, tx_proposal.normal_payment_proposals.size() + tx_proposal.selfsend_payment_proposals.size());

    // collect core selfsend proposals
    std::vector<CarrotPaymentProposalSelfSendV1> selfsend_payment_proposal_cores;
    for (const CarrotPaymentProposalVerifiableSelfSendV1 &selfsend_payment_proposal : tx_proposal.selfsend_payment_proposals)
        selfsend_payment_proposal_cores.push_back(selfsend_payment_proposal.proposal);

    // derive output enote set
    LOG_PRINT_L1("Deriving enotes");
    std::vector<RCTOutputEnoteProposal> output_enote_proposals;
    encrypted_payment_id_t encrypted_payment_id;
    get_output_enote_proposals(tx_proposal.normal_payment_proposals,
        selfsend_payment_proposal_cores,
        tx_proposal.dummy_encrypted_payment_id,
        &alice.s_view_balance_dev,
        &alice.k_view_incoming_dev,
        alice.carrot_account_spend_pubkey,
        tx_proposal.key_images_sorted.at(0),
        output_enote_proposals,
        encrypted_payment_id);

    // Collect balance info and enotes
    std::vector<crypto::public_key> input_onetime_addresses;
    std::vector<rct::key> input_amount_commitments;
    std::vector<rct::key> input_amount_blinding_factors;
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<rct::key> output_amount_blinding_factors;
    std::vector<CarrotEnoteV1> output_enotes;
    for (size_t i = 0; i < n_inputs; ++i)
    {
        const input_info_t &input_info = input_info_by_ki.at(tx_proposal.key_images_sorted.at(i));
        input_onetime_addresses.push_back(std::get<3>(input_info));
        input_amount_commitments.push_back(std::get<2>(input_info));
        input_amount_blinding_factors.push_back(std::get<1>(input_info));
    }
    for (const RCTOutputEnoteProposal &output_enote_proposal : output_enote_proposals)
    {
        output_amounts.push_back(output_enote_proposal.amount);
        output_amount_blinding_factors.push_back(rct::sk2rct(output_enote_proposal.amount_blinding_factor));
        output_enotes.push_back(output_enote_proposal.enote);
    }

    // make pruned tx
    LOG_PRINT_L1("Storing carrot to transaction");
    cryptonote::transaction tx = store_carrot_to_transaction_v1(output_enotes,
        tx_proposal.key_images_sorted,
        tx_proposal.fee,
        encrypted_payment_id);

    ASSERT_EQ(2, tx.version);
    ASSERT_EQ(0, tx.unlock_time);
    ASSERT_EQ(n_inputs, tx.vin.size());
    ASSERT_EQ(n_outputs, tx.vout.size());
    ASSERT_EQ(n_outputs, tx.rct_signatures.outPk.size());

    // Generate bulletproof+
    LOG_PRINT_L1("Generating Bulletproof+");
    tx.rct_signatures.p.bulletproofs_plus.push_back(rct::bulletproof_plus_PROVE(output_amounts, output_amount_blinding_factors));
    ASSERT_EQ(n_outputs, tx.rct_signatures.p.bulletproofs_plus.at(0).V.size());

    // expand tx and calculate signable tx hash
    LOG_PRINT_L1("Calculating signable tx hash");
    hw::device &hwdev = hw::get_device("default");
    ASSERT_TRUE(cryptonote::expand_transaction_1(tx, /*base_only=*/false));
    const crypto::hash tx_prefix_hash = cryptonote::get_transaction_prefix_hash(tx);
    tx.rct_signatures.message = rct::hash2rct(tx_prefix_hash);
    tx.rct_signatures.p.pseudoOuts.resize(n_inputs); // @TODO: make this not necessary to call get_mlsag_hash
    const crypto::hash signable_tx_hash = rct::rct2hash(rct::get_pre_mlsag_hash(tx.rct_signatures, hwdev));

    // rerandomize inputs
    LOG_PRINT_L1("Making rerandomized inputs");
    std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs;
    make_carrot_rerandomized_outputs_nonrefundable(input_onetime_addresses,
        input_amount_commitments,
        input_amount_blinding_factors,
        output_amount_blinding_factors,
        rerandomized_outputs);

    // Make SA/L proofs
    LOG_PRINT_L1("Generating FCMP++ SA/L proofs");
    std::vector<crypto::key_image> actual_key_images;
    std::vector<fcmp_pp::FcmpPpSalProof> sal_proofs;
    for (size_t i = 0; i < n_inputs; ++i)
    {
        const CarrotOpenableRerandomizedOutputV1 openable_opening_hint{
            .rerandomized_output = rerandomized_outputs.at(i),
            .opening_hint = std::get<4>(input_info_by_ki.at(tx_proposal.key_images_sorted.at(i)))
        };

        make_sal_proof_any_to_carrot_v1(signable_tx_hash,
            openable_opening_hint,
            alice.k_prove_spend,
            alice.k_generate_image,
            alice.s_view_balance_dev,
            alice.k_view_incoming_dev,
            alice.s_generate_address_dev,
            tools::add_element(sal_proofs),
            tools::add_element(actual_key_images));
    }

    // Init tree in memory
    LOG_PRINT_L1("Initializing tree with " << min_leaves_needed_for_tree_depth << " leaves");
    CurveTreesGlobalTree global_tree(*curve_trees);
    ASSERT_TRUE(global_tree.grow_tree(0, min_leaves_needed_for_tree_depth, new_outputs.output_pairs));
    LOG_PRINT_L1("Finished initializing tree with " << min_leaves_needed_for_tree_depth << " leaves");

    // Make FCMP paths
    LOG_PRINT_L1("Calculating FCMP paths");
    std::vector<fcmp_pp::ProofInput> fcmp_proof_inputs(n_inputs);
    for (size_t i = 0; i < n_inputs; ++i)
    {
        const size_t leaf_idx = std::get<5>(input_info_by_ki.at(tx_proposal.key_images_sorted.at(i)));
        const auto path = global_tree.get_path_at_leaf_idx(leaf_idx);
        const std::size_t path_leaf_idx = leaf_idx % curve_trees->m_c1_width;

        const fcmp_pp::curve_trees::OutputPair output_pair = {rct::rct2pk(path.leaves[path_leaf_idx].O),
            path.leaves[path_leaf_idx].C};
        const auto output_tuple = fcmp_pp::curve_trees::output_to_tuple(output_pair);

        const auto path_for_proof = curve_trees->path_for_proof(path, output_tuple);

        const auto helios_scalar_chunks = fcmp_pp::tower_cycle::scalar_chunks_to_chunk_vector<fcmp_pp::HeliosT>(
            path_for_proof.c2_scalar_chunks);
        const auto selene_scalar_chunks = fcmp_pp::tower_cycle::scalar_chunks_to_chunk_vector<fcmp_pp::SeleneT>(
            path_for_proof.c1_scalar_chunks);

        const auto path_rust = fcmp_pp::path_new({path_for_proof.leaves.data(), path_for_proof.leaves.size()},
            path_for_proof.output_idx,
            {helios_scalar_chunks.data(), helios_scalar_chunks.size()},
            {selene_scalar_chunks.data(), selene_scalar_chunks.size()});

        fcmp_proof_inputs[i].path = path_rust;
    }

    // make FCMP blinds
    LOG_PRINT_L1("Calculating branch and output blinds");
    for (size_t i = 0; i < n_inputs; ++i)
    {
        fcmp_pp::ProofInput &proof_input = fcmp_proof_inputs[i];
        const FcmpRerandomizedOutputCompressed &rerandomized_output = rerandomized_outputs.at(i);

        // calculate individual blinds
        uint8_t *blinded_o_blind = fcmp_pp::blind_o_blind(fcmp_pp::o_blind(rerandomized_output));
        uint8_t *blinded_i_blind = fcmp_pp::blind_i_blind(fcmp_pp::i_blind(rerandomized_output));
        uint8_t *blinded_i_blind_blind = fcmp_pp::blind_i_blind_blind(fcmp_pp::i_blind_blind(rerandomized_output));
        uint8_t *blinded_c_blind = fcmp_pp::blind_c_blind(fcmp_pp::c_blind(rerandomized_output));

        // make output blinds
        proof_input.output_blinds = fcmp_pp::output_blinds_new(
            blinded_o_blind, blinded_i_blind, blinded_i_blind_blind, blinded_c_blind);

        // generate selene blinds
        proof_input.selene_branch_blinds.reserve(expected_num_selene_branch_blinds);
        for (size_t j = 0; j < expected_num_selene_branch_blinds; ++j)
            proof_input.selene_branch_blinds.push_back(fcmp_pp::selene_branch_blind());

        // generate helios blinds
        proof_input.helios_branch_blinds.reserve(expected_num_helios_branch_blinds);
        for (size_t j = 0; j < expected_num_helios_branch_blinds; ++j)
            proof_input.helios_branch_blinds.push_back(fcmp_pp::helios_branch_blind());

        // dealloc individual blinds
        free(blinded_o_blind);
        free(blinded_i_blind);
        free(blinded_i_blind_blind);
        free(blinded_c_blind);
    }

    // Make FCMP membership proof
    LOG_PRINT_L1("Generating FCMP++ membership proofs");
    std::vector<const uint8_t*> fcmp_proof_inputs_rust;
    for (size_t i = 0; i < n_inputs; ++i)
    {
        fcmp_pp::ProofInput &proof_input = fcmp_proof_inputs.at(i);
        fcmp_proof_inputs_rust.push_back(fcmp_pp::fcmp_prove_input_new(
            rerandomized_outputs.at(i),
            proof_input.path,
            proof_input.output_blinds,
            proof_input.selene_branch_blinds,
            proof_input.helios_branch_blinds));
        free(proof_input.path);
        free(proof_input.output_blinds);
        for (const uint8_t *branch_blind : proof_input.selene_branch_blinds)
            free(const_cast<uint8_t*>(branch_blind));
        for (const uint8_t *branch_blind : proof_input.helios_branch_blinds)
            free(const_cast<uint8_t*>(branch_blind));
    }
    const fcmp_pp::FcmpMembershipProof membership_proof = fcmp_pp::prove_membership(fcmp_proof_inputs_rust,
        n_tree_layers);

    // Dealloc FCMP proof inputs
    for (const uint8_t *proof_input : fcmp_proof_inputs_rust)
      free(const_cast<uint8_t*>(proof_input));

    // Attach rctSigPrunable to tx
    LOG_PRINT_L1("Storing rctSig prunable");
    const std::uint64_t fcmp_block_reference_index = mock::gen_block_index();
    tx.rct_signatures.p = store_fcmp_proofs_to_rct_prunable_v1(std::move(tx.rct_signatures.p.bulletproofs_plus),
        rerandomized_outputs,
        sal_proofs,
        membership_proof,
        fcmp_block_reference_index,
        n_tree_layers);
    tx.pruned = false;

    // Serialize tx to bytes
    LOG_PRINT_L1("Serializing & deserializing transaction");
    const cryptonote::blobdata tx_blob = cryptonote::tx_to_blob(tx);

    // Deserialize tx
    cryptonote::transaction deserialized_tx;
    ASSERT_TRUE(cryptonote::parse_and_validate_tx_from_blob(tx_blob, deserialized_tx));

    // Expand tx
    auto tree_root = global_tree.get_tree_root();
    const crypto::hash tx_prefix_hash_2 = cryptonote::get_transaction_prefix_hash(deserialized_tx);
    ASSERT_TRUE(cryptonote::Blockchain::expand_transaction_2(deserialized_tx, tx_prefix_hash_2, {}, tree_root));

    // Verify non-input consensus rules on tx
    LOG_PRINT_L1("Verifying non-input consensus rules");
    cryptonote::tx_verification_context tvc{};
    ASSERT_TRUE(cryptonote::ver_non_input_consensus(deserialized_tx, tvc, HF_VERSION_FCMP_PLUS_PLUS));
    ASSERT_FALSE(tvc.m_verifivation_failed);
    ASSERT_FALSE(tvc.m_verifivation_impossible);
    ASSERT_FALSE(tvc.m_added_to_pool);
    ASSERT_FALSE(tvc.m_low_mixin);
    ASSERT_FALSE(tvc.m_double_spend);
    ASSERT_FALSE(tvc.m_invalid_input);
    ASSERT_FALSE(tvc.m_invalid_output);
    ASSERT_FALSE(tvc.m_too_big);
    ASSERT_FALSE(tvc.m_overspend);
    ASSERT_FALSE(tvc.m_fee_too_low);
    ASSERT_FALSE(tvc.m_too_few_outputs);
    ASSERT_FALSE(tvc.m_tx_extra_too_big);
    ASSERT_FALSE(tvc.m_nonzero_unlock_time);

    // Recalculate signable tx hash from deserialized tx and check
    const crypto::hash signable_tx_hash_2 = rct::rct2hash(rct::get_pre_mlsag_hash(deserialized_tx.rct_signatures, hwdev));
    ASSERT_EQ(signable_tx_hash, signable_tx_hash_2);

    // Pre-verify SAL proofs
    LOG_PRINT_L1("Verify SA/L proofs");
    ASSERT_EQ(deserialized_tx.vin.size(), n_inputs);
    ASSERT_EQ(deserialized_tx.vin.size(), deserialized_tx.rct_signatures.p.fcmp_ver_helper_data.key_images.size());
    ASSERT_EQ(deserialized_tx.vin.size(), deserialized_tx.rct_signatures.p.pseudoOuts.size());
    ASSERT_GT(deserialized_tx.rct_signatures.p.fcmp_pp.size(), (3*32 + FCMP_PP_SAL_PROOF_SIZE_V1) * n_inputs);
    for (size_t i = 0; i < n_inputs; ++i)
    {
        const uint8_t * const pbytes = deserialized_tx.rct_signatures.p.fcmp_pp.data() +
            (3*32 + FCMP_PP_SAL_PROOF_SIZE_V1) * i;
        FcmpInputCompressed input;
        fcmp_pp::FcmpPpSalProof sal_proof(FCMP_PP_SAL_PROOF_SIZE_V1);
        memcpy(&input, pbytes, 3*32);
        memcpy(&sal_proof[0], pbytes + 3*32, FCMP_PP_SAL_PROOF_SIZE_V1);
        memcpy(input.C_tilde, deserialized_tx.rct_signatures.p.pseudoOuts.at(i).bytes, 32);
        const crypto::key_image &ki = deserialized_tx.rct_signatures.p.fcmp_ver_helper_data.key_images.at(i);
        ASSERT_TRUE(fcmp_pp::verify_sal(signable_tx_hash_2, input, ki, sal_proof));
    }

    // Verify all RingCT non-semantics
    LOG_PRINT_L1("Verify RingCT non-semantics consensus rules");
    ASSERT_TRUE(rct::verRctNonSemanticsSimple(deserialized_tx.rct_signatures));
    free(tree_root);

    // Load carrot from tx
    LOG_PRINT_L1("Parsing carrot info from deserialized transaction");
    std::vector<CarrotEnoteV1> parsed_enotes;
    std::vector<crypto::key_image> parsed_key_images;
    rct::xmr_amount parsed_fee;
    std::optional<encrypted_payment_id_t> parsed_encrypted_payment_id;
    ASSERT_TRUE(try_load_carrot_from_transaction_v1(deserialized_tx,
        parsed_enotes,
        parsed_key_images,
        parsed_fee,
        parsed_encrypted_payment_id));

    // Bob scan
    LOG_PRINT_L1("Bob scanning");
    std::vector<mock::mock_scan_result_t> bob_scan_results;
    mock::mock_scan_enote_set(parsed_enotes,
        parsed_encrypted_payment_id.value_or(null_payment_id),
        bob,
        bob_scan_results);
    ASSERT_EQ(bob_payment_proposals.size(), bob_scan_results.size());

    // Compare bob scan results to bob payment proposals
    std::unordered_set<size_t> matched_scan_results;
    for (size_t i = 0; i < bob_payment_proposals.size(); ++i)
    {
        bool matched = false;
        for (size_t j = 0; j < bob_scan_results.size(); ++j)
        {
            if (matched_scan_results.count(j))
                continue;
            else if (compare_scan_result(bob_scan_results.at(j),
                bob_payment_proposals.at(i)))
            {
                matched = true;
                matched_scan_results.insert(j);
                break;
            }
        }
        ASSERT_TRUE(matched);
    }
}

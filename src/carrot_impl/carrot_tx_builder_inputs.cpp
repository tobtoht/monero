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

//paired header
#include "carrot_tx_builder_inputs.h"

//local headers
#include "carrot_core/account_secrets.h"
#include "carrot_core/address_utils.h"
#include "carrot_core/carrot_enote_scan.h"
#include "carrot_core/config.h"
#include "carrot_core/enote_utils.h"
#include "crypto/generators.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"

//third party headers

//standard headers
#include <algorithm>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "carrot_impl"

namespace carrot
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
using required_money_t = std::map<size_t, boost::multiprecision::int128_t>;
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static int compare_input_candidate_same_ki(const CarrotPreSelectedInput &lhs, const CarrotPreSelectedInput &rhs)
{
    CHECK_AND_ASSERT_THROW_MES(lhs.core.key_image == rhs.core.key_image,
        "compare_input_candidate_same_ki: this function is not meant to compare inputs of different key images");

    // first prefer the higher amount
    if (lhs.core.amount < rhs.core.amount)
        return -1;
    else if (lhs.core.amount > rhs.core.amount)
        return 1;

    // then prefer older
    if (lhs.block_index < rhs.block_index)
        return 1;
    else if (lhs.block_index > rhs.block_index)
        return -1;
    
    // It should be computationally intractable for lhs.is_external != rhs.is_external, but I haven't
    // looked into it too deeply. I guess you would want to prefer whichever one !is_external.

    return 0;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void select_two_inputs_prefer_oldest(const epee::span<const CarrotPreSelectedInput> input_candidates,
    const std::vector<size_t> selectable_inputs,
    const required_money_t &required_money_by_input_count,
    std::set<size_t> &selected_inputs_indices_out)
{
    // calculate required money and fee diff from one to two inputs
    const boost::multiprecision::int128_t required_money = required_money_by_input_count.at(2);
    const rct::xmr_amount fee_diff = boost::numeric_cast<rct::xmr_amount>(required_money -
            required_money_by_input_count.at(1));

    // copy selectable_inputs, excluding dust, then sort by ascending block index
    std::vector<size_t> selectable_inputs_by_bi;
    selectable_inputs_by_bi.reserve(selectable_inputs.size());
    for (size_t idx : selectable_inputs)
        if (input_candidates[idx].core.amount > fee_diff)
            selectable_inputs_by_bi.push_back(idx);
    std::sort(selectable_inputs_by_bi.begin(), selectable_inputs_by_bi.end(),
        [input_candidates](const size_t a, const size_t b) -> bool
        {
            return input_candidates[a].block_index < input_candidates[b].block_index;
        });

    // then copy again and *stable* sort by amount 
    std::vector<size_t> selectable_inputs_by_amount_bi = selectable_inputs_by_bi;
    std::sort(selectable_inputs_by_amount_bi.begin(), selectable_inputs_by_amount_bi.end(),
        [input_candidates](const size_t a, const size_t b) -> bool
        {
            return input_candidates[a].core.amount < input_candidates[b].core.amount;
        });

    // for each input in ascending block index order...
    for (size_t low_bi_input : selectable_inputs_by_bi)
    {
        // calculate how much we need in a corresponding input to this one
        const rct::xmr_amount old_amount = input_candidates[low_bi_input].core.amount;
        const boost::multiprecision::int128_t required_money_in_other_128 = (required_money > old_amount)
            ? (required_money - old_amount) : 0;
        if (required_money_in_other_128 >= std::numeric_limits<rct::xmr_amount>::max())
            continue;
        const rct::xmr_amount required_money_in_other =
            boost::numeric_cast<rct::xmr_amount>(required_money_in_other_128);

        // do a binary search for an input with at least that amount
        auto other_it = std::lower_bound(selectable_inputs_by_amount_bi.cbegin(),
            selectable_inputs_by_amount_bi.cend(),
            required_money_in_other,
            [input_candidates](size_t selectable_index, rct::xmr_amount required_money_in_other) -> bool
                { return input_candidates[selectable_index].core.amount < required_money_in_other; });

        // check that the iterator is in bounds and the complementary input isn't equal to the first
        if (other_it == selectable_inputs_by_amount_bi.cend())
            continue;
        else if (*other_it == low_bi_input)
            ++other_it; // can't choose same input twice

        if (other_it == selectable_inputs_by_amount_bi.cend())
            continue;

        // we found a match !
        selected_inputs_indices_out = {low_bi_input, *other_it};
        return;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::vector<size_t> combine_and_sort_input_partitions(
    const epee::span<const CarrotPreSelectedInput> input_candidates,
    const std::vector<size_t> &a,
    const std::vector<size_t> &b)
{
    std::vector<size_t> z;
    z.reserve(a.size() + b.size());
    z.insert(z.end(), a.cbegin(), a.cend());
    z.insert(z.end(), b.cbegin(), b.cend());

    //! @TODO: there's a faster algorithm for merging sorted lists
    std::sort(z.begin(), z.end(),
        [input_candidates](size_t a, size_t b) -> bool {
            return input_candidates[a].core.amount < input_candidates[b].core.amount;
        });

    return z;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::pair<size_t, boost::multiprecision::int128_t> input_count_for_max_usable_money(
    const epee::span<const CarrotPreSelectedInput> input_candidates,
    const std::vector<size_t> selectable_inputs,
    const required_money_t &required_money_by_input_count)
{
    // Returns (N, X) where the X is the sum of the amounts of the greatest N <= CARROT_MAX_TX_INPUTS
    // inputs from selectable_inputs, maximizing X - R(N). R(N) is the required money for this
    // transaction, including fee, for given input count N. This should correctly handle "almost-dust":
    // inputs which are less than the fee, but greater than or equal to the difference of the fee
    // compared to excluding that input. If this function returns N == 0, then there aren't enough
    // usable funds, i.e. no N exists such that X - R(N) > 0.
    //
    // Prereq: selectable_inputs is sorted in ascending order of input amount and contains no invalid indices

    std::pair<size_t, boost::multiprecision::int128_t> res{0, 0};
    boost::multiprecision::int128_t max_margin = 0;
    boost::multiprecision::int128_t cumulative_input_sum = 0;

    const size_t max_num_ins = std::min<size_t>(selectable_inputs.size(), CARROT_MAX_TX_INPUTS);
    for (size_t idx_idx = selectable_inputs.size(); idx_idx > selectable_inputs.size() - max_num_ins; --idx_idx)
    {
        const rct::xmr_amount amount = input_candidates[selectable_inputs.at(idx_idx - 1)].core.amount;
        cumulative_input_sum += amount;
        const size_t num_ins = selectable_inputs.size() - idx_idx + 1;
        const boost::multiprecision::int128_t margin = cumulative_input_sum - required_money_by_input_count.at(num_ins);

        if (margin > max_margin)
        {
            res = {num_ins, cumulative_input_sum};
            max_margin = margin;
        }
    }

    return res;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
rct::key load_key(const std::uint8_t bytes[32])
{
    rct::key k;
    memcpy(k.bytes, bytes, sizeof(k));
    return k;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void store_key(std::uint8_t bytes[32], const rct::key &k)
{
    memcpy(bytes, k.bytes, 32);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static FcmpInputCompressed calculate_fcmp_input_for_rerandomizations(const crypto::public_key &onetime_address,
    const rct::key &amount_commitment,
    const rct::key &r_o,
    const rct::key &r_i,
    const rct::key &r_r_i,
    const rct::key &r_c)
{
    FcmpInputCompressed res;
    rct::key temp1, temp2;

    // O~ = O + r_o T
    temp1 = rct::scalarmultKey(rct::pk2rct(crypto::get_T()), r_o);
    temp1 = rct::addKeys(rct::pk2rct(onetime_address), temp1);
    memcpy(res.O_tilde, temp1.bytes, sizeof(rct::key));

    // I = Hp(O)
    crypto::ec_point I;
    crypto::derive_key_image_generator(onetime_address, I);

    // I~ = I + r_i U
    temp1 = rct::scalarmultKey(rct::pk2rct(crypto::get_U()), r_i);
    temp1 = rct::addKeys(rct::pt2rct(I), temp1);
    memcpy(res.I_tilde, temp1.bytes, sizeof(rct::key));

    // R = r_i V + r_r_i T
    temp1 = rct::scalarmultKey(rct::pk2rct(crypto::get_V()), r_i);
    temp2 = rct::scalarmultKey(rct::pk2rct(crypto::get_T()), r_r_i);
    temp1 = rct::addKeys(temp1, temp2);
    memcpy(res.R, temp1.bytes, sizeof(rct::key));

    // C~ = C + r_c G
    rct::addKeys1(temp1, r_c, amount_commitment);
    memcpy(res.C_tilde, temp1.bytes, sizeof(rct::key));

    return res;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static FcmpRerandomizedOutputCompressed calculate_rerandomized_output(
    const crypto::public_key &onetime_address,
    const rct::key &amount_commitment,
    const rct::key &r_o,
    const rct::key &r_i,
    const rct::key &r_r_i,
    const rct::key &r_c)
{
    FcmpRerandomizedOutputCompressed res;

    // calculate O~, I~, R, C~
    res.input = calculate_fcmp_input_for_rerandomizations(onetime_address,
        amount_commitment,
        r_o,
        r_i,
        r_r_i,
        r_c);

    // copy r_o, r_i, r_r_i, r_c
    store_key(res.r_o, r_o);
    store_key(res.r_i, r_i);
    store_key(res.r_r_i, r_r_i);
    store_key(res.r_c, r_c);

    return res;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_sal_proof_nominal_address_naive(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const crypto::secret_key &address_privkey_g,
    const crypto::secret_key &address_privkey_t,
    const crypto::secret_key &sender_extension_g,
    const crypto::secret_key &sender_extension_t,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    // O = x G + y T

    // x = k^{j,g}_addr + k^g_o
    crypto::secret_key x;
    sc_add(to_bytes(x),
        to_bytes(address_privkey_g),
        to_bytes(sender_extension_g));

    // y = k^{j,t}_addr + k^t_o
    crypto::secret_key y;
    sc_add(to_bytes(y),
        to_bytes(address_privkey_t),
        to_bytes(sender_extension_t));

    std::tie(sal_proof_out, key_image_out) = fcmp_pp::prove_sal(signable_tx_hash,
        x,
        y,
        rerandomized_output);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_sal_proof_nominal_address_carrot_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const CarrotOutputOpeningHintV1 &opening_hint,
    const crypto::secret_key &address_privkey_g,
    const crypto::secret_key &address_privkey_t,
    const crypto::public_key &account_spend_pubkey,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device *k_view_incoming_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    CHECK_AND_ASSERT_THROW_MES(verify_rerandomized_output_basic(rerandomized_output,
            opening_hint.source_enote.onetime_address,
            opening_hint.source_enote.amount_commitment),
        "make sal proof nominal address carrot v1: rerandomized output does not verify");

    // We scan scan here as a defensive programming measure against naive-scanner burning bugs,
    // malicious-scanner burning bugs, and malicious-scanner subaddress swaps. However, if you want
    // a user to confirm other details about the enote they're spending (e.g. amount, payment ID,
    // subaddress index, internal message, enote type, TXID), you're going to have to pre-scan this
    // enote and implement the checks yourself before calling this function. Hardware wallet
    // developers: if you want your users to keep their hard-earned funds, don't skip cold-side
    // enote scanning in Carrot enotes! Legacy enotes aren't SAFU from malicious-scanner burning
    // anyways since K_o doesn't bind to C_a.

    crypto::secret_key sender_extension_g;
    crypto::secret_key sender_extension_t;
    crypto::public_key address_spend_pubkey;
    rct::xmr_amount amount;
    crypto::secret_key amount_blinding_factor;
    payment_id_t payment_id;
    CarrotEnoteType enote_type;
    janus_anchor_t internal_message;

    // first, try do an internal scan of the enote
    bool scanned = false;
    if (s_view_balance_dev)
    {
        scanned = try_scan_carrot_enote_internal(opening_hint.source_enote,
            *s_view_balance_dev,
            sender_extension_g,
            sender_extension_t,
            address_spend_pubkey,
            amount,
            amount_blinding_factor,
            enote_type,
            internal_message);
        payment_id = null_payment_id;
    }
    else
    {
        internal_message = janus_anchor_t{};
    }

    // if that didn't work, try an external scan
    if (!scanned && k_view_incoming_dev)
    {
        scanned = try_ecdh_and_scan_carrot_enote_external(opening_hint.source_enote,
            opening_hint.encrypted_payment_id,
            *k_view_incoming_dev,
            account_spend_pubkey,
            sender_extension_g,
            sender_extension_t,
            address_spend_pubkey,
            amount,
            amount_blinding_factor,
            payment_id,
            enote_type);
    }

    CHECK_AND_ASSERT_THROW_MES(scanned,
        "make sal proof nominal address carrot v1: cannot spend enote because of a scan failure");

    make_sal_proof_nominal_address_naive(signable_tx_hash,
        rerandomized_output,
        address_privkey_g,
        address_privkey_t,
        sender_extension_g,
        sender_extension_t,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_sal_proof_nominal_address_carrot_coinbase_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const CarrotCoinbaseOutputOpeningHintV1 &opening_hint,
    const crypto::secret_key &address_privkey_g,
    const crypto::secret_key &address_privkey_t,
    const crypto::public_key &account_spend_pubkey,
    const view_incoming_key_device &k_view_incoming_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    const rct::key coinbase_amount_commitment = rct::zeroCommitVartime(opening_hint.source_enote.amount);

    CHECK_AND_ASSERT_THROW_MES(verify_rerandomized_output_basic(rerandomized_output,
            opening_hint.source_enote.onetime_address,
            coinbase_amount_commitment),
        "make sal proof nominal address carrot coinbase v1: rerandomized output does not verify");

    // We scan scan here as a defensive programming measure against naive-scanner burning bugs and
    // malicious-scanner burning bugs. However, if you want a user to confirm other details about
    // the coinbase enote they're spending (e.g. amount, block index), you're going to have to
    // pre-scan this enote and implement the checks yourself before calling this function. Hardware
    // wallet developers: if you want your users to keep their hard-earned funds, don't skip
    // cold-side enote scanning in Carrot enotes! Legacy enotes aren't SAFU from malicious-scanner
    // burning anyways since K_o doesn't bind to C_a.

    crypto::secret_key sender_extension_g;
    crypto::secret_key sender_extension_t;
    crypto::public_key address_spend_pubkey;

    // first, try do an internal scan of the enote
    const bool scanned = try_ecdh_and_scan_carrot_coinbase_enote(opening_hint.source_enote,
        k_view_incoming_dev,
        account_spend_pubkey,
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey);

    CHECK_AND_ASSERT_THROW_MES(scanned,
        "make sal proof nominal address carrot coinbase v1: cannot spend enote because of a scan failure");

    make_sal_proof_nominal_address_naive(signable_tx_hash,
        rerandomized_output,
        address_privkey_g,
        address_privkey_t,
        sender_extension_g,
        sender_extension_t,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
const crypto::public_key &onetime_address_ref(const OutputOpeningHintVariant &opening_hint)
{
    struct onetime_address_ref_visitor: public tools::variant_static_visitor<const crypto::public_key &>
    {
        const crypto::public_key &operator()(const LegacyOutputOpeningHintV1 &h) const
        { return h.onetime_address; }
        const crypto::public_key &operator()(const CarrotOutputOpeningHintV1 &h) const 
        { return h.source_enote.onetime_address; }
        const crypto::public_key &operator()(const CarrotCoinbaseOutputOpeningHintV1 &h) const
        { return h.source_enote.onetime_address; }
    };

    return opening_hint.visit(onetime_address_ref_visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
rct::key amount_commitment_ref(const OutputOpeningHintVariant &opening_hint)
{
    struct amount_commitment_ref_visitor: public tools::variant_static_visitor<rct::key>
    {
        rct::key operator()(const LegacyOutputOpeningHintV1 &h) const
        { return rct::commit(h.amount, rct::sk2rct(h.amount_blinding_factor)); }
        rct::key operator()(const CarrotOutputOpeningHintV1 &h) const 
        { return h.source_enote.amount_commitment; }
        rct::key operator()(const CarrotCoinbaseOutputOpeningHintV1 &h) const
        { return rct::zeroCommitVartime(h.source_enote.amount); }
    };

    return opening_hint.visit(amount_commitment_ref_visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
select_inputs_func_t make_single_transfer_input_selector(
    const epee::span<const CarrotPreSelectedInput> input_candidates,
    const epee::span<const InputSelectionPolicy> policies,
    const std::uint32_t flags,
    std::set<size_t> *selected_input_indices_out)
{
    using namespace InputSelectionFlags;

    CHECK_AND_ASSERT_THROW_MES(!policies.empty(),
        "make_single_transfer_input_selector: no input selection policies provided");

    // Sanity check flags
    const bool confused_qfs = (flags & ALLOW_PRE_CARROT_INPUTS_IN_NORMAL_TRANSFERS) &&
        !(flags & ALLOW_EXTERNAL_INPUTS_IN_NORMAL_TRANSFERS);
    CHECK_AND_ASSERT_THROW_MES(!confused_qfs,
        "make single transfer input selector: It does not make sense to allow pre-carrot inputs in normal transfers, "
        "but not external carrot inputs.");

    // input selector :)
    return [=](const boost::multiprecision::int128_t &nominal_output_sum,
        const std::map<std::size_t, rct::xmr_amount> &fee_by_input_count,
        const std::size_t num_normal_payment_proposals,
        const std::size_t num_selfsend_payment_proposals,
        std::vector<CarrotSelectedInput> &selected_inputs_out)
    {
        // 1. Compile map of best input candidates by key image to mitigate the "burning bug" for legacy enotes
        std::unordered_map<crypto::key_image, size_t> best_input_by_key_image;
        for (size_t i = 0; i < input_candidates.size(); ++i)
        {
            const CarrotPreSelectedInput &input_candidate = input_candidates[i];
            auto it = best_input_by_key_image.find(input_candidate.core.key_image);
            if (it == best_input_by_key_image.end())
            {
               best_input_by_key_image[input_candidate.core.key_image] = i;
            }
            else
            {
                const CarrotPreSelectedInput &other_input_candidate = input_candidates[it->second];
                if (compare_input_candidate_same_ki(other_input_candidate, input_candidate) < 0)
                    it->second = i;
            }
        }

        // 2. Collect list of non-burned inputs and sort by amount
        std::vector<size_t> all_non_burned_inputs;
        all_non_burned_inputs.reserve(best_input_by_key_image.size());
        for (const auto &best_input : best_input_by_key_image)
            all_non_burned_inputs.push_back(best_input.second);
        std::sort(all_non_burned_inputs.begin(), all_non_burned_inputs.end(),
            [input_candidates](size_t a, size_t b) -> bool {
                return input_candidates[a].core.amount < input_candidates[b].core.amount;
        });

        // 3. Partition into:
        //      a) Pre-carrot (no quantum forward secrecy)
        //      b) External carrot (quantum forward secret if public address not known)
        //      c) Internal carrot (always quantum forward secret unless secret keys known)
        std::vector<size_t> pre_carrot_inputs;
        pre_carrot_inputs.reserve(all_non_burned_inputs.size());
        std::vector<size_t> external_carrot_inputs;
        external_carrot_inputs.reserve(all_non_burned_inputs.size());
        std::vector<size_t> internal_inputs;
        internal_inputs.reserve(all_non_burned_inputs.size());
        for (size_t candidate_idx : all_non_burned_inputs)
        {
            if (input_candidates[candidate_idx].is_pre_carrot)
                pre_carrot_inputs.push_back(candidate_idx);
            else if (input_candidates[candidate_idx].is_external)
                external_carrot_inputs.push_back(candidate_idx);
            else
                internal_inputs.push_back(candidate_idx);
        }

        // 4. Calculate minimum required input money sum for a given input count
        const bool subtract_fee = flags & IS_KNOWN_FEE_SUBTRACTABLE;
        std::map<size_t, boost::multiprecision::int128_t> required_money_by_input_count;
        for (const auto &fee_and_input_count : fee_by_input_count)
        {
            required_money_by_input_count[fee_and_input_count.first] = 
                nominal_output_sum + (subtract_fee ? 0 : fee_and_input_count.second);
        }

        // 5. Calculate misc features
        const bool must_use_internal = !(flags & ALLOW_EXTERNAL_INPUTS_IN_NORMAL_TRANSFERS) &&
            (num_normal_payment_proposals != 0);
        const bool allow_mixed_externality = (flags & ALLOW_MIXED_INTERNAL_EXTERNAL) &&
            !must_use_internal;
        const bool must_use_carrot = !(flags & ALLOW_PRE_CARROT_INPUTS_IN_NORMAL_TRANSFERS) &&
            (num_normal_payment_proposals != 0);
        const bool allow_mixed_carrotness = (flags & ALLOW_MIXED_CARROT_PRE_CARROT) &&
            !must_use_carrot;

        // We should prefer to spend non-forward-secret enotes in transactions where all the outputs are going back to
        // ourself. Otherwise, if we spend these enotes while transferring money to another entity, an external observer
        // who A) has a quantum computer, and B) knows one of their public addresses, will be able to trace the money
        // transfer. Such an observer will always be able to tell which view-incoming keys / accounts these
        // non-forward-secrets enotes belong to, their amounts, and where they're spent. So since they already know that
        // information, churning back to oneself doesn't actually reveal that much more additional information.
        const bool prefer_non_fs = num_normal_payment_proposals == 0;
        CHECK_AND_ASSERT_THROW_MES(!must_use_internal || !prefer_non_fs,
            "make_single_transfer_input_selector: bug: must_use_internal AND prefer_non_fs are true");

        // There is no "prefer pre-carrot" variable since in the case that we prefer spending non-forward-secret, we
        // always prefer first spending pre-carrot over carrot, if it is allowed

        // 6. Short-hand functor for dispatching input selection on a subset of inputs
        //    Note: Result goes into `selected_inputs_indices`. If already populated, then this functor does nothing
        std::set<size_t> selected_inputs_indices;
        const auto try_dispatch_input_selection =
            [&](const std::vector<size_t> &selectable_indices)
        {
            // Return early if already selected inputs or no available selectable
            const bool already_selected = !selected_inputs_indices.empty();
            if (already_selected || selectable_indices.empty())
                return;

            // Return early if not enough money in this selectable set...
            const auto max_usable_money = input_count_for_max_usable_money(input_candidates,
                    selectable_indices,
                    required_money_by_input_count);
            const bool enough_money = max_usable_money.first > 0;
            if (!enough_money)
                return;

            // for each passed policy and while not already selected inputs...
            for (size_t policy_idx = 0; policy_idx < policies.size() && selected_inputs_indices.empty(); ++policy_idx)
            {
                switch (policies[policy_idx])
                {
                case InputSelectionPolicy::TwoInputsPreferOldest:
                    select_two_inputs_prefer_oldest(input_candidates,
                            selectable_indices,
                            required_money_by_input_count,
                            selected_inputs_indices);
                    break;
                case InputSelectionPolicy::HighestUnlockedBalance:
                case InputSelectionPolicy::LowestInputCountAndFee:
                case InputSelectionPolicy::ConsolidateDiscretized:
                case InputSelectionPolicy::OldestInputs:
                default:
                    ASSERT_MES_AND_THROW("dispatch_input_selection_policy: unrecognized input selection policy");
                }
            }
        };

        // 8. Try dispatching for non-forward-secret input subsets, if preferred in this context
        if (prefer_non_fs)
        {
            // try getting rid of pre-carrot enotes first, if allowed
            if (!must_use_carrot)
                try_dispatch_input_selection(pre_carrot_inputs);

            // ... then external carrot
            try_dispatch_input_selection(external_carrot_inputs);
        }

        // 9. Try dispatching for internal
        try_dispatch_input_selection(internal_inputs);

        // 10. Try dispatching for non-FS *after* internal, if allowed and not already tried
        if (!must_use_internal || !prefer_non_fs)
        {
            // Spending non-FS inputs in a normal transfer transaction is not ideal, but at least
            // when partition it like this, we aren't "dirtying" the carrot with the pre-carrot, and
            // the internal with the external
            if (!must_use_carrot)
                try_dispatch_input_selection(pre_carrot_inputs);
            try_dispatch_input_selection(external_carrot_inputs);
        }

        // 11. Try dispatching for all non-FS (mixed pre-carrot & carrot external), if allowed
        if (allow_mixed_carrotness)
        {
            // We're mixing carrot/pre-carrot spends here, but avoiding "dirtying" the internal
            try_dispatch_input_selection(
                combine_and_sort_input_partitions(input_candidates, pre_carrot_inputs, external_carrot_inputs));
        }

        // 12. Try dispatching for all carrot, if allowed
        if (allow_mixed_externality)
        {
            // We're mixing internal & external carrot spends here, but avoiding "dirtying" the
            // carrot spends with pre-carrot spends. This will be quantum forward secret iff the
            // adversary doesn't know one of your public addresses
            try_dispatch_input_selection(
                combine_and_sort_input_partitions(input_candidates, external_carrot_inputs, internal_inputs));
        }

        //! @TODO: MRL discussion about whether step 11 or step 12 should go first. In other words,
        //         do we prefer to avoid dirtying internal, and protect against quantum adversaries
        //         who know your public addresses? Or do we prefer to avoid dirtying w/ pre-carrot,
        //         and protect against quantum adversaries with no special knowledge of your public
        //         addresses, but whose attacks are only relevant when spending pre-FCMP++ enotes?

        // 13. Try dispatching for everything, if allowed
        if (allow_mixed_carrotness && allow_mixed_externality)
            try_dispatch_input_selection(all_non_burned_inputs);

        // Notice that we don't combine just the pre_carrot_inputs and internal_inputs by themselves

        // 14. Sanity check indices
        CHECK_AND_ASSERT_THROW_MES(!selected_inputs_indices.empty(),
            "make_single_transfer_input_selector: input selection failed");
        CHECK_AND_ASSERT_THROW_MES(*selected_inputs_indices.crbegin() < input_candidates.size(),
            "make_single_transfer_input_selector: bug: selected inputs index out of range");

        // 15. Do a greedy search for inputs whose amount doesn't pay for itself and drop them, logging debug messages
        //     Note: this also happens to be optimal if the fee difference between each input count is constant
        bool should_search_for_dust = !(flags & ALLOW_DUST);
        while (should_search_for_dust && selected_inputs_indices.size() > CARROT_MIN_TX_INPUTS)
        {
            should_search_for_dust = false; // only loop again if we remove an input below
            const boost::multiprecision::int128_t fee_diff =
                required_money_by_input_count.at(selected_inputs_indices.size()) - 
                required_money_by_input_count.at(selected_inputs_indices.size() - 1);
            CHECK_AND_ASSERT_THROW_MES(fee_diff >= 0,
                "make_single_transfer_input_selector: bug: fee is expected to be higher with fewer inputs");
            for (auto it = selected_inputs_indices.begin(); it != selected_inputs_indices.end(); ++it)
            {
                const CarrotPreSelectedInput &input_candidate = input_candidates[*it];
                if (input_candidate.core.amount < fee_diff)
                {
                    MDEBUG("make_single_transfer_input_selector: dropping dusty input "
                        << input_candidate.core.key_image << " with amount " << input_candidate.core.amount
                        << ", which is less than the difference in fee of this transaction with it: " << fee_diff);
                    selected_inputs_indices.erase(it);
                    should_search_for_dust = true;
                    break; // break out of inner `for` loop so we can recalculate `fee_diff`
                }
            }
        }

        // 16. Check the sum of input amounts is great enough
        const size_t num_selected = selected_inputs_indices.size();
        const boost::multiprecision::int128_t required_money = required_money_by_input_count.at(num_selected);
        boost::multiprecision::int128_t input_amount_sum = 0;
        for (const size_t idx : selected_inputs_indices)
            input_amount_sum += input_candidates[idx].core.amount;
        CHECK_AND_ASSERT_THROW_MES(input_amount_sum >= required_money,
            "make_single_transfer_input_selector: bug: input selection returned successful without enough funds");

        // 17. Collect selected inputs
        selected_inputs_out.clear();
        selected_inputs_out.reserve(num_selected);
        for (size_t selected_input_index : selected_inputs_indices)
            selected_inputs_out.push_back(input_candidates[selected_input_index].core);

        if (selected_input_indices_out != nullptr)
            *selected_input_indices_out = std::move(selected_inputs_indices);
    };
}
//-------------------------------------------------------------------------------------------------------------------
void make_carrot_rerandomized_outputs_nonrefundable(const std::vector<crypto::public_key> &input_onetime_addresses,
    const std::vector<rct::key> &input_amount_commitments,
    const std::vector<rct::key> &input_amount_blinding_factors,
    const std::vector<rct::key> &output_amount_blinding_factors,
    std::vector<FcmpRerandomizedOutputCompressed> &rerandomized_outputs_out)
{
    rerandomized_outputs_out.clear();

    const size_t nins = input_onetime_addresses.size();
    CHECK_AND_ASSERT_THROW_MES(nins, "make carrot rerandomized outputs nonrefundable: no inputs provided");
    CHECK_AND_ASSERT_THROW_MES(input_amount_commitments.size() == nins,
        "make carrot rerandomized outputs nonrefundable: wrong input amount commitments size");
    CHECK_AND_ASSERT_THROW_MES(input_amount_blinding_factors.size() == nins,
        "make carrot rerandomized outputs nonrefundable: wrong input amount blinding factors size");

    // set blinding_factor_imbalance to sum(output amount blinding factors) - sum(input amount blinding factors)
    rct::key blinding_factor_imbalance;
    sc_0(blinding_factor_imbalance.bytes);
    blinding_factor_imbalance.bytes[0] = 1; // we start off with 1 to account for the fee amount commitment
    for (const rct::key &obf : output_amount_blinding_factors)
        sc_add(blinding_factor_imbalance.bytes, blinding_factor_imbalance.bytes, obf.bytes);
    for (const rct::key &ibf : input_amount_blinding_factors)
        sc_sub(blinding_factor_imbalance.bytes, blinding_factor_imbalance.bytes, ibf.bytes);

    rerandomized_outputs_out.reserve(nins);
    for (size_t i = 0; i < nins; ++i)
    {
        const bool last = i == nins - 1;

        // O
        const crypto::public_key &onetime_address = input_onetime_addresses.at(i);
        // C
        const rct::key &amount_commitment = input_amount_commitments.at(i);

        // I = Hp(O)
        crypto::ec_point I;
        crypto::derive_key_image_generator(onetime_address, I);

        // sample r_o, r_i, r_r_i randomly
        const rct::key r_o = rct::skGen();
        const rct::key r_i = rct::skGen();
        const rct::key r_r_i = rct::skGen();

        // sample r_c for all inputs except for the last one, set that one such that the tx balances
        const rct::key r_c = last ? blinding_factor_imbalance : rct::skGen();

        // update blinding_factor_imbalance with new rerandomization
        sc_sub(blinding_factor_imbalance.bytes, blinding_factor_imbalance.bytes, r_c.bytes);

        // calculate rerandomized output and push
        rerandomized_outputs_out.push_back(calculate_rerandomized_output(
            onetime_address,
            amount_commitment,
            r_o,
            r_i,
            r_r_i,
            r_c
        ));
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_rerandomized_output_basic(const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const crypto::public_key &onetime_address,
    const rct::key &amount_commitment)
{
    const FcmpInputCompressed recomputed_input = calculate_fcmp_input_for_rerandomizations(
        onetime_address,
        amount_commitment,
        load_key(rerandomized_output.r_o),
        load_key(rerandomized_output.r_i),
        load_key(rerandomized_output.r_r_i),
        load_key(rerandomized_output.r_c));

    return 0 == memcmp(&recomputed_input, &rerandomized_output.input, sizeof(FcmpInputCompressed));
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_openable_rerandomized_output_basic(const CarrotOpenableRerandomizedOutputV1 &openable_rerandomized_output)
{
    return verify_rerandomized_output_basic(openable_rerandomized_output.rerandomized_output,
        onetime_address_ref(openable_rerandomized_output.opening_hint),
        amount_commitment_ref(openable_rerandomized_output.opening_hint));
}
//-------------------------------------------------------------------------------------------------------------------
void make_sal_proof_legacy_to_legacy_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const LegacyOutputOpeningHintV1 &opening_hint,
    const crypto::secret_key &k_spend,
    const cryptonote_hierarchy_address_device &addr_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    CHECK_AND_ASSERT_THROW_MES(verify_rerandomized_output_basic(rerandomized_output,
            opening_hint.onetime_address,
            rct::commit(opening_hint.amount, rct::sk2rct(opening_hint.amount_blinding_factor))),
        "make sal proof legacy to legacy v1: rerandomized output does not verify");

    // k^{j,}g_addr = k_s + k^j_subext
    crypto::secret_key address_privkey_g;
    addr_dev.make_legacy_subaddress_extension(opening_hint.subaddr_index.major,
        opening_hint.subaddr_index.minor,
        address_privkey_g);
    sc_add(to_bytes(address_privkey_g),
        to_bytes(address_privkey_g),
        to_bytes(k_spend));

    // note that we pass k_spend as k_generate_image, and leave k_prove_spend as 0
    make_sal_proof_nominal_address_naive(signable_tx_hash,
        rerandomized_output,
        address_privkey_g,
        crypto::null_skey,
        opening_hint.sender_extension_g,
        crypto::null_skey,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_sal_proof_carrot_to_legacy_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const CarrotOutputOpeningHintV1 &opening_hint,
    const crypto::secret_key &k_spend,
    const cryptonote_hierarchy_address_device &addr_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    // check that the opening hint tells us to open as a legacy address
    const AddressDeriveType derive_type = opening_hint.subaddr_index.derive_type;
    CHECK_AND_ASSERT_THROW_MES(derive_type == AddressDeriveType::PreCarrot,
        "make sal proof carrot to carrot v1: invalid subaddr derive type: " << static_cast<int>(derive_type));

    // k^{j, g}_addr = k_s + k^j_subext
    crypto::secret_key address_privkey_g;
    addr_dev.make_legacy_subaddress_extension(opening_hint.subaddr_index.index.major,
        opening_hint.subaddr_index.index.minor,
        address_privkey_g);
    sc_add(to_bytes(address_privkey_g),
        to_bytes(address_privkey_g),
        to_bytes(k_spend));

    make_sal_proof_nominal_address_carrot_v1(signable_tx_hash,
        rerandomized_output,
        opening_hint,
        address_privkey_g,
        /*address_privkey_t=*/crypto::null_skey,
        addr_dev.get_cryptonote_account_spend_pubkey(),
        /*s_view_balance_dev=*/nullptr,
        &addr_dev,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_sal_proof_carrot_to_carrot_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const CarrotOutputOpeningHintV1 &opening_hint,
    const crypto::secret_key &k_prove_spend,
    const crypto::secret_key &k_generate_image,
    const view_balance_secret_device &s_view_balance_dev,
    const view_incoming_key_device &k_view_incoming_dev,
    const generate_address_secret_device &s_generate_address_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    // check that the opening hint tells us to open as a Carrot address
    const AddressDeriveType derive_type = opening_hint.subaddr_index.derive_type;
    CHECK_AND_ASSERT_THROW_MES(derive_type == AddressDeriveType::Carrot,
        "make sal proof carrot to carrot v1: invalid subaddr derive type: " << static_cast<int>(derive_type));

    // K_s = k_gi G + k_ps T
    crypto::public_key account_spend_pubkey;
    make_carrot_spend_pubkey(k_generate_image, k_prove_spend, account_spend_pubkey);

    const std::uint32_t major_index = opening_hint.subaddr_index.index.major;
    const std::uint32_t minor_index = opening_hint.subaddr_index.index.minor;
    const bool is_subaddress = major_index || minor_index;
    crypto::secret_key k_subaddress_scalar;
    if (is_subaddress)
    {
        // s^j_gen = H_32[s_ga](j_major, j_minor)
        crypto::secret_key s_address_generator;
        s_generate_address_dev.make_index_extension_generator(major_index, minor_index, s_address_generator);

        // k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
        make_carrot_subaddress_scalar(account_spend_pubkey,
            s_address_generator,
            major_index,
            minor_index,
            k_subaddress_scalar);
    }
    else
    {
        // k^j_subscal = 1
        sc_0(to_bytes(k_subaddress_scalar));
        k_subaddress_scalar.data[0] = 1;
    }

    // k^{j, g}_addr = k_gi * k^j_subscal
    crypto::secret_key address_privkey_g;
    sc_mul(to_bytes(address_privkey_g), to_bytes(k_generate_image), to_bytes(k_subaddress_scalar));

    // k^{j, t}_addr = k_ps * k^j_subscal
    crypto::secret_key address_privkey_t;
    sc_mul(to_bytes(address_privkey_t), to_bytes(k_prove_spend), to_bytes(k_subaddress_scalar));

    make_sal_proof_nominal_address_carrot_v1(signable_tx_hash,
        rerandomized_output,
        opening_hint,
        address_privkey_g,
        address_privkey_t,
        account_spend_pubkey,
        &s_view_balance_dev,
        &k_view_incoming_dev,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_sal_proof_carrot_coinbase_to_legacy_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const CarrotCoinbaseOutputOpeningHintV1 &opening_hint,
    const crypto::secret_key &k_spend,
    const cryptonote_hierarchy_address_device &addr_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    // check that the opening hint tells us to open as a legacy address
    const AddressDeriveType derive_type = opening_hint.derive_type;
    CHECK_AND_ASSERT_THROW_MES(derive_type == AddressDeriveType::PreCarrot,
        "make sal proof carrot coinbase to legacy v1: invalid subaddr derive type: " << static_cast<int>(derive_type));

    make_sal_proof_nominal_address_carrot_coinbase_v1(signable_tx_hash,
        rerandomized_output,
        opening_hint,
        k_spend,
        crypto::null_skey,
        addr_dev.get_cryptonote_account_spend_pubkey(),
        addr_dev,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_sal_proof_carrot_coinbase_to_carrot_v1(const crypto::hash &signable_tx_hash,
    const FcmpRerandomizedOutputCompressed &rerandomized_output,
    const CarrotCoinbaseOutputOpeningHintV1 &opening_hint,
    const crypto::secret_key &k_prove_spend,
    const crypto::secret_key &k_generate_image,
    const view_incoming_key_device &k_view_incoming_dev,
    fcmp_pp::FcmpPpSalProof &sal_proof_out,
    crypto::key_image &key_image_out)
{
    // check that the opening hint tells us to open as a Carrot address
    const AddressDeriveType derive_type = opening_hint.derive_type;
    CHECK_AND_ASSERT_THROW_MES(derive_type == AddressDeriveType::Carrot,
        "make sal proof carrot coinbase to carrot v1: invalid subaddr derive type: " << static_cast<int>(derive_type));

    // K_s = k_gi G + k_ps T
    crypto::public_key account_spend_pubkey;
    make_carrot_spend_pubkey(k_generate_image, k_prove_spend, account_spend_pubkey);

    make_sal_proof_nominal_address_carrot_coinbase_v1(signable_tx_hash,
        rerandomized_output,
        opening_hint,
        k_generate_image,
        k_prove_spend,
        account_spend_pubkey,
        k_view_incoming_dev,
        sal_proof_out,
        key_image_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace carrot

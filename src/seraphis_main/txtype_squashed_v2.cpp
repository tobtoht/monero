// Copyright (c) 2022, The Monero Project
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
#include "txtype_squashed_v2.h"

//local headers
#include "common/container_helpers.h"
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "ringct/multiexp.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis_crypto/bulletproofs_plus2.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_multiexp.h"
#include "seraphis_crypto/sp_transcript.h"
#include "tx_builder_types.h"
#include "tx_builders_inputs.h"
#include "tx_builders_legacy_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_component_types_legacy.h"
#include "tx_validation_context.h"
#include "tx_validators.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void get_sp_tx_squashed_v2_txid(const SpTxSquashedV2 &tx, rct::key &tx_id_out)
{
    // tx_id = H_32(tx_proposal_prefix, tx_artifacts_merkle_root)

    // 1. tx proposal prefix
    // H_32(tx version, legacy input key images, seraphis input key images, output enotes, fee, tx supplement)
    rct::key tx_proposal_prefix;
    make_tx_proposal_prefix_v1(tx, tx_proposal_prefix);

    // 2. input images prefix
    // - note: key images are represented in the tx id twice (tx proposal prefix and input images
    //   - the reasons are: A) decouple proposals from the enote image structure, B) don't require proposals to commit
    //     to input commitment masks
    // H_32({C", KI}((legacy)), {K", C", KI}((seraphis)))
    rct::key input_images_prefix;
    make_input_images_prefix_v1(tx.legacy_input_images, tx.sp_input_images, input_images_prefix);

    // 3. tx proofs prefix
    // H_32(balance proof, legacy ring signatures, image proofs, seraphis membership proofs)
    rct::key tx_proofs_prefix;
    make_tx_proofs_prefix_v1(tx.balance_proof,
        tx.legacy_ring_signatures,
        tx.sp_image_proofs,
        tx.sp_membership_proofs,
        tx_proofs_prefix);

    // 4. tx artifacts prefix
    // H_32(input images prefix, tx proofs prefix)
    rct::key tx_artifacts_merkle_root;
    make_tx_artifacts_merkle_root_v1(input_images_prefix, tx_proofs_prefix, tx_artifacts_merkle_root);

    // 5. tx id
    // tx_id = H_32(tx_proposal_prefix, tx_artifacts_merkle_root)
    SpFSTranscript transcript{config::HASH_KEY_SERAPHIS_TRANSACTION_TYPE_SQUASHED_V1, 2*sizeof(rct::key)};
    transcript.append("prefix", tx_proposal_prefix);
    transcript.append("artifacts", tx_artifacts_merkle_root);

    assert(transcript.size() <= 128 && "sp squashed v1 tx id must fit within one blake2b block (128 bytes).");
    sp_hash_to_32(transcript.data(), transcript.size(), tx_id_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v2(const SpTxSquashedV2::SemanticRulesVersion semantic_rules_version,
    std::vector<LegacyEnoteImageV2> legacy_input_images,
    std::vector<SpEnoteImageV1> sp_input_images,
    std::vector<SpEnoteV1> outputs,
    SpBalanceProofV1 balance_proof,
    std::vector<LegacyRingSignatureV4> legacy_ring_signatures,
    std::vector<SpImageProofV1> sp_image_proofs,
    std::vector<SpMembershipProofV2> sp_membership_proofs,
    SpTxSupplementV1 tx_supplement,
    const DiscretizedFee discretized_transaction_fee,
    SpTxSquashedV2 &tx_out)
{
    tx_out.tx_semantic_rules_version = semantic_rules_version;
    tx_out.legacy_input_images       = std::move(legacy_input_images);
    tx_out.sp_input_images           = std::move(sp_input_images);
    tx_out.outputs                   = std::move(outputs);
    tx_out.balance_proof             = std::move(balance_proof);
    tx_out.legacy_ring_signatures    = std::move(legacy_ring_signatures);
    tx_out.sp_image_proofs           = std::move(sp_image_proofs);
    tx_out.sp_membership_proofs      = std::move(sp_membership_proofs);
    tx_out.tx_supplement             = std::move(tx_supplement);
    tx_out.tx_fee                    = discretized_transaction_fee;

    CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(tx_out), "Failed to assemble an SpTxSquashedV2.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v2(const SpTxSquashedV2::SemanticRulesVersion semantic_rules_version,
    SpPartialTxV1 partial_tx,
    std::vector<SpMembershipProofV2> sp_membership_proofs,
    SpTxSquashedV2 &tx_out)
{
    // TODO: implement check_v2_partial_tx_semantics_v2
    // // check partial tx semantics
    // check_v2_partial_tx_semantics_v2(partial_tx, semantic_rules_version);

    // note: seraphis membership proofs cannot be validated without the ledger used to construct them, so there is no
    //       check here

    // finish tx
    make_seraphis_tx_squashed_v2(semantic_rules_version,
        std::move(partial_tx.legacy_input_images),
        std::move(partial_tx.sp_input_images),
        std::move(partial_tx.outputs),
        std::move(partial_tx.balance_proof),
        std::move(partial_tx.legacy_ring_signatures),
        std::move(partial_tx.sp_image_proofs),
        std::move(sp_membership_proofs),
        std::move(partial_tx.tx_supplement),
        partial_tx.tx_fee,
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v2(const SpTxSquashedV2::SemanticRulesVersion semantic_rules_version,
    SpPartialTxV1 partial_tx,
    std::vector<SpAlignableMembershipProofV2> alignable_membership_proofs,
    SpTxSquashedV2 &tx_out)
{
    // line up the the membership proofs with the partial tx's input images (which are sorted)
    std::vector<SpMembershipProofV2> tx_membership_proofs = align_v2_membership_proofs_v2(partial_tx.sp_input_images,
        std::move(alignable_membership_proofs));

    // finish tx
    make_seraphis_tx_squashed_v2(semantic_rules_version, std::move(partial_tx), std::move(tx_membership_proofs), tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
SemanticConfigComponentCountsV1 semantic_config_component_counts_v1(
    const SpTxSquashedV2::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigComponentCountsV1 config{};

    // TODO: implement

    // note: in the squashed model, inputs + outputs must be <= the BP+ pre-generated generator array size ('maxM')
    if (tx_semantic_rules_version == SpTxSquashedV2::SemanticRulesVersion::MOCK)
    {
        config.min_inputs = 1;
        config.max_inputs = 100000;
        config.min_outputs = 1;
        config.max_outputs = 100000;
    }
    else if (tx_semantic_rules_version == SpTxSquashedV2::SemanticRulesVersion::ONE)
    {
        config.min_inputs = 1;
        config.max_inputs = config::SP_MAX_INPUTS_V1;
        config.min_outputs = 2;
        config.max_outputs = config::SP_MAX_OUTPUTS_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Tried to get semantic config for component counts with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
SemanticConfigLegacyRefSetV1 semantic_config_legacy_ref_sets_v1(
    const SpTxSquashedV2::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigLegacyRefSetV1 config{};

    // TODO: implement

    if (tx_semantic_rules_version == SpTxSquashedV2::SemanticRulesVersion::MOCK)
    {
        config.ring_size_min = 1;
        config.ring_size_max = 1000;
    }
    else if (tx_semantic_rules_version == SpTxSquashedV2::SemanticRulesVersion::ONE)
    {
        config.ring_size_min = config::LEGACY_RING_SIZE_V1;
        config.ring_size_max = config::LEGACY_RING_SIZE_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false,
            "Tried to get semantic config for legacy ref set sizes with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
SemanticConfigSpRefSetV2 semantic_config_sp_ref_sets_v2(
    const SpTxSquashedV2::SemanticRulesVersion tx_semantic_rules_version)
{
    // TODO: implement
    SemanticConfigSpRefSetV2 config{};
    return config;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_semantics<SpTxSquashedV2>(const SpTxSquashedV2 &tx)
{
    // validate component counts (num inputs/outputs/etc.)
    if (!validate_sp_semantics_component_counts_v1(semantic_config_component_counts_v1(tx.tx_semantic_rules_version),
            tx.legacy_input_images.size(),
            tx.sp_input_images.size(),
            tx.legacy_ring_signatures.size(),
            tx.sp_membership_proofs.size(),
            tx.sp_image_proofs.size(),
            tx.outputs.size(),
            tx.tx_supplement.output_enote_ephemeral_pubkeys.size(),
            tx.balance_proof.bpp2_proof.V.size()))
        return false;

    // validate legacy input proof reference set sizes
    if (!validate_sp_semantics_legacy_reference_sets_v1(semantic_config_legacy_ref_sets_v1(tx.tx_semantic_rules_version),
            tx.legacy_ring_signatures))
        return false;

    // TODO: implement semantics check for fcmp's
    // // validate seraphis input proof reference set sizes
    // if (!validate_sp_semantics_sp_reference_sets_v2(semantic_config_sp_ref_sets_v2(tx.tx_semantic_rules_version),
    //         tx.sp_membership_proofs))
    //     return false;

    // validate output serialization semantics
    if (!validate_sp_semantics_output_serialization_v2(tx.outputs))
        return false;

    // validate input image semantics
    if (!validate_sp_semantics_input_images_v1(tx.legacy_input_images, tx.sp_input_images))
        return false;

    // TODO: implement for fcmp's
    // // validate layout (sorting, uniqueness) of input images, membership proof ref sets, outputs, and tx supplement
    // if (!validate_sp_semantics_layout_v1(tx.legacy_ring_signatures,
    //         tx.sp_membership_proofs,
    //         tx.legacy_input_images,
    //         tx.sp_input_images,
    //         tx.outputs,
    //         tx.tx_supplement.output_enote_ephemeral_pubkeys,
    //         tx.tx_supplement.tx_extra))
    //     return false;

    // validate the tx fee is well-formed
    if (!validate_sp_semantics_fee_v1(tx.tx_fee))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_key_images<SpTxSquashedV2>(const SpTxSquashedV2 &tx, const TxValidationContext &tx_validation_context)
{
    // unspentness proof: check that key images are not in the ledger
    if (!validate_sp_key_images_v1(tx.legacy_input_images, tx.sp_input_images, tx_validation_context))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_amount_balance<SpTxSquashedV2>(const SpTxSquashedV2 &tx)
{
    // balance proof
    if (!validate_sp_amount_balance_v1(tx.legacy_input_images,
            tx.sp_input_images,
            tx.outputs,
            tx.tx_fee,
            tx.balance_proof))
        return false;

    // deferred for batching: range proofs

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_input_proofs<SpTxSquashedV2>(const SpTxSquashedV2 &tx, const TxValidationContext &tx_validation_context)
{
    // prepare image proofs message
    rct::key tx_proposal_prefix;
    make_tx_proposal_prefix_v1(tx, tx_proposal_prefix);

    // ownership, membership, and key image validity of legacy inputs
    if (!validate_sp_legacy_input_proofs_v1(tx.legacy_ring_signatures,
            tx.legacy_input_images,
            tx_proposal_prefix,
            tx_validation_context))
        return false;

    // ownership proof (and proof that key images are well-formed)
    if (!validate_sp_composition_proofs_v1(tx.sp_image_proofs, tx.sp_input_images, tx_proposal_prefix))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_txs_batchable<SpTxSquashedV2>(const std::vector<const SpTxSquashedV2*> &txs,
    const TxValidationContext &tx_validation_context)
{
    std::vector<const SpMembershipProofV2*> sp_membership_proof_ptrs;
    std::vector<const SpEnoteImageCore*> sp_input_image_ptrs;
    std::vector<const BulletproofPlus2*> range_proof_ptrs;
    sp_membership_proof_ptrs.reserve(txs.size()*20);  //heuristic... (most txs have 1-2 seraphis inputs)
    sp_input_image_ptrs.reserve(txs.size()*20);
    range_proof_ptrs.reserve(txs.size());

    // prepare for batch-verification
    for (const SpTxSquashedV2 *tx : txs)
    {
        if (!tx)
            return false;

        // gather membership proof pieces
        for (const SpMembershipProofV2 &sp_membership_proof : tx->sp_membership_proofs)
            sp_membership_proof_ptrs.push_back(&sp_membership_proof);

        for (const SpEnoteImageV1 &sp_input_image : tx->sp_input_images)
            sp_input_image_ptrs.push_back(&(sp_input_image.core));

        // gather range proofs
        range_proof_ptrs.push_back(&(tx->balance_proof.bpp2_proof));
    }

    // range proofs
    std::list<SpMultiexpBuilder> validation_data_range_proofs;
    if (!try_get_bulletproof_plus2_verification_data(range_proof_ptrs, validation_data_range_proofs))
        return false;

    // TODO: implement batch verification
    if (!validate_sp_membership_proofs_v2(sp_membership_proof_ptrs, tx_validation_context))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_tx_contextual_validation_id(const SpTxSquashedV2 &tx,
    const TxValidationContext &tx_validation_context,
    rct::key &validation_id_out)
{
    try
    {
        // 1. check key images
        if (!validate_sp_key_images_v1(tx.legacy_input_images, tx.sp_input_images, tx_validation_context))
            return false;

        // 2. get legacy ring members
        std::vector<rct::ctkeyV> legacy_ring_members;
        legacy_ring_members.reserve(tx.legacy_ring_signatures.size());

        for (const LegacyRingSignatureV4 &legacy_ring_signature : tx.legacy_ring_signatures)
        {
            // get the legacy ring members
            tx_validation_context.get_reference_set_proof_elements_v1(
                legacy_ring_signature.reference_set,
                tools::add_element(legacy_ring_members));
        }

        // 3. get seraphis reference set elements
        std::vector<std::uint64_t> sp_reference_indices_temp;
        std::vector<rct::keyV> sp_membership_proof_refs;
        sp_membership_proof_refs.reserve(tx.sp_membership_proofs.size());

        // TODO: implement
        // for (const SpMembershipProofV2 &sp_membership_proof : tx.sp_membership_proofs)
        // {
            // // a. decompress the reference set indices
            // if(!try_get_reference_indices_from_binned_reference_set_v1(sp_membership_proof.binned_reference_set,
            //         sp_reference_indices_temp))
            //     return false;

            // // b. get the seraphis reference set elements
            // tx_validation_context.get_reference_set_proof_elements_v2(sp_reference_indices_temp,
            //     tools::add_element(sp_membership_proof_refs));
        // }

        // 4. transaction id
        rct::key tx_id;
        get_sp_tx_squashed_v2_txid(tx, tx_id);

        // 5. validation_id = H_32(tx_id, legacy ring members, seraphis membership proof reference elements)
        SpFSTranscript transcript{config::HASH_KEY_SERAPHIS_TX_CONTEXTUAL_VALIDATION_ID_V2, sizeof(tx_id)};
        transcript.append("tx_id", tx_id);
        transcript.append("legacy_ring_members", legacy_ring_members);
        transcript.append("sp_membership_proof_refs", sp_membership_proof_refs);

        sp_hash_to_32(transcript.data(), transcript.size(), validation_id_out.bytes);
    } catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

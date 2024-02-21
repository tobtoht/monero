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

// A normal Seraphis transaction implemented in the 'squashed enote' model.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "device/device.hpp"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/sp_core_types.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_component_types_legacy.h"
#include "tx_validation_context.h"
#include "tx_validators.h"
#include "txtype_base.h"

//third party headers

//standard headers
#include <string>
#include <vector>

//forward declarations


namespace sp
{

////
// Normal Seraphis tx in the squashed enote model
// - input membership/ownership/key image validity (legacy): clsag proofs (one per input)
// - input membership (seraphis): full chain membership proofs (one per input)
// - input ownership/key image validity (seraphis): seraphis composition proofs (one per input)
// - input reference sets (legacy): set of on-chain indices
// - outputs: seraphis enotes
// - range proofs: Bulletproof+ (aggregated range proofs for all seraphis inputs' masked commitments and new output
//   enotes' commitments)
// - fees: discretized
// - memo field: sorted TLV format
///
struct SpTxSquashedV2 final
{
    enum class SemanticRulesVersion : unsigned char
    {
        MOCK = 0,
        ONE = 1
    };

    /// semantic rules version
    SemanticRulesVersion tx_semantic_rules_version;

    /// legacy tx input images (spent legacy enotes)
    std::vector<LegacyEnoteImageV2> legacy_input_images;
    /// seraphis tx input images (spent seraphis enotes)
    std::vector<SpEnoteImageV1> sp_input_images;
    /// tx outputs (new seraphis enotes)
    std::vector<SpEnoteV1> outputs;
    /// balance proof (balance proof and range proofs)
    SpBalanceProofV1 balance_proof;
    /// ring signature proofs: membership and ownership/key-image-legitimacy for each legacy input
    std::vector<LegacyRingSignatureV4> legacy_ring_signatures;
    /// composition proofs: ownership/key-image-legitimacy for each seraphis input
    std::vector<SpImageProofV1> sp_image_proofs;
    /// Full chain membership proofs on squashed enotes: membership for each seraphis input
    std::vector<SpMembershipProofV2> sp_membership_proofs;
    /// supplemental data for tx
    SpTxSupplementV1 tx_supplement;
    /// the transaction fee (discretized representation)
    DiscretizedFee tx_fee;
};

/**
* brief: get_sp_tx_squashed_v2_txid - get the transaction id
* param: tx -
* outparam: tx_id_out -
*/
void get_sp_tx_squashed_v2_txid(const SpTxSquashedV2 &tx, rct::key &tx_id_out);
/**
* brief: make_seraphis_tx_squashed_v2 - make an SpTxSquashedV2 transaction
* ...
* outparam: tx_out -
*/
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
    SpTxSquashedV2 &tx_out);
void make_seraphis_tx_squashed_v2(const SpTxSquashedV2::SemanticRulesVersion semantic_rules_version,
    SpPartialTxV1 partial_tx,
    std::vector<SpMembershipProofV2> sp_membership_proofs,
    SpTxSquashedV2 &tx_out);
void make_seraphis_tx_squashed_v2(const SpTxSquashedV2::SemanticRulesVersion semantic_rules_version,
    SpPartialTxV1 partial_tx,
    std::vector<SpAlignableMembershipProofV2> alignable_membership_proofs,
    SpTxSquashedV2 &tx_out);

/**
* brief: semantic_config_component_counts_v1 - component count configuration for a given semantics rule version
* param: tx_semantic_rules_version -
* return: allowed component counts for the given semantics rules version
*/
SemanticConfigComponentCountsV1 semantic_config_component_counts_v1(
    const SpTxSquashedV2::SemanticRulesVersion tx_semantic_rules_version);
/**
* brief: semantic_config_legacy_ref_sets_v1 - legacy reference set configuration for a given semantics rule version
* param: tx_semantic_rules_version -
* return: allowed reference set configuration for the given semantics rules version
*/
SemanticConfigLegacyRefSetV1 semantic_config_legacy_ref_sets_v1(
    const SpTxSquashedV2::SemanticRulesVersion tx_semantic_rules_version);
/**
* brief: semantic_config_sp_ref_sets_v2 - seraphis reference set configuration for a given semantics rule version
* param: tx_semantic_rules_version -
* return: allowed reference set configuration for the given semantics rules version
*/
SemanticConfigSpRefSetV2 semantic_config_sp_ref_sets_v2(
    const SpTxSquashedV2::SemanticRulesVersion tx_semantic_rules_version);


//// tx base concept implementations

/// short descriptor of the tx type
template <>
inline std::string tx_descriptor<SpTxSquashedV2>() { return "SpSquashedV2"; }

/// tx structure version
template <>
inline unsigned char tx_structure_version<SpTxSquashedV2>()
{
    return static_cast<unsigned char>(TxStructureVersionSp::TxTypeSpSquashedV2);
}

/// version of an SpTxSquashedV2 tx
inline tx_version_t tx_version_from(const SpTxSquashedV2::SemanticRulesVersion tx_semantic_rules_version)
{
    return tx_version_from<SpTxSquashedV2>(static_cast<unsigned char>(tx_semantic_rules_version));
}

/// transaction validators
template <>
bool validate_tx_semantics<SpTxSquashedV2>(const SpTxSquashedV2 &tx);
template <>
bool validate_tx_key_images<SpTxSquashedV2>(const SpTxSquashedV2 &tx, const TxValidationContext &tx_validation_context);
template <>
bool validate_tx_amount_balance<SpTxSquashedV2>(const SpTxSquashedV2 &tx);
template <>
bool validate_tx_input_proofs<SpTxSquashedV2>(const SpTxSquashedV2 &tx, const TxValidationContext &tx_validation_context);
template <>
bool validate_txs_batchable<SpTxSquashedV2>(const std::vector<const SpTxSquashedV2*> &txs,
    const TxValidationContext &tx_validation_context);

/// contextual validation id
/// - can be used for checking if an already-validated tx (whose contextual validation id was recorded) is still valid
///   against a validation context that may have changed (e.g. due to a reorg)
bool try_get_tx_contextual_validation_id(const SpTxSquashedV2 &tx,
    const TxValidationContext &tx_validation_context,
    rct::key &validation_id_out);

} //namespace sp

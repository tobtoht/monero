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

#pragma once

#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "curve_trees.h"
#include "ringct/rctTypes.h"
#include "tree_sync.h"

#include <deque>
#include <memory>
#include <unordered_map>


namespace fcmp_pp
{
namespace curve_trees
{
//----------------------------------------------------------------------------------------------------------------------
using BlockIdx  = uint64_t;
using BlockHash = crypto::hash;

using LeafIdx       = uint64_t;
using LayerIdx      = std::size_t;
using ChildChunkIdx = uint64_t;

using OutputRef = crypto::hash;
OutputRef get_output_ref(const OutputPair &o);

struct BlockMeta final
{
    BlockIdx blk_idx;
    BlockHash blk_hash;
    uint64_t n_leaf_tuples;
};

// We need to use a ref count on all individual elems in the cache because it's possible for:
//  a) multiple blocks to share path elems that need to remain after pruning a block past the max reorg depth.
//  b) multiple registered outputs to share the same path elems.
// We can't remove a cached elem unless we know it's ref'd 0 times.
struct CachedTreeElemChunk final
{
    std::vector<std::array<uint8_t, 32UL>> tree_elems;
    uint64_t ref_count;
};

struct CachedLeafChunk final
{
    std::vector<OutputPair> leaves;
    uint64_t ref_count;
};

struct AssignedLeafIdx final
{
    bool assigned_leaf_idx{false};
    LeafIdx leaf_idx{0};

    void assign_leaf(const LeafIdx idx) { leaf_idx = idx; assigned_leaf_idx = true; }
    void unassign_leaf() { leaf_idx = 0; assigned_leaf_idx = false; }
};

using RegisteredOutputs = std::unordered_map<OutputRef, AssignedLeafIdx>;
using LeafCache         = std::unordered_map<ChildChunkIdx, CachedLeafChunk>;
using ChildChunkCache   = std::unordered_map<ChildChunkIdx, CachedTreeElemChunk>;

// TODO: technically this can be a vector. There should *always* be at least 1 entry for every layer
using TreeElemCache     = std::unordered_map<LayerIdx, ChildChunkCache>;

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// Syncs the tree and keeps a user's known received outputs up to date, all saved in memory.
// - The object does not store the entire tree locally. The object only stores what it needs in order to update paths
//   of known received outputs as it syncs.
// - The memory footprint of the TreeSyncMemory object is roughly all known output paths and the last chunk of tree
//   elems of every layer of the tree the last N blocks. The latter is required to handle reorgs up to N blocks deep.
// - WARNING: the implementation is not thread safe, it expects synchronous calls.
//   TODO: use a mutex to enforce thread safety.
template<typename C1, typename C2>
class TreeSyncMemory final : public TreeSync<C1, C2>
{
public:
    TreeSyncMemory(std::shared_ptr<CurveTrees<C1, C2>> &curve_trees,
        const std::size_t max_reorg_depth = ORPHANED_BLOCKS_MAX_COUNT):
            TreeSync<C1, C2>(curve_trees, max_reorg_depth)
    {};

    bool register_output(const OutputPair &output, const uint64_t unlock_block_idx) override;

    // TODO: bool cancel_output_registration

    void sync_block(const uint64_t block_idx,
        const crypto::hash &block_hash,
        const crypto::hash &prev_block_hash,
        std::vector<OutputContext> &&new_leaf_tuples) override;

    bool pop_block() override;

    bool get_output_path(const OutputPair &output, typename CurveTrees<C1, C2>::Path &path_out) const override;

// Internal helper functions
private:
    typename CurveTrees<C1, C2>::LastHashes get_last_hashes(const uint64_t n_leaf_tuples) const;

    typename CurveTrees<C1, C2>::LastChunkChildrenToTrim get_last_chunk_children_to_regrow(
        const std::vector<TrimLayerInstructions> &trim_instructions) const;

    typename CurveTrees<C1, C2>::LastHashes get_last_hashes_to_trim(
        const std::vector<TrimLayerInstructions> &trim_instructions) const;

    void deque_block(const BlockMeta &block);

// State held in memory
private:
    // The outputs that TreeSyncMemory should keep track of while syncing
    RegisteredOutputs m_registered_outputs;

    // Cached leaves and tree elems
    LeafCache m_leaf_cache;
    TreeElemCache m_tree_elem_cache;

    // Used for getting tree extensions and reductions when growing and trimming respectively
    // - These are unspecific to the wallet's registered outputs. These are strictly necessary to ensure we can rebuild
    //   the tree extensions and reductions for each block correctly locally when syncing.
    std::deque<BlockMeta> m_cached_blocks;

// TODO: serialization
};
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace curve_trees
}//namespace fcmp_pp
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

#include "common/unordered_containers_boost_serialization.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "curve_trees.h"
#include "ringct/rctTypes.h"
#include "serialization/array.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/pair.h"
#include "serialization/serialization.h"
#include "tree_sync.h"

#include <boost/serialization/array.hpp>
#include <boost/serialization/deque.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/version.hpp>
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

using UnlockBlockIdx  = BlockIdx;
using CreatedBlockIdx = BlockIdx;
using NumOutputs      = std::size_t;

using OutputRef = crypto::hash;

struct BlockMeta final
{
    BlockIdx blk_idx;
    BlockHash blk_hash;
    uint64_t n_leaf_tuples;

    template <class Archive>
    inline void serialize(Archive &a, const unsigned int ver)
    {
        a & blk_hash;
        a & blk_idx;
        a & n_leaf_tuples;
    }

    BEGIN_SERIALIZE_OBJECT()
        FIELD(blk_idx)
        FIELD(blk_hash)
        FIELD(n_leaf_tuples)
    END_SERIALIZE()
};

// We need to use a ref count on all individual elems in the cache because it's possible for:
//  a) multiple blocks to share path elems that need to remain after pruning a block past the max reorg depth.
//  b) multiple registered outputs to share the same path elems.
// We can't remove a cached elem unless we know it's ref'd 0 times.
struct CachedLeafChunk final
{
    std::vector<OutputPair> leaves;
    uint64_t ref_count;

    template <class Archive>
    inline void serialize(Archive &a, const unsigned int ver)
    {
        a & leaves;
        a & ref_count;
    }

    BEGIN_SERIALIZE_OBJECT()
        FIELD(leaves)
        FIELD(ref_count)
    END_SERIALIZE()
};

struct CachedTreeElemChunk final
{
    std::vector<std::array<uint8_t, 32UL>> tree_elems;
    uint64_t ref_count;

    template <class Archive>
    inline void serialize(Archive &a, const unsigned int ver)
    {
        a & tree_elems;
        a & ref_count;
    }

    BEGIN_SERIALIZE_OBJECT()
        FIELD(tree_elems)
        FIELD(ref_count)
    END_SERIALIZE()
};

struct AssignedLeafIdx final
{
    bool assigned_leaf_idx{false};
    LeafIdx leaf_idx{0};

    void assign_leaf(const LeafIdx idx) { leaf_idx = idx; assigned_leaf_idx = true; }
    void unassign_leaf() { leaf_idx = 0; assigned_leaf_idx = false; }

    template <class Archive>
    inline void serialize(Archive &a, const unsigned int ver)
    {
        a & assigned_leaf_idx;
        a & leaf_idx;
    }

    BEGIN_SERIALIZE_OBJECT()
        FIELD(assigned_leaf_idx)
        FIELD(leaf_idx)
    END_SERIALIZE()
};

using LockedOutputsByUnlock  = std::unordered_map<UnlockBlockIdx, std::vector<OutputContext>>;
using LockedOutputRefs       = std::unordered_map<UnlockBlockIdx, NumOutputs>;
using LockedOutputsByCreated = std::unordered_map<CreatedBlockIdx, LockedOutputRefs>;

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
// - The memory footprint of the TreeSyncMemory object is roughly ALL locked outputs in the chain, all known output
//   paths, and the last chunk of tree elems at every layer of the tree the last N blocks. The latter is required to
//   handle reorgs up to N blocks deep.
// - WARNING: the implementation is not thread safe, it expects synchronous calls.
//   TODO: use a mutex to enforce thread safety.
template<typename C1, typename C2>
class TreeSyncMemory final : public TreeSync<C1, C2>
{
public:
    TreeSyncMemory(std::shared_ptr<CurveTrees<C1, C2>> curve_trees,
        const uint64_t max_reorg_depth = ORPHANED_BLOCKS_MAX_COUNT):
            TreeSync<C1, C2>(curve_trees, max_reorg_depth)
    {};

    bool register_output(const OutputPair &output, const uint64_t unlock_block_idx) override;

    // TODO: bool cancel_output_registration

    void sync_block(const uint64_t block_idx,
        const crypto::hash &block_hash,
        const crypto::hash &prev_block_hash,
        const fcmp_pp::curve_trees::OutputsByUnlockBlock &outs_by_unlock_block) override;

    bool pop_block() override;

    bool get_output_path(const OutputPair &output, typename CurveTrees<C1, C2>::Path &path_out) const override;

// Public functions not part of TreeSync interface
public:
    uint64_t get_output_count() const { return m_output_count; }

    // Clear all state
    void clear();

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
    // Locked outputs in the chain that we use to grow the tree with internally upon unlock
    LockedOutputsByUnlock m_locked_outputs;
    LockedOutputsByCreated m_locked_output_refs;

    // Keep a global output counter so the caller knows how output id's should be set
    uint64_t m_output_count{0};

    // The outputs that TreeSyncMemory should keep track of while syncing
    RegisteredOutputs m_registered_outputs;

    // Cached leaves and tree elems
    LeafCache m_leaf_cache;
    TreeElemCache m_tree_elem_cache;

    // Used for getting tree extensions and reductions when growing and trimming respectively
    // - These are unspecific to the wallet's registered outputs. These are strictly necessary to ensure we can rebuild
    //   the tree extensions and reductions for each block correctly locally when syncing.
    std::deque<BlockMeta> m_cached_blocks;

// Serialization
public:
    template <class Archive>
    inline void serialize(Archive &a, const unsigned int ver)
    {
        a & m_locked_outputs;
        a & m_locked_output_refs;
        a & m_output_count;
        a & m_registered_outputs;
        a & m_leaf_cache;
        a & m_tree_elem_cache;
        a & m_cached_blocks;
    }

    BEGIN_SERIALIZE_OBJECT()
        VERSION_FIELD(0)
        FIELD(m_locked_outputs)
        FIELD(m_locked_output_refs)
        FIELD(m_output_count)
        FIELD(m_registered_outputs)
        FIELD(m_leaf_cache)
        FIELD(m_tree_elem_cache)
        FIELD(m_cached_blocks)
        // It's possible for m_cached_blocks.size() > m_max_reorg_depth if the max reorg depth changes across runs.
        // This is ok as implemented. m_cached_blocks.size() will stay constant while syncing in this case.
    END_SERIALIZE()
};
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace curve_trees
}//namespace fcmp_pp

// Since BOOST_CLASS_VERSION does not work for templated class, implement it
namespace boost
{
namespace serialization
{
template<typename C1, typename C2>
struct version<fcmp_pp::curve_trees::TreeSyncMemory<C1, C2>>
{
    static const int VERSION = 0;
    typedef mpl::int_<VERSION> type;
    typedef mpl::integral_c_tag tag;
    BOOST_STATIC_CONSTANT(unsigned int, value = version::type::value);
    BOOST_MPL_ASSERT((
        boost::mpl::less<
            boost::mpl::int_<VERSION>,
            boost::mpl::int_<256>
        >
    ));
};
}
}

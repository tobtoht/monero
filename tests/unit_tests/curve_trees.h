// Copyright (c) 2014, The Monero Project
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

#include "fcmp_pp/curve_trees.h"
#include "fcmp_pp/tower_cycle.h"
#include "unit_tests_utils.h"

using Helios       = fcmp_pp::curve_trees::Helios;
using Selene       = fcmp_pp::curve_trees::Selene;
using CurveTreesV1 = fcmp_pp::curve_trees::CurveTreesV1;

//----------------------------------------------------------------------------------------------------------------------
namespace test
{
const std::vector<fcmp_pp::curve_trees::OutputContext> generate_random_outputs(const CurveTreesV1 &curve_trees,
    const std::size_t old_n_leaf_tuples,
    const std::size_t new_n_leaf_tuples);

std::shared_ptr<CurveTreesV1> init_curve_trees_test(const std::size_t helios_chunk_width,
    const std::size_t selene_chunk_width,
    const std::size_t tree_depth,
    uint64_t &n_leaves_out);
}//namespace test
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
// Helper class to read/write a global tree in memory. It's only used in testing because normally the tree isn't kept
// in memory (it's stored in the db)
class CurveTreesGlobalTree
{
public:
    CurveTreesGlobalTree(CurveTreesV1 &curve_trees): m_curve_trees(curve_trees) {};

//member structs
public:
    template<typename C>
    using Layer = std::vector<typename C::Point>;

    // A complete tree, useful for testing (don't want to keep the whole tree in memory during normal operation)
    struct Tree final
    {
        std::vector<fcmp_pp::curve_trees::OutputPair> leaves;
        std::vector<Layer<Helios>> c1_layers;
        std::vector<Layer<Selene>> c2_layers;
    };

//public member functions
public:
    // Read the in-memory tree and get the number of leaf tuples
    std::size_t get_num_leaf_tuples() const;

    // Grow tree by provided new_n_leaf_tuples
    bool grow_tree(const std::size_t expected_old_n_leaf_tuples, const std::size_t new_n_leaf_tuples);

    // Trim the provided number of leaf tuples from the tree
    bool trim_tree(const std::size_t expected_old_n_leaf_tuples, const std::size_t trim_n_leaf_tuples);

    // Validate the in-memory tree by re-hashing every layer, starting from root and working down to leaf layer
    bool audit_tree(const std::size_t expected_n_leaf_tuples) const;

    // Get the path in the tree of the provided leaf idx
    CurveTreesV1::Path get_path_at_leaf_idx(const std::size_t leaf_idx) const;

    // Hint: use num leaf tuples in the tree to determine the type
    std::array<uint8_t, 32UL> get_tree_root() const;

private:
    // Use the tree extension to extend the in-memory tree
    void extend_tree(const CurveTreesV1::TreeExtension &tree_extension);

    // Use the tree reduction to reduce the in-memory tree
    void reduce_tree(const CurveTreesV1::TreeReduction &tree_reduction);

    // Read the in-memory tree and get the last hashes from each layer in the tree
    CurveTreesV1::LastHashes get_last_hashes() const;

    // Read the in-memory tree and get data from what will be the last chunks after trimming the tree to the provided
    // number of leaves
    // - This function is useful to collect all tree data necessary to perform the actual trim operation
    // - This function can return elems from each last chunk that will need to be trimmed
    CurveTreesV1::LastHashes get_last_hashes_to_trim(
        const std::vector<fcmp_pp::curve_trees::TrimLayerInstructions> &trim_instructions) const;

    CurveTreesV1::LastChunkChildrenToTrim get_all_last_chunk_children_to_trim(
        const std::vector<fcmp_pp::curve_trees::TrimLayerInstructions> &trim_instructions);

    // logging helpers
    void log_last_hashes(const CurveTreesV1::LastHashes &last_hashes);
    void log_tree_extension(const CurveTreesV1::TreeExtension &tree_extension);
    void log_tree();

private:
    CurveTreesV1 &m_curve_trees;
    Tree m_tree = Tree{};
};
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------

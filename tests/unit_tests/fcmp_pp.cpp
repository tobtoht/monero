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

#include "gtest/gtest.h"

#include "common/container_helpers.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "curve_trees.h"
#include "fcmp_pp/prove.h"
#include "fcmp_pp/tower_cycle.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"

#include "crypto/crypto.h"
#include "crypto/generators.h"

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
struct OutputContextsAndKeys
{
    std::vector<crypto::secret_key> x_vec;
    std::vector<crypto::secret_key> y_vec;
    std::vector<fcmp_pp::curve_trees::OutputContext> outputs;
};
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static rct::key derive_key_image_generator(const rct::key O)
{
    crypto::public_key I;
    crypto::derive_key_image_generator(rct::rct2pk(O), I);
    return rct::pk2rct(I);
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void *rerandomize_output_manual(const rct::key &O, const rct::key &C)
{
    // sample random r_o, r_i, r_r_i, r_c in [0, l)
    rct::key r_o = rct::skGen();
    rct::key r_i = rct::skGen();
    rct::key r_r_i = rct::skGen();
    rct::key r_c = rct::skGen();

    // O~ = O + r_o T
    rct::key O_tilde = rct::scalarmultKey(rct::pk2rct(crypto::get_T()), r_o);
    O_tilde = rct::addKeys(O_tilde, O);

    // I = Hp(O)
    // I~ = I + r_i U
    const rct::key I = derive_key_image_generator(O);
    rct::key I_tilde = rct::scalarmultKey(rct::pk2rct(crypto::get_U()), r_i);
    I_tilde = rct::addKeys(I_tilde, I);

    // precomp T
    const ge_p3 T_p3 = crypto::get_T_p3();
    ge_dsmp T_dsmp;
    ge_dsm_precomp(T_dsmp, &T_p3);

    // R = r_i V + r_r_i T
    rct::key R;
    rct::addKeys3(R, r_i, rct::pk2rct(crypto::get_V()), r_r_i, T_dsmp);

    // C~ = C + r_c G
    rct::key C_tilde;
    rct::addKeys1(C_tilde, r_c, C);

    // make rerandomized output
    CResult res = ::rerandomized_output_new(O_tilde.bytes,
        I_tilde.bytes,
        R.bytes,
        C_tilde.bytes,
        r_o.bytes,
        r_i.bytes,
        r_r_i.bytes,
        r_c.bytes);
    CHECK_AND_ASSERT_THROW_MES(res.err == nullptr, "rerandomize_output_manual: encountered error in rerandomized_output_new");
    CHECK_AND_ASSERT_THROW_MES(res.value != nullptr, "rerandomize_output_manual: encountered unexpected value in rerandomized_output_new");

    return res.value;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static const OutputContextsAndKeys generate_random_outputs(const CurveTreesV1 &curve_trees,
    const std::size_t old_n_leaf_tuples,
    const std::size_t new_n_leaf_tuples)
{
    OutputContextsAndKeys outs;
    outs.x_vec.reserve(new_n_leaf_tuples);
    outs.y_vec.reserve(new_n_leaf_tuples);
    outs.outputs.reserve(new_n_leaf_tuples);

    for (std::size_t i = 0; i < new_n_leaf_tuples; ++i)
    {
        const std::uint64_t output_id = old_n_leaf_tuples + i;

        // Generate random output tuple
        crypto::secret_key o,c;
        crypto::public_key O,C;
        crypto::generate_keys(O, o, o, false);
        crypto::generate_keys(C, c, c, false);

        rct::key C_key = rct::pk2rct(C);
        auto output_pair = fcmp_pp::curve_trees::OutputPair{
                .output_pubkey = std::move(O),
                .commitment    = std::move(C_key)
            };

        auto output_context = fcmp_pp::curve_trees::OutputContext{
                .output_id   = output_id,
                .output_pair = std::move(output_pair)
            };

        // Output pubkey O = xG + yT
        // In this test, x is o, y is zero
        crypto::secret_key x = std::move(o);
        crypto::secret_key y;
        sc_0((unsigned char *)y.data);

        outs.x_vec.emplace_back(std::move(x));
        outs.y_vec.emplace_back(std::move(y));
        outs.outputs.emplace_back(std::move(output_context));
    }

    return outs;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
TEST(fcmp_pp, prove)
{
    static const std::size_t N_INPUTS = 8;

    static const std::size_t selene_chunk_width = fcmp_pp::curve_trees::SELENE_CHUNK_WIDTH;
    static const std::size_t helios_chunk_width = fcmp_pp::curve_trees::HELIOS_CHUNK_WIDTH;
    static const std::size_t tree_depth = 3;

    LOG_PRINT_L1("Test prove with selene chunk width " << selene_chunk_width
        << ", helios chunk width " << helios_chunk_width << ", tree depth " << tree_depth);

    uint64_t min_leaves_needed_for_tree_depth = 0;
    const auto curve_trees = test::init_curve_trees_test(selene_chunk_width,
        helios_chunk_width,
        tree_depth,
        min_leaves_needed_for_tree_depth);

    LOG_PRINT_L1("Initializing tree with " << min_leaves_needed_for_tree_depth << " leaves");

    // Init tree in memory
    CurveTreesGlobalTree global_tree(*curve_trees);
    const auto new_outputs = generate_random_outputs(*curve_trees, 0, min_leaves_needed_for_tree_depth);
    ASSERT_TRUE(global_tree.grow_tree(0, min_leaves_needed_for_tree_depth, new_outputs.outputs));

    LOG_PRINT_L1("Finished initializing tree with " << min_leaves_needed_for_tree_depth << " leaves");

    const auto tree_root = global_tree.get_tree_root();

    // Keep them cached across runs
    std::vector<const uint8_t *> selene_branch_blinds;
    std::vector<const uint8_t *> helios_branch_blinds;

    std::vector<const uint8_t *> fcmp_prove_inputs;
    std::vector<crypto::key_image> key_images;
    std::vector<crypto::ec_point> pseudo_outs;

    // Create proof for every leaf in the tree
    for (std::size_t leaf_idx = 0; leaf_idx < global_tree.get_n_leaf_tuples(); ++leaf_idx)
    {
        LOG_PRINT_L1("Constructing proof inputs for leaf idx " << leaf_idx);

        const auto path = global_tree.get_path_at_leaf_idx(leaf_idx);
        const std::size_t output_idx = leaf_idx % curve_trees->m_c1_width;

        // const fcmp_pp::curve_trees::OutputPair output_pair = {rct::rct2pk(path.leaves[output_idx].O), path.leaves[output_idx].C};
        // ASSERT_TRUE(curve_trees->audit_path(path, output_pair, global_tree.get_n_leaf_tuples()));
        // LOG_PRINT_L1("Passed the audit...\n");

        const auto x = (uint8_t *) new_outputs.x_vec[leaf_idx].data;
        const auto y = (uint8_t *) new_outputs.y_vec[leaf_idx].data;

        // Leaves
        std::vector<fcmp_pp::OutputBytes> output_bytes;
        output_bytes.reserve(path.leaves.size());
        for (const auto &leaf : path.leaves)
        {
            output_bytes.push_back({
                    .O_bytes = (uint8_t *)&leaf.O.bytes,
                    .I_bytes = (uint8_t *)&leaf.I.bytes,
                    .C_bytes = (uint8_t *)&leaf.C.bytes,
                });
        }
        const fcmp_pp::OutputChunk leaves{output_bytes.data(), output_bytes.size()};

        const auto rerandomized_output = fcmp_pp::rerandomize_output(output_bytes[output_idx]);

        pseudo_outs.emplace_back(fcmp_pp::pseudo_out(rerandomized_output));

        key_images.emplace_back();
        crypto::generate_key_image(rct::rct2pk(path.leaves[output_idx].O),
            new_outputs.x_vec[leaf_idx],
            key_images.back());

        // selene scalars from helios points
        std::vector<std::vector<fcmp_pp::tower_cycle::Selene::Scalar>> selene_scalars;
        std::vector<fcmp_pp::tower_cycle::Selene::Chunk> selene_chunks;
        for (const auto &helios_points : path.c2_layers)
        {
            // Exclude the root
            if (helios_points.size() == 1)
                break;
            selene_scalars.emplace_back();
            auto &selene_layer = selene_scalars.back();
            selene_layer.reserve(helios_points.size());
            for (const auto &c2_point : helios_points)
                selene_layer.emplace_back(curve_trees->m_c2->point_to_cycle_scalar(c2_point));
            // Padding with 0's
            for (std::size_t i = helios_points.size(); i < curve_trees->m_c1_width; ++i)
                selene_layer.emplace_back(curve_trees->m_c1->zero_scalar());
            selene_chunks.emplace_back(fcmp_pp::tower_cycle::Selene::Chunk{selene_layer.data(), selene_layer.size()});
        }
        const Selene::ScalarChunks selene_scalar_chunks{selene_chunks.data(), selene_chunks.size()};

        // helios scalars from selene points
        std::vector<std::vector<fcmp_pp::tower_cycle::Helios::Scalar>> helios_scalars;
        std::vector<fcmp_pp::tower_cycle::Helios::Chunk> helios_chunks;
        for (const auto &selene_points : path.c1_layers)
        {
            // Exclude the root
            if (selene_points.size() == 1)
                break;
            helios_scalars.emplace_back();
            auto &helios_layer = helios_scalars.back();
            helios_layer.reserve(selene_points.size());
            for (const auto &c1_point : selene_points)
                helios_layer.emplace_back(curve_trees->m_c1->point_to_cycle_scalar(c1_point));
            // Padding with 0's
            for (std::size_t i = selene_points.size(); i < curve_trees->m_c2_width; ++i)
                helios_layer.emplace_back(curve_trees->m_c2->zero_scalar());
            helios_chunks.emplace_back(fcmp_pp::tower_cycle::Helios::Chunk{helios_layer.data(), helios_layer.size()});
        }
        const Helios::ScalarChunks helios_scalar_chunks{helios_chunks.data(), helios_chunks.size()};

        const auto path_rust = fcmp_pp::path_new(leaves,
            output_idx,
            helios_scalar_chunks,
            selene_scalar_chunks);

        // Collect blinds for rerandomized output
        const auto o_blind = fcmp_pp::o_blind(rerandomized_output);
        const auto i_blind = fcmp_pp::i_blind(rerandomized_output);
        const auto i_blind_blind = fcmp_pp::i_blind_blind(rerandomized_output);
        const auto c_blind = fcmp_pp::c_blind(rerandomized_output);

        const auto blinded_o_blind = fcmp_pp::blind_o_blind(o_blind);
        const auto blinded_i_blind = fcmp_pp::blind_i_blind(i_blind);
        const auto blinded_i_blind_blind = fcmp_pp::blind_i_blind_blind(i_blind_blind);
        const auto blinded_c_blind = fcmp_pp::blind_c_blind(c_blind);

        const auto output_blinds = fcmp_pp::output_blinds_new(blinded_o_blind,
            blinded_i_blind,
            blinded_i_blind_blind,
            blinded_c_blind);

        // Cache branch blinds
        if (selene_branch_blinds.empty())
            for (std::size_t i = 0; i < helios_scalars.size(); ++i)
                selene_branch_blinds.emplace_back(fcmp_pp::selene_branch_blind());

        if (helios_branch_blinds.empty())
            for (std::size_t i = 0; i < selene_scalars.size(); ++i)
                helios_branch_blinds.emplace_back(fcmp_pp::helios_branch_blind());

        auto fcmp_prove_input = fcmp_pp::fcmp_pp_prove_input_new(x,
            y,
            rerandomized_output,
            path_rust,
            output_blinds,
            selene_branch_blinds,
            helios_branch_blinds);

        fcmp_prove_inputs.emplace_back(std::move(fcmp_prove_input));
        if (fcmp_prove_inputs.size() < N_INPUTS)
            continue;

        LOG_PRINT_L1("Constructing proof");
        const crypto::hash tx_hash{};
        const std::size_t n_layers = 1 + tree_depth;
        const auto proof = fcmp_pp::prove(
                tx_hash,
                fcmp_prove_inputs,
                n_layers
            );

        bool verify = fcmp_pp::verify(
                tx_hash,
                proof,
                n_layers,
                tree_root,
                pseudo_outs,
                key_images
            );
        ASSERT_TRUE(verify);

        fcmp_prove_inputs.clear();
        pseudo_outs.clear();
        key_images.clear();
    }
}
//----------------------------------------------------------------------------------------------------------------------
TEST(fcmp_pp, sal_completeness)
{
    // O, I, C, L
    const rct::key x = rct::skGen();
    const rct::key y = rct::skGen();
    rct::key O;
    rct::addKeys2(O, x, y, rct::pk2rct(crypto::get_T())); // O = x G + y T
    const rct::key I = derive_key_image_generator(O);
    const rct::key C = rct::pkGen();
    crypto::key_image L;
    crypto::generate_key_image(rct::rct2pk(O), rct::rct2sk(x), L);

    // Rerandomize
    uint8_t *rerandomized_output{fcmp_pp::rerandomize_output(fcmp_pp::OutputBytes{
        .O_bytes = O.bytes,
        .I_bytes = I.bytes,
        .C_bytes = C.bytes
    })};

    // Generate signable_tx_hash
    const crypto::hash signable_tx_hash = crypto::rand<crypto::hash>();

    // Get the input
    void *fcmp_input = fcmp_input_ref(rerandomized_output);

    // Prove
    const fcmp_pp::FcmpPpSalProof sal_proof = fcmp_pp::prove_sal(signable_tx_hash,
        rct::rct2sk(x),
        rct::rct2sk(y),
        rerandomized_output);
    free(rerandomized_output);

    // Verify
    const bool ver = fcmp_pp::verify_sal(signable_tx_hash, fcmp_input, L, sal_proof);
    free(fcmp_input);

    EXPECT_TRUE(ver);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(fcmp_pp, membership_completeness)
{
    static const std::size_t MAX_NUM_INPUTS = 8;

    static const std::size_t selene_chunk_width = fcmp_pp::curve_trees::SELENE_CHUNK_WIDTH;
    static const std::size_t helios_chunk_width = fcmp_pp::curve_trees::HELIOS_CHUNK_WIDTH;
    static const std::size_t tree_depth = 3;
    static const std::size_t n_layers = 1 + tree_depth;

    LOG_PRINT_L1("Test prove with selene chunk width " << selene_chunk_width
        << ", helios chunk width " << helios_chunk_width << ", tree depth " << tree_depth);

    uint64_t min_leaves_needed_for_tree_depth = 0;
    const auto curve_trees = test::init_curve_trees_test(selene_chunk_width,
        helios_chunk_width,
        tree_depth,
        min_leaves_needed_for_tree_depth);

    LOG_PRINT_L1("Initializing tree with " << min_leaves_needed_for_tree_depth << " leaves");

    // Init tree in memory
    CurveTreesGlobalTree global_tree(*curve_trees);
    const auto new_outputs = generate_random_outputs(*curve_trees, 0, min_leaves_needed_for_tree_depth);
    ASSERT_TRUE(global_tree.grow_tree(0, min_leaves_needed_for_tree_depth, new_outputs.outputs));

    LOG_PRINT_L1("Finished initializing tree with " << min_leaves_needed_for_tree_depth << " leaves");

    const size_t num_tree_leaves = global_tree.get_n_leaf_tuples();

    // Make branch blinds once purely for performance reasons (DO NOT DO THIS IN PRODUCTION)
    const size_t expected_num_selene_branch_blinds = (tree_depth + 1) / 2;
    LOG_PRINT_L1("Calculating " << expected_num_selene_branch_blinds << " Selene branch blinds");
    std::vector<const uint8_t *> selene_branch_blinds;
    for (size_t i = 0; i < expected_num_selene_branch_blinds; ++i)
        selene_branch_blinds.emplace_back(fcmp_pp::selene_branch_blind());

    const size_t expected_num_helios_branch_blinds = tree_depth / 2;
    LOG_PRINT_L1("Calculating " << expected_num_helios_branch_blinds << " Helios branch blinds");
    std::vector<const uint8_t *> helios_branch_blinds;
    for (size_t i = 0; i < expected_num_helios_branch_blinds; ++i)
        helios_branch_blinds.emplace_back(fcmp_pp::helios_branch_blind());

    // For every supported input size...
    for (size_t num_inputs = 1; num_inputs <= MAX_NUM_INPUTS; ++num_inputs)
    {
        LOG_PRINT_L1("Starting " << num_inputs << "-in " << n_layers << "-layer test case");

        // Build up a set of `num_inputs` inputs to prove membership on
        ASSERT_LE(num_inputs, num_tree_leaves);
        std::set<size_t> selected_indices;
        std::vector<const void*> fcmp_raw_inputs;
        fcmp_raw_inputs.reserve(num_inputs);
        std::vector<const uint8_t*> fcmp_provable_inputs;
        fcmp_provable_inputs.reserve(num_inputs);
        while (selected_indices.size() < num_inputs)
        {
            // Generate a random unique leaf tuple index within the tree
            const size_t leaf_idx = crypto::rand_idx(num_tree_leaves);
            if (selected_indices.count(leaf_idx))
                continue;
            else
                selected_indices.insert(leaf_idx);

            // Fetch path
            const auto path = global_tree.get_path_at_leaf_idx(leaf_idx);
            const std::size_t output_idx = leaf_idx % curve_trees->m_c1_width;

            // Collect leaves in this path
            std::vector<fcmp_pp::OutputBytes> output_bytes;
            output_bytes.reserve(path.leaves.size());
            for (const auto &leaf : path.leaves)
            {
                output_bytes.push_back({
                        .O_bytes = (uint8_t *)&leaf.O.bytes,
                        .I_bytes = (uint8_t *)&leaf.I.bytes,
                        .C_bytes = (uint8_t *)&leaf.C.bytes,
                    });
            }
            const fcmp_pp::OutputChunk leaves{output_bytes.data(), output_bytes.size()};

            // selene scalars from helios points
            std::vector<std::vector<fcmp_pp::tower_cycle::Selene::Scalar>> selene_scalars;
            std::vector<fcmp_pp::tower_cycle::Selene::Chunk> selene_chunks;
            for (const auto &helios_points : path.c2_layers)
            {
                // Exclude the root
                if (helios_points.size() == 1)
                    break;
                selene_scalars.emplace_back();
                auto &selene_layer = selene_scalars.back();
                selene_layer.reserve(helios_points.size());
                for (const auto &c2_point : helios_points)
                    selene_layer.emplace_back(curve_trees->m_c2->point_to_cycle_scalar(c2_point));
                // Padding with 0's
                for (std::size_t i = helios_points.size(); i < curve_trees->m_c1_width; ++i)
                    selene_layer.emplace_back(curve_trees->m_c1->zero_scalar());
                selene_chunks.emplace_back(fcmp_pp::tower_cycle::Selene::Chunk{selene_layer.data(), selene_layer.size()});
            }
            const Selene::ScalarChunks selene_scalar_chunks{selene_chunks.data(), selene_chunks.size()};

            // helios scalars from selene points
            std::vector<std::vector<fcmp_pp::tower_cycle::Helios::Scalar>> helios_scalars;
            std::vector<fcmp_pp::tower_cycle::Helios::Chunk> helios_chunks;
            for (const auto &selene_points : path.c1_layers)
            {
                // Exclude the root
                if (selene_points.size() == 1)
                    break;
                helios_scalars.emplace_back();
                auto &helios_layer = helios_scalars.back();
                helios_layer.reserve(selene_points.size());
                for (const auto &c1_point : selene_points)
                    helios_layer.emplace_back(curve_trees->m_c1->point_to_cycle_scalar(c1_point));
                // Padding with 0's
                for (std::size_t i = selene_points.size(); i < curve_trees->m_c2_width; ++i)
                    helios_layer.emplace_back(curve_trees->m_c2->zero_scalar());
                helios_chunks.emplace_back(fcmp_pp::tower_cycle::Helios::Chunk{helios_layer.data(), helios_layer.size()});
            }
            const Helios::ScalarChunks helios_scalar_chunks{helios_chunks.data(), helios_chunks.size()};

            const auto path_rust = fcmp_pp::path_new(leaves,
                output_idx,
                helios_scalar_chunks,
                selene_scalar_chunks);

            // rerandomize output
            uint8_t *rerandomized_output = reinterpret_cast<uint8_t*>(rerandomize_output_manual(
                path.leaves.at(output_idx).O,
                path.leaves.at(output_idx).C));

            // check the size of our precalculated branch blind cache
            ASSERT_EQ(helios_scalars.size(), expected_num_selene_branch_blinds);
            ASSERT_EQ(selene_scalars.size(), expected_num_helios_branch_blinds);

            // Calculate output blinds for rerandomized output
            LOG_PRINT_L1("Calculating output blind");
            const auto o_blind = fcmp_pp::o_blind(rerandomized_output);
            const auto i_blind = fcmp_pp::i_blind(rerandomized_output);
            const auto i_blind_blind = fcmp_pp::i_blind_blind(rerandomized_output);
            const auto c_blind = fcmp_pp::c_blind(rerandomized_output);

            const auto blinded_o_blind = fcmp_pp::blind_o_blind(o_blind);
            const auto blinded_i_blind = fcmp_pp::blind_i_blind(i_blind);
            const auto blinded_i_blind_blind = fcmp_pp::blind_i_blind_blind(i_blind_blind);
            const auto blinded_c_blind = fcmp_pp::blind_c_blind(c_blind);

            const auto output_blinds = fcmp_pp::output_blinds_new(blinded_o_blind,
                blinded_i_blind,
                blinded_i_blind_blind,
                blinded_c_blind);
            
            // make provable FCMP input
            fcmp_provable_inputs.push_back(fcmp_pp::fcmp_prove_input_new(rerandomized_output,
                path_rust,
                output_blinds,
                selene_branch_blinds,
                helios_branch_blinds));
            
            // get FCMP input
            fcmp_raw_inputs.push_back(::fcmp_input_ref(rerandomized_output));

            // dealloc
            free(rerandomized_output);
            free(output_blinds);
        }

        ASSERT_EQ(fcmp_raw_inputs.size(), fcmp_provable_inputs.size());

        // Create FCMP proof
        LOG_PRINT_L1("Proving " << num_inputs << "-in " << n_layers << "-layer FCMP");
        const fcmp_pp::FcmpMembershipProof proof = fcmp_pp::prove_membership(fcmp_provable_inputs,
            n_layers);

        // Verify
        LOG_PRINT_L1("Verifying " << num_inputs << "-in " << n_layers << "-layer FCMP");
        EXPECT_TRUE(fcmp_pp::verify_membership(proof, n_layers, global_tree.get_tree_root(), fcmp_raw_inputs));
    }
}
//----------------------------------------------------------------------------------------------------------------------
TEST(fcmp_pp, read_write_rerandomized_output)
{
    rct::key bytes_in[8];
    for (size_t i = 0; i < 4; ++i)
        bytes_in[i] = rct::pkGen();
    for (size_t i = 4; i < 8; ++i)
        bytes_in[i] = rct::skGen();
    uint8_t bytes_out[8 * 32];

    static_assert(sizeof(bytes_in) == sizeof(bytes_out));
    static_assert(sizeof(bytes_out) == 8 * 32);

    CResult res = ::rerandomized_output_read(bytes_in[0].bytes);
    ASSERT_EQ(res.err, nullptr);
    ASSERT_NE(res.value, nullptr);
    void *rerandomized_output = res.value;

    res = ::rerandomized_output_write(rerandomized_output, bytes_out);
    ASSERT_EQ(res.err, nullptr);
    ASSERT_NE(res.value, nullptr);

    EXPECT_EQ(0, memcmp(bytes_in, bytes_out, sizeof(bytes_in)));

    free(rerandomized_output);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(fcmp_pp, force_init_gen_u_v)
{
#ifdef NDEBUG
    GTEST_SKIP() << "Generator reproduction assert statements don't trigger on Release builds";
#endif

    const ge_p3 U_p3 = crypto::get_U_p3();
    const ge_p3 V_p3 = crypto::get_V_p3();
    const ge_cached U_cached = crypto::get_U_cached();
    const ge_cached V_cached = crypto::get_V_cached();

    (void) U_p3, (void) V_p3, (void) U_cached, (void) V_cached;
}
//----------------------------------------------------------------------------------------------------------------------

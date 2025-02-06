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

#include "fcmp_pp_crypto.h"

#include "misc_log_ex.h"
#include "ringct/rctOps.h"

// static void print_bytes(const fe f)
// {
//     unsigned char bytes[32];
//     fe_tobytes(bytes, f);
//     for (int i = 0; i < 32; ++i)
//     {
//         printf("%d, ", bytes[i]);
//     }
//     printf("\n");
// }

// static void print_fe(const fe f)
// {
//     for (int i = 0; i < 10; ++i)
//     {
//         printf("%d, ", f[i]);
//     }
//     printf("\n");
// }

static bool sqrt_ext(fe y, const fe x)
{
    fe y_res;

    fe x2;
    fe_dbl(x2, x);

    fe b;
    fe_pow22523(b, x2);

    fe b_sq;
    fe_sq(b_sq, b);

    fe c;
    fe_mul(c, x2, b_sq);

    if (memcmp(c, fe_one, sizeof(fe)) == 0 || memcmp(c, fe_m1, sizeof(fe)) == 0)
    {
        fe_0(c);
        c[0] = 3;
    }

    fe c_sub_1;
    fe_sub(c_sub_1, c, fe_one);

    fe_mul(y_res, x, b);
    fe_mul(y_res, y_res, c_sub_1);

    if (fe_isnegative(y_res)) {
        fe_neg(y_res, y_res);
    }

    fe y_sq;
    fe_sq(y_sq, y_res);
    bool r = memcmp(x, y_sq, sizeof(fe)) == 0;

    fe_copy(y, y_res);
    return r;
};

namespace fcmp_pp
{
    // TODO: impl faster sqrt
    bool sqrt(fe y, const fe x)
    {
        return sqrt_ext(y, x);
    };
}//namespace fcmp_pp

static void inv_iso(fe u_out, fe w_out, const fe u, const fe w)
{
    // 4u
    fe_dbl(u_out, u);
    fe_dbl(u_out, u_out);
    // 2w
    fe_dbl(w_out, w);
};

static void inv_psi1(fe e_out, fe u_out, fe w_out, const fe e, const fe u, const fe w)
{
    fe e_res, u_res, w_res;

    fe tt;
    bool cc = sqrt_ext(tt, u);
    fe_copy(w_res, tt);
    fe w_;
    fe_copy(w_, w);
    fe_copy(e_res, e);

    if (!cc)
    {
        fe tt_sq;
        fe_sq(tt_sq, tt);
        fe neg_u_dbl;
        fe_dbl(neg_u_dbl, u);
        fe_neg(neg_u_dbl, neg_u_dbl);
        if (memcmp(tt_sq, neg_u_dbl, sizeof(fe)) == 0) {
            fe_mul(tt, tt, fe_sqrtm1);
        }

        fe_mul(w_, w, tt);

        fe e_sq;
        fe_sq(e_sq, e);
        fe_mul(w_res, fe_msqrt2b, e_sq);

        fe_mul(e_res, e_res, tt);
    }

    fe w_res_sq;
    fe_sq(w_res_sq, w_res);

    fe e_res_sq;
    fe_sq(e_res_sq, e_res);

    fe A_e_sq;
    fe_mul(A_e_sq, fe_a0, e_res_sq);

    fe w_res_w;
    fe_mul(w_res_w, w_res, w_);

    fe_sub(u_res, w_res_sq, A_e_sq);
    fe_reduce(u_res, u_res);
    fe_sub(u_res, u_res, w_res_w);
    fe_mul(u_res, u_res, fe_inv2);

    fe_copy(e_out, e_res);
    fe_copy(u_out, u_res);
    fe_copy(w_out, w_res);
};

static bool inv_psi2(fe u_out, fe w_out, const fe e, const fe u, const fe w)
{
    fe u_res, w_res;

    if (!fcmp_pp::sqrt(w_res, u))
        return false;
    fe e_sq;
    fe_sq(e_sq, e);
    fe Ap_e_sq;
    fe_mul(Ap_e_sq, fe_ap, e_sq);

    fe w_res_w;
    fe_mul(w_res_w, w_res, w);

    fe_sub(u_res, u, Ap_e_sq);
    fe_reduce(u_res, u_res);
    fe_sub(u_res, u_res, w_res_w);
    fe_mul(u_res, u_res, fe_inv2);

    fe_copy(u_out, u_res);
    fe_copy(w_out, w_res);

    return true;
};

static bool check_e_u_w(const fe e, const fe u, const fe w)
{
    static fe a;
    fe_1(a);
    fe_neg(a, a);
    fe A;
    fe_add(A, a, fe_d);
    fe_dbl(A, A);
    fe B;
    fe_sq(B, fe_a_sub_d);

    fe w_sq, u_w_sq;
    fe_sq(w_sq, w);
    fe_mul(u_w_sq, u, w_sq);

    fe u_sq, A_u_mul_e_sq, e_sq, e_sq_sq, B_mul_e_sq_sq, sum;
    fe_sq(u_sq, u);
    fe_mul(A_u_mul_e_sq, A, u);
    fe_sq(e_sq, e);
    fe_mul(A_u_mul_e_sq, A_u_mul_e_sq, e_sq);
    fe_sq(e_sq_sq, e_sq);
    fe_mul(B_mul_e_sq_sq, B, e_sq_sq);

    fe_reduce(A_u_mul_e_sq, A_u_mul_e_sq);
    fe_add(sum, u_sq, A_u_mul_e_sq);

    fe_reduce(sum, sum);
    fe_reduce(B_mul_e_sq_sq, B_mul_e_sq_sq);
    fe_add(sum, sum, B_mul_e_sq_sq);

    fe_reduce(sum, sum);

    if (memcmp(u_w_sq, sum, sizeof(fe)) != 0) {
        return false;
    }

    return true;
}

namespace fcmp_pp
{
//----------------------------------------------------------------------------------------------------------------------
bool mul8_is_identity(const ge_p3 &point) {
    ge_p2 point_ge_p2;
    ge_p3_to_p2(&point_ge_p2, &point);
    ge_p1p1 point_mul8;
    ge_mul8(&point_mul8, &point_ge_p2);
    ge_p2 point_mul8_p2;
    ge_p1p1_to_p2(&point_mul8_p2, &point_mul8);
    rct::key tmp;
    ge_tobytes(tmp.bytes, &point_mul8_p2);
    return tmp == rct::I;
}
//----------------------------------------------------------------------------------------------------------------------
// https://github.com/kayabaNerve/fcmp-plus-plus/blob/94744c5324e869a9483bbbd93a864e108304bf76/crypto/divisors/src/tests/torsion_check.rs
// Returns true if point is torsion free
// Pre-condition: point is a valid point and point*8 not equal to identity
// WARNING1: this approach needs to be carefully vetted academically and audited
// before it can be used in production.
// WARNING2: since fe_add and fe_sub expect the input fe's to be within a
// smaller domain than the output fe, we sometimes need to "reduce" a field elem
// to chain calls to fe_add and fe_sub. Notice all calls to fe_reduce.
bool torsion_check_vartime(const ge_p3 &point) {
    assert(!mul8_is_identity(point));

    // ed to wei
    fe e, u, w;
    {
        fe z_plus_ed_y, z_minus_ed_y;
        fe_add(z_plus_ed_y, fe_one, point.Y);
        fe_sub(z_minus_ed_y, fe_one, point.Y);

        // e
        fe_mul(e, z_minus_ed_y, point.X);
        // u
        fe_mul(u, fe_a_sub_d, z_plus_ed_y);
        fe_mul(u, u, point.X);
        fe_mul(u, u, e);
        // w
        fe_dbl(w, z_minus_ed_y);
    }

    assert(check_e_u_w(e, u, w));

    // Torsion check
    for (int i = 0; i < 2; ++i) {
        inv_iso(u, w, u, w);
        if (!inv_psi2(u, w, e, u, w)) {
            return false;
        }
        inv_psi1(e, u, w, e, u, w);
        assert(check_e_u_w(e, u, w));
    }

    fe _;
    inv_iso(u, _, u, w);

    if (!sqrt(u, u)) {
        return false;
    }

    return true;
}
//----------------------------------------------------------------------------------------------------------------------
rct::key clear_torsion(const ge_p3 &point) {
    // mul by inv 8, then mul by 8
    ge_p2 point_inv_8;
    ge_scalarmult(&point_inv_8, rct::INV_EIGHT.bytes, &point);
    ge_p1p1 point_inv_8_mul_8;
    ge_mul8(&point_inv_8_mul_8, &point_inv_8);
    ge_p3 torsion_cleared_point;
    ge_p1p1_to_p3(&torsion_cleared_point, &point_inv_8_mul_8);
    rct::key k_out;
    ge_p3_tobytes(k_out.bytes, &torsion_cleared_point);
    return k_out;
}
//----------------------------------------------------------------------------------------------------------------------
bool point_to_ed_y_derivatives(const rct::key &pub, EdYDerivatives &ed_y_derivatives) {
    if (pub == rct::I)
        return false;
    fe y;
    if (fe_frombytes_vartime(y, pub.bytes) != 0)
        return false;
    fe one;
    fe_1(one);
    // (1+y),(1-y)
    fe_add(ed_y_derivatives.one_plus_y, one, y);
    fe_sub(ed_y_derivatives.one_minus_y, one, y);
    return true;
}
//----------------------------------------------------------------------------------------------------------------------
void ed_y_derivatives_to_wei_x(const EdYDerivatives &pre_wei_x, rct::key &wei_x) {
    fe inv_one_minus_y;
    fe_invert(inv_one_minus_y, pre_wei_x.one_minus_y);
    fe_ed_y_derivatives_to_wei_x(wei_x.bytes, inv_one_minus_y, pre_wei_x.one_plus_y);
}
//----------------------------------------------------------------------------------------------------------------------
bool point_to_wei_x(const rct::key &pub, rct::key &wei_x) {
    EdYDerivatives ed_y_derivatives;
    if (!point_to_ed_y_derivatives(pub, ed_y_derivatives))
        return false;
    ed_y_derivatives_to_wei_x(ed_y_derivatives, wei_x);
    return true;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
}//namespace fcmp_pp

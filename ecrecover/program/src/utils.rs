use ziskos::{
    arith256_mod::{syscall_arith256_mod, SyscallArith256ModParams},
    exp_power_of_two,
    fcall_msb_pos_256,
    fcall_secp256k1_fp_inv,
    point256::SyscallPoint256,
    secp256k1_add::{syscall_secp256k1_add, SyscallSecp256k1AddParams},
    secp256k1_dbl::syscall_secp256k1_dbl,
};

use crate::constants::{G_X, G_Y, P, P_MINUS_ONE};

pub(crate) fn gt(x: &[u64; 4], y: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if x[i] > y[i] {
            return true;
        } else if x[i] < y[i] {
            return false;
        }
    }
    false
}

/// Given two 256-bit unsigned integers `x` and `y`, returns the result of the subtraction `x - y`
pub(crate) fn sub(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let xi = x[i];
        let yi = y[i] + borrow;
        if xi >= yi {
            result[i] = xi - yi;
            borrow = 0;
        } else {
            let r = (1u128 << 64) + xi as u128 - yi as u128;
            result[i] = r as u64;
            borrow = 1;
        }
    }

    result
}

/// Given a number 256-bit number `x`, uses the Euler's Criterion `x^{(p-1)/2} == -1 (mod p)` to assert it is not a quadratic residue.
/// It assumes that `x` is a field element.
pub(crate) fn assert_nqr_p(x: &[u64; 4]) {
    // Note: (p-1)/2 = 2^255 - 2^32 + 2^31 - 2^9 + 2^4 + 2^3 - 1

    //                x^(2^255) · x^(2^31) · x^(2^4) · x^(2^3)
    // x^((p-1)/2) = ------------------------------------------
    //                     x^(2^32) · x^(2^9) · x

    // Costs: 253 squarings, 9 multiplications

    // Compute the necessary powers of two
    let exp_3 = exp_power_of_two(x, &P, 3);
    let mut params = SyscallArith256ModParams {
        a: &exp_3,
        b: &exp_3,
        c: &[0, 0, 0, 0],
        module: &P,
        d: &mut [0, 0, 0, 0],
    };
    syscall_arith256_mod(&mut params);
    let exp_4 = *params.d;
    let exp_9 = exp_power_of_two(&exp_4, &P, 5);
    let exp_31 = exp_power_of_two(&exp_9, &P, 22);
    params.a = &exp_31;
    params.b = &exp_31;
    syscall_arith256_mod(&mut params);
    let exp_32 = *params.d;
    let exp_255 = exp_power_of_two(&exp_32, &P, 223);

    // --> Compute the numerator
    params.a = &exp_255;
    params.b = &exp_31;
    syscall_arith256_mod(&mut params);
    let _res = *params.d;
    params.a = &_res;
    params.b = &exp_4;
    syscall_arith256_mod(&mut params);
    let _res = *params.d;
    params.a = &_res;
    params.b = &exp_3;
    syscall_arith256_mod(&mut params);
    let num = *params.d;

    // --> Compute the denominator
    params.a = &exp_32;
    params.b = &exp_9;
    syscall_arith256_mod(&mut params);
    let _res = *params.d;
    params.a = &_res;
    params.b = x;
    syscall_arith256_mod(&mut params);
    let den = *params.d;

    // --> Compute the result
    // Hint the inverse of the denominator and check it
    let den_inv = fcall_secp256k1_fp_inv(&den);
    params.a = &den;
    params.b = &den_inv;
    syscall_arith256_mod(&mut params);
    assert_eq!(*params.d, [0x1, 0x0, 0x0, 0x0]);

    // Multiply and check the non-quadratic residue
    params.a = &num;
    params.b = &den_inv;
    syscall_arith256_mod(&mut params);
    assert_eq!(*params.d, P_MINUS_ONE);
}

/// Given points `p1` and `p2`, performs the point addition `p1 + p2` and assigns the result to `p1`.
/// It assumes that `p1` and `p2` are from the Secp256k1 curve, that `p1,p2 != 𝒪` and that `p2 != p1,-p1`
fn add_points_assign(p1: &mut SyscallPoint256, p2: &SyscallPoint256) {
    let mut params = SyscallSecp256k1AddParams { p1, p2 };
    syscall_secp256k1_add(&mut params);
}

/// Given a point `p1`, performs the point doubling `2·p1` and assigns the result to `p1`.
/// It assumes that `p1` is from the Secp256k1 curve and that `p1 != 𝒪`
///
/// Note: We don't need to assume that 2·p1 != 𝒪 because there are not points of order 2 on the Secp256k1 curve
fn double_point_assign(p1: &mut SyscallPoint256) {
    syscall_secp256k1_dbl(p1);
}

/// Given points `p1` and `p2`, performs the point addition `p1 + p2` and assigns the result to `p1`.
/// It assumes that `p1` and `p2` are from the Secp256k1 curve, that `p2 != 𝒪`
fn add_points_complete_assign(
    p1: &mut SyscallPoint256,
    p1_is_infinity: &mut bool,
    p2: &SyscallPoint256,
) {
    if p1.x != p2.x {
        add_points_assign(p1, p2);
    } else if p1.y == p2.y {
        double_point_assign(p1);
    } else {
        *p1_is_infinity = true;
    }
}

/// Given a point `p` and scalars `k1` and `k2`, computes the double scalar multiplication `k1·G + k2·p`
/// It assumes that `k1,k2 ∈ [1, N-1]` and that `p != 𝒪`
pub(crate) fn double_scalar_mul_with_g(
    k1: &[u64; 4],
    k2: &[u64; 4],
    p: &SyscallPoint256,
) -> (bool, SyscallPoint256) {
    // Start by precomputing g + p
    let mut gp = SyscallPoint256 { x: G_X, y: G_Y };
    let mut gp_is_infinity = false;
    add_points_complete_assign(&mut gp, &mut gp_is_infinity, p);

    // Hint the maximum length between the binary representations of k1 and k2
    // We will verify the output by recomposing both k1 and k2
    // Moreover, we should check that the first received bit (of either k1 or k2) is 1
    let (max_limb, max_bit) = fcall_msb_pos_256(k1, k2);

    // Perform the loop, based on the binary representation of k1 and k2
    // Start at 𝒪
    let mut res = SyscallPoint256 { x: [0u64; 4], y: [0u64; 4] };
    let mut res_is_infinity = true;
    let mut k1_rec = [0u64; 4];
    let mut k2_rec = [0u64; 4];
    // We do the first iteration separately
    let _max_limb = max_limb as usize;
    let k1_bit = (k1[_max_limb] >> max_bit) & 1;
    let k2_bit = (k2[_max_limb] >> max_bit) & 1;
    assert!(k1_bit == 1 || k2_bit == 1); // At least one of the scalars should start with 1
    if (k1_bit == 0) && (k2_bit == 1) {
        // If res is 𝒪, set res = p; otherwise, double res and add p
        if res_is_infinity {
            res.x = p.x;
            res.y = p.y;
            res_is_infinity = false;
        } else {
            double_point_assign(&mut res);
            add_points_complete_assign(&mut res, &mut res_is_infinity, p);
        }

        // Update k2_rec
        k2_rec[_max_limb] |= 1 << max_bit;
    } else if (k1_bit == 1) && (k2_bit == 0) {
        // If res is 𝒪, set res = g; otherwise, double res and add g
        if res_is_infinity {
            res.x = G_X;
            res.y = G_Y;
            res_is_infinity = false;
        } else {
            double_point_assign(&mut res);
            add_points_complete_assign(
                &mut res,
                &mut res_is_infinity,
                &SyscallPoint256 { x: G_X, y: G_Y },
            );
        }

        // Update k1_rec
        k1_rec[_max_limb] |= 1 << max_bit;
    } else if (k1_bit == 1) && (k2_bit == 1) {
        if res_is_infinity {
            // If (g + p) is 𝒪, do nothing; otherwise set res = (g + p)
            if !gp_is_infinity {
                res.x = gp.x;
                res.y = gp.y;
                res_is_infinity = false;
            }
        } else {
            // If (g + p) is 𝒪, simply double res; otherwise double res and add (g + p)
            double_point_assign(&mut res);
            if !gp_is_infinity {
                add_points_complete_assign(&mut res, &mut res_is_infinity, &gp);
            }
        }

        // Update k1_rec and k2_rec
        k1_rec[_max_limb] |= 1 << max_bit;
        k2_rec[_max_limb] |= 1 << max_bit;
    }

    // Perform the rest of the loop
    for i in (0..=max_limb).rev() {
        let _i = i as usize;
        let bit_len = if i == max_limb { max_bit-1 } else { 63 };
        for j in (0..=bit_len).rev() {
            let k1_bit = (k1[_i] >> j) & 1;
            let k2_bit = (k2[_i] >> j) & 1;

            if (k1_bit == 0) && (k2_bit == 0) {
                // If res is 𝒪, do nothing; otherwise, double
                if !res_is_infinity {
                    double_point_assign(&mut res);
                }
            } else if (k1_bit == 0) && (k2_bit == 1) {
                // If res is 𝒪, set res = p; otherwise, double res and add p
                if res_is_infinity {
                    res.x = p.x;
                    res.y = p.y;
                    res_is_infinity = false;
                } else {
                    double_point_assign(&mut res);
                    add_points_complete_assign(&mut res, &mut res_is_infinity, p);
                }

                // Update k2_rec
                k2_rec[_i] |= 1 << j;
            } else if (k1_bit == 1) && (k2_bit == 0) {
                // If res is 𝒪, set res = g; otherwise, double res and add g
                if res_is_infinity {
                    res.x = G_X;
                    res.y = G_Y;
                    res_is_infinity = false;
                } else {
                    double_point_assign(&mut res);
                    add_points_complete_assign(
                        &mut res,
                        &mut res_is_infinity,
                        &SyscallPoint256 { x: G_X, y: G_Y },
                    );
                }

                // Update k1_rec
                k1_rec[_i] |= 1 << j;
            } else if (k1_bit == 1) && (k2_bit == 1) {
                if res_is_infinity {
                    // If (g + p) is 𝒪, do nothing; otherwise set res = (g + p)
                    if !gp_is_infinity {
                        res.x = gp.x;
                        res.y = gp.y;
                        res_is_infinity = false;
                    }
                } else {
                    // If (g + p) is 𝒪, simply double res; otherwise double res and add (g + p)
                    double_point_assign(&mut res);
                    if !gp_is_infinity {
                        add_points_complete_assign(&mut res, &mut res_is_infinity, &gp);
                    }
                }

                // Update k1_rec and k2_rec
                k1_rec[_i] |= 1 << j;
                k2_rec[_i] |= 1 << j;
            }
        }
    }

    // Check that the recomposed scalars are the same as the received scalars
    assert_eq!(k1_rec, *k1);
    assert_eq!(k2_rec, *k2);

    (res_is_infinity, res)
}
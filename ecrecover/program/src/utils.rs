use ziskos::syscalls::{
    point256::SyscallPoint256,
    secp256k1_add::{syscall_secp256k1_add, SyscallSecp256k1AddParams},
    secp256k1_dbl::syscall_secp256k1_dbl,
};

/// Secp256k1 group of points generator
const G_X: [u64; 4] =
    [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC];
const G_Y: [u64; 4] =
    [0x9C47D08FFB10D4B8, 0xFD17B448A6855419, 0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465];
const G_Y_NEG: [u64; 4] =
    [0x63B82F6F04EF2777, 0x02E84BB7597AABE6, 0xA25B0403F1EEF757, 0xB7C52588D95C3B9A];

/// Given two 256-bit unsigned integers `x` and `y`, returns the result of the subtraction `x - y`
pub fn sub(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
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
        add_points_assign(p1, &p2);
    } else if p1.y == p2.y {
        double_point_assign(p1);
    } else {
        *p1_is_infinity = true;
    }
}

/// Given a point `p` and scalars `k1` and `k2`, computes the double scalar multiplication `k1·G + k2·p`
/// It assumes that `k1,k2 ∈ [1, N-1]` and that `p != G,𝒪`
pub fn double_scalar_mul_with_g(
    k1: &[u64; 4],
    k2: &[u64; 4],
    p: &SyscallPoint256,
) -> (bool, SyscallPoint256) {
    // Start by precomputing g + p
    let mut gp = SyscallPoint256 { x: [0u64; 4], y: [0u64; 4] };
    let mut gp_is_infinity = false;
    if p.x == G_X && p.y == G_Y_NEG {
        gp_is_infinity = true;
    } else {
        add_points_assign(&mut gp, &p);
    }

    // Get the the maximum length between the binary representations of k1 and k2
    let (max_limb, max_bit) = msb_pos_256(k1, k2);

    // Perform the loop, based on the binary representation of k1 and k2
    // Start at 𝒪
    let mut res = SyscallPoint256 { x: [0u64; 4], y: [0u64; 4] };
    let mut res_is_infinity = true;
    for i in (0..max_limb).rev() {
        let bit_len = if i == max_limb { max_bit } else { 64 };
        for j in (0..bit_len).rev() {
            let k1_bit = (k1[i] >> j) & 1;
            let k2_bit = (k2[i] >> j) & 1;

            if (k1_bit == 0) && (k2_bit == 0) {
                // If res is 𝒪, do nothing; otherwise, double
                if res_is_infinity {
                    continue;
                }
            } else if (k1_bit == 0) && (k2_bit == 1) {
                // If res is 𝒪, set res = p; otherwise, add p
                if res_is_infinity {
                    res.x = p.x;
                    res.y = p.y;
                    res_is_infinity = false;
                } else {
                    add_points_complete_assign(&mut res, &mut res_is_infinity, p);
                }
            } else if (k1_bit == 1) && (k2_bit == 0) {
                // If res is 𝒪, set res = g; otherwise, add g
                if res_is_infinity {
                    res.x = G_X;
                    res.y = G_Y;
                    res_is_infinity = false;
                } else {
                    add_points_complete_assign(
                        &mut res,
                        &mut res_is_infinity,
                        &SyscallPoint256 { x: G_X, y: G_Y },
                    );
                }
            } else if (k1_bit == 1) && (k2_bit == 1) {
                if res_is_infinity {
                    // If (g + p) is 𝒪, do nothing; otherwise set res = (g + p)
                    if gp_is_infinity {
                        continue;
                    } else {
                        res.x = gp.x;
                        res.y = gp.y;
                        res_is_infinity = false;
                    }
                } else {
                    // If (g + p) is 𝒪, simply double res; otherwise add (g + p)
                    if !gp_is_infinity {
                        add_points_complete_assign(&mut res, &mut res_is_infinity, &gp);
                    }
                }
            }

            // Always double res
            double_point_assign(&mut res);
        }
    }

    (res_is_infinity, res)
}

// Q: Do we prefer constant time functions?
fn msb_pos_256(x: &[u64; 4], y: &[u64; 4]) -> (usize, usize) {
    for i in (0..4).rev() {
        if x[i] != 0 || y[i] != 0 {
            let word = if x[i] > y[i] { x[i] } else { y[i] };
            return (i, msb_pos(word));
        }
    }
    panic!("Invalid input: x and y are both zero");
}

// Q: Do we prefer constant time functions?
#[rustfmt::skip]
fn msb_pos(mut x: u64) -> usize {
    let mut pos = 0;
    if x >= 1 << 32 { x >>= 32; pos += 32; }
    if x >= 1 << 16 { x >>= 16; pos += 16; }
    if x >= 1 << 8  { x >>= 8;  pos += 8;  }
    if x >= 1 << 4  { x >>= 4;  pos += 4;  }
    if x >= 1 << 2  { x >>= 2;  pos += 2;  }
    if x >= 1 << 1  {           pos += 1;  }
    pos
}

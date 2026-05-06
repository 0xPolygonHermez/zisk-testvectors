use super::common::*;

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
extern "C" {
    fn overflowing_add256_c(a: *const u64, b: *const u64, result: *mut u64) -> u8;

    fn overflowing_sub256_c(a: *const u64, b: *const u64, result: *mut u64) -> u8;

    fn overflowing_neg256_c(a: *const u64, result: *mut u64) -> u8;

    fn overflowing_mul256_c(a: *const u64, b: *const u64, result: *mut u64) -> u8;

    fn overflowing_square256_c(a: *const u64, result: *mut u64) -> u8;

    fn overflowing_pow256_c(base: *const u64, exp: *const u64, result: *mut u64) -> u8;
}

fn overflowing_add(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let overflow = unsafe { overflowing_add256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        (result, overflow != 0)
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        let (v, o) = RU256::from_limbs(a).overflowing_add(RU256::from_limbs(b));
        (*v.as_limbs(), o)
    }
}

fn overflowing_sub(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let overflow = unsafe { overflowing_sub256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        (result, overflow != 0)
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        let (v, o) = RU256::from_limbs(a).overflowing_sub(RU256::from_limbs(b));
        (*v.as_limbs(), o)
    }
}

fn overflowing_neg(a: [u64; 4]) -> ([u64; 4], bool) {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let overflow = unsafe { overflowing_neg256_c(a.as_ptr(), result.as_mut_ptr()) };
        (result, overflow != 0)
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        let (v, o) = RU256::from_limbs(a).overflowing_neg();
        (*v.as_limbs(), o)
    }
}

fn overflowing_mul(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let overflow = unsafe { overflowing_mul256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        (result, overflow != 0)
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        let (v, o) = RU256::from_limbs(a).overflowing_mul(RU256::from_limbs(b));
        (*v.as_limbs(), o)
    }
}

fn overflowing_square(a: [u64; 4]) -> ([u64; 4], bool) {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let overflow = unsafe { overflowing_square256_c(a.as_ptr(), result.as_mut_ptr()) };
        (result, overflow != 0)
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        let (v, o) = RU256::from_limbs(a).overflowing_mul(RU256::from_limbs(a));
        (*v.as_limbs(), o)
    }
}

fn overflowing_pow(base: [u64; 4], exp: [u64; 4]) -> ([u64; 4], bool) {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let overflow =
            unsafe { overflowing_pow256_c(base.as_ptr(), exp.as_ptr(), result.as_mut_ptr()) };
        (result, overflow != 0)
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        let (v, o) = RU256::from_limbs(base).overflowing_pow(RU256::from_limbs(exp));
        (*v.as_limbs(), o)
    }
}

pub fn overflowing_tests() {
    // ── overflowing_add256 ────────────────────────────────────────────────────
    assert_eq!(overflowing_add(ZERO, ZERO), (ZERO, false));
    assert_eq!(overflowing_add(ONE, TWO), ([3, 0, 0, 0], false));
    // carry propagates across one limb
    assert_eq!(overflowing_add([u64::MAX, 0, 0, 0], ONE), ([0, 1, 0, 0], false));
    // carry propagates across two limbs
    assert_eq!(overflowing_add([u64::MAX, u64::MAX, 0, 0], ONE), ([0, 0, 1, 0], false));
    assert_eq!(overflowing_add(MAX, ONE), (ZERO, true));
    // 2*(2^256 - 1) mod 2^256 = MAX - 1, carry 1
    assert_eq!(overflowing_add(MAX, MAX), ([u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX], true));

    // ── overflowing_sub256 ────────────────────────────────────────────────────
    assert_eq!(overflowing_sub(TWO, ONE), (ONE, false));
    assert_eq!(overflowing_sub(ONE, ONE), (ZERO, false));
    assert_eq!(overflowing_sub(MAX, MAX), (ZERO, false));
    // borrow propagates across one limb
    assert_eq!(overflowing_sub([0, 1, 0, 0], ONE), ([u64::MAX, 0, 0, 0], false));
    assert_eq!(overflowing_sub(ZERO, ONE), (MAX, true));
    assert_eq!(overflowing_sub(ONE, TWO), (MAX, true));

    // ── overflowing_neg256 ────────────────────────────────────────────────────
    assert_eq!(overflowing_neg(ZERO), (ZERO, false));
    assert_eq!(overflowing_neg(ONE), (MAX, true));
    assert_eq!(overflowing_neg(MAX), (ONE, true));

    // ── overflowing_mul256 ────────────────────────────────────────────────────
    assert_eq!(overflowing_mul(ZERO, ONE), (ZERO, false));
    assert_eq!(overflowing_mul(ONE, ONE), (ONE, false));
    assert_eq!(overflowing_mul(TWO, [3, 0, 0, 0]), ([6, 0, 0, 0], false));
    // (2^64)^2 = 2^128 — no overflow
    assert_eq!(overflowing_mul(POW2_64, POW2_64), (POW2_128, false));
    // MAX * 2: low = MAX-1, overflow
    assert_eq!(overflowing_mul(MAX, TWO), ([u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX], true));
    // 2^128 * 2^128 = 2^256 ≡ 0 (mod 2^256), overflow
    assert_eq!(overflowing_mul(POW2_128, POW2_128), (ZERO, true));

    // ── overflowing_square256 ─────────────────────────────────────────────────
    assert_eq!(overflowing_square(ZERO), (ZERO, false));
    assert_eq!(overflowing_square(ONE), (ONE, false));
    assert_eq!(overflowing_square(TWO), ([4, 0, 0, 0], false));
    // (2^64)^2 = 2^128 — no overflow
    assert_eq!(overflowing_square(POW2_64), (POW2_128, false));
    // (2^128)^2 = 2^256 ≡ 0 (mod 2^256), overflow
    assert_eq!(overflowing_square(POW2_128), (ZERO, true));

    // ── overflowing_pow256 ────────────────────────────────────────────────────
    // Special-case early returns
    // base^0 = 1 (including 0^0)
    assert_eq!(overflowing_pow(ZERO, ZERO), (ONE, false));
    assert_eq!(overflowing_pow([42, 0, 0, 0], ZERO), (ONE, false));
    // base^1 = base
    assert_eq!(overflowing_pow([42, 0, 0, 0], ONE), ([42, 0, 0, 0], false));
    // 0^exp = 0
    assert_eq!(overflowing_pow(ZERO, [5, 0, 0, 0]), (ZERO, false));
    // 1^exp = 1
    assert_eq!(overflowing_pow(ONE, [100, 0, 0, 0]), (ONE, false));

    // Power-of-two exponent path (repeated squaring only)
    // 2^2 = 4  (exp=2=2^1, one squaring)
    assert_eq!(overflowing_pow(TWO, TWO), ([4, 0, 0, 0], false));
    // 2^4 = 16 (exp=4=2^2, two squarings)
    assert_eq!(overflowing_pow(TWO, [4, 0, 0, 0]), ([16, 0, 0, 0], false));
    // 3^4 = 81
    assert_eq!(overflowing_pow([3, 0, 0, 0], [4, 0, 0, 0]), ([81, 0, 0, 0], false));

    // General square-and-multiply path
    // 2^3 = 8  (exp=3 = 0b11)
    assert_eq!(overflowing_pow(TWO, [3, 0, 0, 0]), ([8, 0, 0, 0], false));
    // 2^5 = 32 (exp=5 = 0b101)
    assert_eq!(overflowing_pow(TWO, [5, 0, 0, 0]), ([32, 0, 0, 0], false));
    // 3^5 = 243 (exp=5 = 0b101)
    assert_eq!(overflowing_pow([3, 0, 0, 0], [5, 0, 0, 0]), ([243, 0, 0, 0], false));

    // Overflow cases
    // MAX^2 mod 2^256 = (-1)^2 mod 2^256 = 1, overflow
    assert_eq!(overflowing_pow(MAX, TWO), (ONE, true));
    // 2^256 mod 2^256 = 0, overflow  (exp=256=2^8, power-of-two path)
    assert_eq!(overflowing_pow(TWO, [256, 0, 0, 0]), (ZERO, true));

    println!("All U256 Overflow tests passed!");
}

use super::common::*;

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
extern "C" {
    fn wrapping_add256_c(a: *const u64, b: *const u64, result: *mut u64);

    fn wrapping_sub256_c(a: *const u64, b: *const u64, result: *mut u64);

    fn wrapping_neg256_c(a: *const u64, result: *mut u64);

    fn wrapping_mul256_c(a: *const u64, b: *const u64, result: *mut u64);

    fn wrapping_square256_c(a: *const u64, result: *mut u64);

    fn wrapping_div256_c(a: *const u64, b: *const u64, result: *mut u64);

    fn wrapping_rem256_c(a: *const u64, b: *const u64, result: *mut u64);

    fn wrapping_pow256_c(a: *const u64, b: *const u64, result: *mut u64);
}

fn wrapping_add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { wrapping_add256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).wrapping_add(RU256::from_limbs(b)).as_limbs()
    }
}

fn wrapping_sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { wrapping_sub256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).wrapping_sub(RU256::from_limbs(b)).as_limbs()
    }
}

fn wrapping_neg(a: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { wrapping_neg256_c(a.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).wrapping_neg().as_limbs()
    }
}

fn wrapping_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { wrapping_mul256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).wrapping_mul(RU256::from_limbs(b)).as_limbs()
    }
}

fn wrapping_square(a: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { wrapping_square256_c(a.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).wrapping_mul(RU256::from_limbs(a)).as_limbs()
    }
}

fn wrapping_div(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { wrapping_div256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).wrapping_div(RU256::from_limbs(b)).as_limbs()
    }
}

fn wrapping_rem(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { wrapping_rem256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).wrapping_rem(RU256::from_limbs(b)).as_limbs()
    }
}

fn wrapping_pow(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { wrapping_pow256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).wrapping_pow(RU256::from_limbs(b)).as_limbs()
    }
}

pub fn wrapping_tests() {
    // ── wrapping_add256 ───────────────────────────────────────────────────────
    assert_eq!(wrapping_add(ONE, TWO), [3, 0, 0, 0]);
    assert_eq!(wrapping_add(MAX, ONE), ZERO);
    assert_eq!(wrapping_add(MAX, MAX), [u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX]);

    // ── wrapping_sub256 ───────────────────────────────────────────────────────
    assert_eq!(wrapping_sub(TWO, ONE), ONE);
    assert_eq!(wrapping_sub(ZERO, ONE), MAX);

    // ── wrapping_neg256 ───────────────────────────────────────────────────────
    assert_eq!(wrapping_neg(ZERO), ZERO);
    assert_eq!(wrapping_neg(ONE), MAX);
    assert_eq!(wrapping_neg(MAX), ONE);
    // double negation is the identity
    let a = [0xdeadbeef_cafebabe_u64, 0x1234567890abcdef, 0, 0];
    assert_eq!(wrapping_neg(wrapping_neg(a)), a);

    // ── wrapping_div256 / wrapping_rem256 ─────────────────────────────────────
    let a = [0x16b12176aedd308e_u64, 0x9d331c2b34766fc9, 0x0b7f85b22001249e, 0x3b4e3fc5e0d8b014];
    let b = [0x16b12176aedd308e_u64, 0x9d331c2b34766fc9, 0x0b7f85b22001249e, 0x0];
    let expected_quo = [0x2868ebf5edfaecd5_u64, 0x5, 0x0, 0x0];
    let expected_rem = [0x0dbb84a86764e268_u64, 0xfd48d6ec2b636246, 0x0adbb6db4207ffb8, 0x0];
    assert_eq!(wrapping_div(a, b), expected_quo);
    assert_eq!(wrapping_rem(a, b), expected_rem);
    // a % b when a == 0
    assert_eq!(wrapping_rem(ZERO, ONE), ZERO);
    // a % a == 0
    assert_eq!(wrapping_rem(a, a), ZERO);

    // ── wrapping_mul256 ───────────────────────────────────────────────────────
    assert_eq!(wrapping_mul(TWO, [3, 0, 0, 0]), [6, 0, 0, 0]);
    assert_eq!(wrapping_mul(MAX, TWO), [u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX]);
    assert_eq!(wrapping_mul(POW2_128, POW2_128), ZERO);

    // ── wrapping_square256 ────────────────────────────────────────────────────
    assert_eq!(wrapping_square([3, 0, 0, 0]), [9, 0, 0, 0]);
    assert_eq!(wrapping_square(POW2_64), POW2_128);
    assert_eq!(wrapping_square(POW2_128), ZERO);

    // ── wrapping_pow256 ───────────────────────────────────────────────────────
    assert_eq!(wrapping_pow(TWO, [10, 0, 0, 0]), [1024, 0, 0, 0]);
    assert_eq!(wrapping_pow([3, 0, 0, 0], [5, 0, 0, 0]), [243, 0, 0, 0]);
    assert_eq!(wrapping_pow(ZERO, [5, 0, 0, 0]), ZERO);
    assert_eq!(wrapping_pow(ONE, [100, 0, 0, 0]), ONE);
    // MAX^2 wraps to 1
    assert_eq!(wrapping_pow(MAX, TWO), ONE);
    // 2^256 wraps to 0
    assert_eq!(wrapping_pow(TWO, [256, 0, 0, 0]), ZERO);

    println!("All U256 Wrapping tests passed!");
}

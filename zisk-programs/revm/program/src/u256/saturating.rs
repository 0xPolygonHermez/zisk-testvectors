use super::common::*;

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
extern "C" {
    fn saturating_add256_c(a: *const u64, b: *const u64, result: *mut u64);

    fn saturating_sub256_c(a: *const u64, b: *const u64, result: *mut u64);

    fn saturating_mul256_c(a: *const u64, b: *const u64, result: *mut u64);

    fn saturating_square256_c(a: *const u64, result: *mut u64);

    fn saturating_pow256_c(a: *const u64, b: *const u64, result: *mut u64);
}

fn saturating_add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { saturating_add256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).saturating_add(RU256::from_limbs(b)).as_limbs()
    }
}

fn saturating_sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { saturating_sub256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).saturating_sub(RU256::from_limbs(b)).as_limbs()
    }
}

fn saturating_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { saturating_mul256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).saturating_mul(RU256::from_limbs(b)).as_limbs()
    }
}

fn saturating_square(a: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { saturating_square256_c(a.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(a).saturating_mul(RU256::from_limbs(a)).as_limbs()
    }
}

fn saturating_pow(base: [u64; 4], exp: [u64; 4]) -> [u64; 4] {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        unsafe { saturating_pow256_c(base.as_ptr(), exp.as_ptr(), result.as_mut_ptr()) };
        result
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        *RU256::from_limbs(base).saturating_pow(RU256::from_limbs(exp)).as_limbs()
    }
}

pub fn saturating_tests() {
    // ── saturating_add256 ─────────────────────────────────────────────────────
    assert_eq!(saturating_add(ONE, TWO), [3, 0, 0, 0]);
    assert_eq!(saturating_add(MAX, ONE), MAX);
    assert_eq!(saturating_add(MAX, MAX), MAX);

    // ── saturating_sub256 ─────────────────────────────────────────────────────
    assert_eq!(saturating_sub(TWO, ONE), ONE);
    assert_eq!(saturating_sub(ZERO, ONE), ZERO);
    assert_eq!(saturating_sub(ONE, TWO), ZERO);

    // ── saturating_mul256 ────────────────────────────────────────────────────
    assert_eq!(saturating_mul(TWO, [3, 0, 0, 0]), [6, 0, 0, 0]);
    assert_eq!(saturating_mul(MAX, TWO), MAX);
    assert_eq!(saturating_mul(POW2_128, POW2_128), MAX);

    // ── saturating_square256 ─────────────────────────────────────────────────
    assert_eq!(saturating_square([3, 0, 0, 0]), [9, 0, 0, 0]);
    assert_eq!(saturating_square(POW2_128), MAX);

    // ── saturating_pow256 ─────────────────────────────────────────────────────
    assert_eq!(saturating_pow(TWO, [10, 0, 0, 0]), [1024, 0, 0, 0]);
    assert_eq!(saturating_pow(ZERO, [99, 0, 0, 0]), ZERO);
    assert_eq!(saturating_pow(ONE, MAX), ONE);
    assert_eq!(saturating_pow(MAX, TWO), MAX);
    assert_eq!(saturating_pow(TWO, [256, 0, 0, 0]), MAX);

    println!("All U256 Saturating tests passed!");
}

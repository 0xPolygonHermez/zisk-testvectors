use super::common::*;

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
extern "C" {
    fn checked_add256_c(a: *const u64, b: *const u64, result: *mut u64) -> u8;

    fn checked_sub256_c(a: *const u64, b: *const u64, result: *mut u64) -> u8;

    fn checked_neg256_c(a: *const u64, result: *mut u64) -> u8;

    fn checked_mul256_c(a: *const u64, b: *const u64, result: *mut u64) -> u8;

    fn checked_square256_c(a: *const u64, result: *mut u64) -> u8;

    fn checked_pow256_c(base: *const u64, exp: *const u64, result: *mut u64) -> u8;

    fn checked_div256_c(a: *const u64, b: *const u64, result: *mut u64) -> u8;

    fn checked_rem256_c(a: *const u64, b: *const u64, result: *mut u64) -> u8;
}

fn checked_add(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let success = unsafe { checked_add256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        if success == 1 {
            Some(result)
        } else {
            None
        }
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        RU256::from_limbs(a).checked_add(RU256::from_limbs(b)).map(|v| *v.as_limbs())
    }
}

fn checked_sub(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let success = unsafe { checked_sub256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        if success == 1 {
            Some(result)
        } else {
            None
        }
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        RU256::from_limbs(a).checked_sub(RU256::from_limbs(b)).map(|v| *v.as_limbs())
    }
}

fn checked_neg(a: [u64; 4]) -> Option<[u64; 4]> {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let success = unsafe { checked_neg256_c(a.as_ptr(), result.as_mut_ptr()) };
        if success == 1 {
            Some(result)
        } else {
            None
        }
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        RU256::from_limbs(a).checked_neg().map(|v| *v.as_limbs())
    }
}

fn checked_mul(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let success = unsafe { checked_mul256_c(a.as_ptr(), b.as_ptr(), result.as_mut_ptr()) };
        if success == 1 {
            Some(result)
        } else {
            None
        }
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        RU256::from_limbs(a).checked_mul(RU256::from_limbs(b)).map(|v| *v.as_limbs())
    }
}

fn checked_square(a: [u64; 4]) -> Option<[u64; 4]> {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let success = unsafe { checked_square256_c(a.as_ptr(), result.as_mut_ptr()) };
        if success == 1 {
            Some(result)
        } else {
            None
        }
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        RU256::from_limbs(a).checked_mul(RU256::from_limbs(a)).map(|v| *v.as_limbs())
    }
}

fn checked_pow(base: [u64; 4], exp: [u64; 4]) -> Option<[u64; 4]> {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let success = unsafe { checked_pow256_c(base.as_ptr(), exp.as_ptr(), result.as_mut_ptr()) };
        if success == 1 {
            Some(result)
        } else {
            None
        }
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        RU256::from_limbs(base).checked_pow(RU256::from_limbs(exp)).map(|v| *v.as_limbs())
    }
}

fn checked_div(base: [u64; 4], exp: [u64; 4]) -> Option<[u64; 4]> {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let success = unsafe { checked_div256_c(base.as_ptr(), exp.as_ptr(), result.as_mut_ptr()) };
        if success == 1 {
            Some(result)
        } else {
            None
        }
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        RU256::from_limbs(base).checked_div(RU256::from_limbs(exp)).map(|v| *v.as_limbs())
    }
}

fn checked_rem(base: [u64; 4], exp: [u64; 4]) -> Option<[u64; 4]> {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut result = [0u64; 4];
        let success = unsafe { checked_rem256_c(base.as_ptr(), exp.as_ptr(), result.as_mut_ptr()) };
        if success == 1 {
            Some(result)
        } else {
            None
        }
    }

    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        RU256::from_limbs(base).checked_rem(RU256::from_limbs(exp)).map(|v| *v.as_limbs())
    }
}

pub fn checked_tests() {
    // ── checked_add256 ────────────────────────────────────────────────────────
    assert_eq!(checked_add(ONE, TWO), Some([3, 0, 0, 0]));
    assert_eq!(checked_add(MAX, ZERO), Some(MAX));
    assert_eq!(checked_add(MAX, ONE), None);

    // ── checked_sub256 ────────────────────────────────────────────────────────
    assert_eq!(checked_sub(TWO, ONE), Some(ONE));
    assert_eq!(checked_sub(ONE, ONE), Some(ZERO));
    assert_eq!(checked_sub(ZERO, ONE), None);

    // ── checked_neg256 ────────────────────────────────────────────────────────
    assert_eq!(checked_neg(ZERO), Some(ZERO));
    assert_eq!(checked_neg(ONE), None);
    assert_eq!(checked_neg(MAX), None);

    // ── checked_div256 ────────────────────────────────────────────────────────
    let a = [0x16b12176aedd308e_u64, 0x9d331c2b34766fc9, 0x0b7f85b22001249e, 0x3b4e3fc5e0d8b014];
    let b = [0x16b12176aedd308e_u64, 0x9d331c2b34766fc9, 0x0b7f85b22001249e, 0x0];
    let expected_quo = [0x2868ebf5edfaecd5_u64, 0x5, 0x0, 0x0];
    let expected_rem = [0x0dbb84a86764e268_u64, 0xfd48d6ec2b636246, 0x0adbb6db4207ffb8, 0x0];
    assert_eq!(checked_div(a, b), Some(expected_quo));
    assert_eq!(checked_div(ZERO, ONE), Some(ZERO));
    assert_eq!(checked_div(a, ZERO), None);

    // ── checked_rem256 ────────────────────────────────────────────────────────
    assert_eq!(checked_rem(a, b), Some(expected_rem));
    assert_eq!(checked_rem(ZERO, ONE), Some(ZERO));
    assert_eq!(checked_rem(a, ZERO), None);

    // ── checked_mul256 ────────────────────────────────────────────────────────
    assert_eq!(checked_mul(TWO, [3, 0, 0, 0]), Some([6, 0, 0, 0]));
    assert_eq!(checked_mul(ONE, ONE), Some(ONE));
    assert_eq!(checked_mul(MAX, TWO), None);
    assert_eq!(checked_mul(POW2_128, POW2_128), None);

    // ── checked_square256 ────────────────────────────────────────────────────
    assert_eq!(checked_square([3, 0, 0, 0]), Some([9, 0, 0, 0]));
    assert_eq!(checked_square(POW2_64), Some(POW2_128));
    assert_eq!(checked_square(POW2_128), None);

    // ── checked_pow256 ────────────────────────────────────────────────────────
    assert_eq!(checked_pow(TWO, [10, 0, 0, 0]), Some([1024, 0, 0, 0]));
    assert_eq!(checked_pow([3, 0, 0, 0], [5, 0, 0, 0]), Some([243, 0, 0, 0]));
    assert_eq!(checked_pow(TWO, ZERO), Some(ONE));
    assert_eq!(checked_pow(MAX, TWO), None);
    assert_eq!(checked_pow(TWO, [256, 0, 0, 0]), None);

    println!("All U256 Checked tests passed!");
}

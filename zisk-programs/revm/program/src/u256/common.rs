pub(crate) const ZERO: [u64; 4] = [0, 0, 0, 0];

pub(crate) const ONE: [u64; 4] = [1, 0, 0, 0];

pub(crate) const TWO: [u64; 4] = [2, 0, 0, 0];

pub(crate) const MAX: [u64; 4] = [u64::MAX, u64::MAX, u64::MAX, u64::MAX];

pub(crate) const POW2_64: [u64; 4] = [0, 1, 0, 0]; // 2^64
pub(crate) const POW2_128: [u64; 4] = [0, 0, 1, 0]; // 2^128

#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
pub(crate) type RU256 = ruint::Uint<256, 4>;

#![no_main]
#![cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
ziskos::entrypoint!(main);

use ziskos::{
    fcall2_secp256k1_fn_inv, fcall2_secp256k1_fp_inv,
    fcall_secp256k1_fn_inv, fcall_secp256k1_fp_inv, fcall_secp256k1_fp_sqrt, ziskos_fcall_get,
};

fn main() {
    /* SAGE:
       p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
       K = GF(p)
       a = K(0x0000000000000000000000000000000000000000000000000000000000000000)
       b = K(0x0000000000000000000000000000000000000000000000000000000000000007)
       E = EllipticCurve(K, (a, b))
       G = E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
       E.set_order(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 * 0x1)
       F=GF(p)
       num=F(0x0000667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798).sqrt()
       hex_str = hex(num)[2:].zfill(64)
       chunks = [hex_str[i:i+16] for i in range(0, 64, 16)]
       for i, chunk in enumerate(chunks[::-1], 1):
           print(f"0x{chunk},")
    */

    // 7934893560151485808
    // [15214554533581868167, 5866531221545748743, 2306789128252389664, 7934893560151485808
    //

    let value: [u64; 4] =
        [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x0000667EF9DCBBAC];
    let expected_result_1: [u64; 4] =
        [0xd324f4bcf5f4cc87, 0x516a1b1053f90907, 0x20035c7d81377920, 0x6e1e67a6ef5d2d70];

    let expected_result_0: [u64; 4] =
        [0x2cdb0b420a0b2fa8, 0xae95e4efac06f6f8, 0xdffca3827ec886df, 0x91e1985910a2d28f];

    let no_root: [u64; 4] =
        [0xfffffffefffffc2e, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];

    let result = fcall_secp256k1_fp_sqrt(&value, 1);
    assert_eq!(result[0], 1);
    assert_eq!(result[1..5], expected_result_1);

    let result = fcall_secp256k1_fp_sqrt(&no_root, 0);
    assert_eq!(result[0], 0);

    let result = fcall_secp256k1_fp_sqrt(&value, 0);
    assert_eq!(result[0], 1);
    assert_eq!(result[1..5], expected_result_0);

    let value: [u64; 4] =
        [0xfffffffefffffc2c, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];
    let expected_result_1: [u64; 4] =
        [0x8272d850e32a03dd, 0x39e092ea25eb132b, 0xdcc88f3d586869d3, 0xf5d2d456caf80e20];

    let expected_result_0: [u64; 4] =
        [0x7d8d27ae1cd5f852, 0xc61f6d15da14ecd4, 0x233770c2a797962c, 0x0a2d2ba93507f1df];

    let result = fcall_secp256k1_fp_sqrt(&value, 1);
    assert_eq!(result[0], 1);
    assert_eq!(result[1..5], expected_result_1);

    let result = fcall_secp256k1_fp_sqrt(&value, 0);
    assert_eq!(result[0], 1);
    assert_eq!(result[1..5], expected_result_0);

    // secp256k1_fp_inv

    let value: [u64; 4] =
        [0xffffffffbfffff0c, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff];
    let inv_value: [u64; 4] =
        [0x0000000000000004, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];

    let result = fcall_secp256k1_fp_inv(&value);
    assert_eq!(result, inv_value);

    fcall2_secp256k1_fp_inv(&value);
    let result = [ziskos_fcall_get(), ziskos_fcall_get(), ziskos_fcall_get(), ziskos_fcall_get()];
    assert_eq!(result, inv_value);

    let result = fcall_secp256k1_fp_inv(&inv_value);
    assert_eq!(result, value);

    fcall2_secp256k1_fp_inv(&inv_value);
    let result = [ziskos_fcall_get(), ziskos_fcall_get(), ziskos_fcall_get(), ziskos_fcall_get()];
    assert_eq!(result, value);

    // let zero: [u64;4] = [
    //     0x0000000000000000,
    //     0x0000000000000000,
    //     0x0000000000000000,
    //     0x0000000000000000,
    // ];

    // let result = fcall_secp256k1_fp_inv(&zero);
    // assert_eq!(result, zero);

    // fcall2_secp256k1_fp_inv(&zero);
    // let result = [ziskos_fcall_get(),ziskos_fcall_get(),ziskos_fcall_get(),ziskos_fcall_get()];
    // assert_eq!(result, zero);

    let value: [u64; 4] =
        [0x3623dfe3727a53ca, 0x9834d5ea5c40a9dd, 0x3b13b13b13b13b13, 0x13b13b13b13b13b1];
    let inv_value: [u64; 4] =
        [0x000000000000000d, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];

    let result = fcall_secp256k1_fn_inv(&value);
    assert_eq!(result, inv_value);

    fcall2_secp256k1_fn_inv(&value);
    let result = [ziskos_fcall_get(), ziskos_fcall_get(), ziskos_fcall_get(), ziskos_fcall_get()];
    assert_eq!(result, inv_value);

    let result = fcall_secp256k1_fn_inv(&inv_value);
    assert_eq!(result, value);

    fcall2_secp256k1_fn_inv(&inv_value);
    let result = [ziskos_fcall_get(), ziskos_fcall_get(), ziskos_fcall_get(), ziskos_fcall_get()];
    assert_eq!(result, value);

    println!("Success");
}

#![no_main]

ziskos::entrypoint!(main);

use ziskos::fcall_msb_pos_256;

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

    let x: [u64; 4] =
        [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x0000667EF9DCBBAC];
    let y: [u64; 4] =
        [0xd324f4bcf5f4cc87, 0x516a1b1053f90907, 0x20035c7d81377920, 0x001e67a6ef5d2d70];

    let result = fcall_msb_pos_256(&x, &y);
    assert_eq!(result, (3, 52));

    let x: [u64; 4] = [0, 0, 0, 0];
    let y: [u64; 4] = [1, 0, 0, 0];

    let result = fcall_msb_pos_256(&x, &y);
    println!("result: {:?}", result);
    assert_eq!(result, (0, 0));

    let x: [u64; 4] = [0, 0, 0, 0];
    let y: [u64; 4] = [2, 0, 0, 0];

    let result = fcall_msb_pos_256(&x, &y);
    println!("result: {:?}", result);
    assert_eq!(result, (0, 1));

    let result = fcall_msb_pos_256(&y, &x);
    println!("result: {:?}", result);
    assert_eq!(result, (0, 1));

    let x: [u64; 4] = [0x8000_0000_0000_0000, 0, 0, 0];
    let y: [u64; 4] = [2, 0, 0, 0];
    let result = fcall_msb_pos_256(&x, &y);
    assert_eq!(result, (0, 63));

    let result = fcall_msb_pos_256(&y, &x);
    assert_eq!(result, (0, 63));

    let x: [u64; 4] = [0x8000_0000_0000_0000, 0, 0, 0];
    let y: [u64; 4] = [0, 2, 0, 0];
    let result = fcall_msb_pos_256(&x, &y);
    assert_eq!(result, (1, 1));

    let result = fcall_msb_pos_256(&y, &x);
    assert_eq!(result, (1, 1));

    let x: [u64; 4] = [0x8000_0000_0000_0000, 0, 0, 0];
    let y: [u64; 4] = [0, 0, 1, 0];
    let result = fcall_msb_pos_256(&x, &y);
    assert_eq!(result, (2, 0));

    let result = fcall_msb_pos_256(&y, &x);
    assert_eq!(result, (2, 0));

    let x: [u64; 4] = [0x8000_0000_0000_0000, 0, 0, 0];
    let y: [u64; 4] = [0, 0, 0, 1];
    let result = fcall_msb_pos_256(&x, &y);
    assert_eq!(result, (3, 0));

    let result = fcall_msb_pos_256(&y, &x);
    assert_eq!(result, (3, 0));

    let x: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    let y: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ];
    let result = fcall_msb_pos_256(&x, &y);
    assert_eq!(result, (3, 63));

    println!("Success");
}

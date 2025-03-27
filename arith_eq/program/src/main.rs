#![no_main]
ziskos::entrypoint!(main);

use ziskos::read_input;
use ziskos::syscalls::{point256::*, secp256k1_add::*};

// RUST_BACKTRACE=full ~/devel/zisk2/zisk/target/release/ziskemu -x -e target/riscv64ima-polygon-ziskos-elf/release/arith_eq -i ../inputs/input_arith_eq_1.bin
fn main() {
    // Get the input from ziskos
    let input: Vec<u8> = read_input();

    //     // let a:[u64;4] = [2,4,8,16];
    //     // let b:[u64;4] = [3,9,27,81];
    //     // let c:[u64;4] = [7,49,345,2500];
    //     let mut a:[u64;4] = [2000,0,0,0];
    //     let mut b:[u64;4] = [3000,0,0,0];
    //     let mut c:[u64;4] = [7000,0,0,0];
    //     let mut dl:[u64;4] = [0,0,0,0];
    //     let mut dh:[u64;4] = [0,0,0,0];

    //     // let expected_dh:[u64;4] = [0,0,0,0];
    //     // let expected_dl:[u64;4] = [13,0,0,0];

    //     let mut params = SyscallArith256Params {
    //         a: &mut a,
    //         b: &mut b,
    //         c: &mut c,
    //         dh: &mut dh,
    //         dl: &mut dl,
    //     };
    //     // println!("a:{:?} b:{:?} c:{:?}", a, b, c);
    //     // println!("a:{:?} b:{:?} c:{:?}", params.a, params.b, params.c);
    //     syscall_arith256(&mut params);

    //     params.a = &[0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF];
    //     params.b = &[0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF];
    //     params.c = &[0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF];

    //     syscall_arith256(&mut params);

    //     /*
    //     println!("         dh:{:?}", dh);
    //     println!("expected dh:{:?}", expected_dh);
    //     println!("         dl:{:?}", dl);
    //     println!("expected dl:{:?}", expected_dl);
    //     assert_eq!(dh, expected_dh);
    //     assert_eq!(dl, expected_dl);
    // */
    //     let a:[u64;4] = [0xfe4548225cb9dfa4, 0x1ace4c2f19cce8e7, 0x3c14acc8f690399c, 0xb41d9862807fb9a6];
    //     let b:[u64;4] = [0x03e3c5ed16415a7e, 0x9c9abb69f69d5bbc, 0x0f01aa32a7e179ad, 0xb56c299101bd20a9];
    //     let c:[u64;4] = [0x9525b93f2a1f52d8, 0x6c2d32c3ab9e25d8, 0x89bd54b9a79c1120, 0x22c85a06d186d3dc];
    //     let mut dh = [0u64;4];
    //     let mut dl = [0u64;4];
    //     let expected_dh:[u64;4] = [0x287463f043f29e82, 0xbb4f5f8f33d245d6, 0xa00dec917cfbec0e, 0x7fa50678b1ccc8f0];
    //     let expected_dl:[u64;4] = [0x76e6120006df0d90, 0x3d40082479e40341, 0xd77695f447184b82, 0x665c40b5e08024ca];

    //     let mut params = SyscallArith256Params {
    //         a: &a,
    //         b: &b,
    //         c: &c,
    //         dh: &mut dh,
    //         dl: &mut dl,
    //     };
    //     // println!("a:{:?} b:{:?} c:{:?}", a, b, c);
    //     // println!("a:{:?} b:{:?} c:{:?}", params.a, params.b, params.c);
    //     syscall_arith256(&mut params);
    //     // println!("         dh:{:?}", dh);
    //     // println!("expected dh:{:?}", expected_dh);
    //     // println!("         dl:{:?}", dl);
    //     // println!("expected dl:{:?}", expected_dl);
    //     assert_eq!(dh, expected_dh);
    //     assert_eq!(dl, expected_dl);

    //     let a:[u64;4] = [0xc9b03b176c169088, 0xd1d94829bb3cc946, 0x39349d1bf4b794cf, 0x004e92b17f7142c5];
    //     let b:[u64;4] = [0xe4c088941d280ed3, 0xff4472a415745899, 0x723bb20bf34a1146, 0x164ea2e2f331a446];
    //     let c:[u64;4] = [0x75739ecf648445db, 0x292e87449105b601, 0x40e58685a0e3aaeb, 0x2da4ddb14e364a33];
    //     let module:[u64;4] = [0xc979c9fb78dd4897, 0x5fe43f22bfc7c66a, 0x3aa373ebdbc235f6, 0x037c1f03941c34d0];
    //     let mut d:[u64;4] = [0,0,0,0];
    //     let expected_d:[u64;4] = [0x421ce3fbbf73f568, 0x507e2ae84c2047d6, 0xff90b568ef1a0d2e, 0x00ec2496386ece23];

    //     let mut params = SyscallArith256ModParams {
    //         a: &a,
    //         b: &b,
    //         c: &c,
    //         module: &module,
    //         d: &mut d,
    //     };
    //     // println!("a:{:?} b:{:?} c:{:?} module:{:?}", a, b, c, module);
    //     syscall_arith256_mod(&mut params);
    //     // println!("         d:{:?}", d);
    //     // println!("expected d:{:?}", expected_d);
    //     assert_eq!(d, expected_d);

    let mut p1 = SyscallPoint256 {
        x: [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC],
        y: [0x9C47D08FFB10D4B8, 0xFD17B448A6855419, 0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465],
    };
    let p2 = SyscallPoint256 {
        x: [0xABAC09B95C709EE5, 0x5C778E4B8CEF3CA7, 0x3045406E95C07CD8, 0xC6047F9441ED7D6D],
        y: [0x236431A950CFE52A, 0xF7F632653266D0E1, 0xA3C58419466CEAEE, 0x1AE168FEA63DC339],
    };
    let p3 = SyscallPoint256 {
        x: [0x8601F113BCE036F9, 0xB531C845836F99B0, 0x49344F85F89D5229, 0xF9308A019258C310],
        y: [0x6CB9FD7584B8E672, 0x6500A99934C2231B, 0x0FE337E62A37F356, 0x388F7B0F632DE814],
    };

    // println!("p1:{:?} p2:{:?}", p1, p2);
    let mut params = SyscallSecp256k1AddParams { p1: &mut p1, p2: &p2 };
    syscall_secp256k1_add(&mut params);
    // println!("p1:{:?}", p1);
    // println!("p3:{:?}", p3);
    assert_eq!(&p1.x, &p3.x);
    assert_eq!(&p1.y, &p3.y);

    // let mut p1 = SyscallPoint256 {
    //     x: [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC ],
    //     y: [0x9C47D08FFB10D4B8, 0xFD17B448A6855419, 0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465 ]
    // };
    // let p2 = SyscallPoint256 {
    //     x: [0xABAC09B95C709EE5, 0x5C778E4B8CEF3CA7, 0x3045406E95C07CD8, 0xC6047F9441ED7D6D ],
    //     y: [0x236431A950CFE52A, 0xF7F632653266D0E1, 0xA3C58419466CEAEE, 0x1AE168FEA63DC339 ]
    // };
    // params.p1 = &mut p1;
    // params.p2 = &p2;
    // syscall_secp256k1_add(&mut params);
    // // println!("p1:{:?}", p1);
    // // println!("p3:{:?}", p3);
    // assert_eq!(&p1.x, &p3.x);
    // assert_eq!(&p1.y, &p3.y);

    // let mut p1 = SyscallPoint256 {
    //         x: [0x2F057A1460297556, 0x82F6472F8568A18B, 0x20453A14355235D3, 0xFFF97BD5755EEEA4],
    //         y: [0x3C870C36B075F297, 0xDE80F0F6518FE4A0, 0xF3BE96017F45C560, 0xAE12777AACFBB620],
    // };

    // let p3 = SyscallPoint256 {
    //         x: [0xC5B0F47070AFE85A, 0x687CF4419620095B, 0x15C38F004D734633, 0xD01115D548E7561B],
    //         y: [0x6B051B13F4062327, 0x79238C5DD9A86D52, 0xA8B64537E17BD815, 0xA9F34FFDC815E0D7],
    // };

    // // println!("p1:{:?}", p1);
    // syscall_secp256k1_dbl(&mut p1);
    // // println!("p1:{:?}", p1);
    // // println!("p3:{:?}", p3);
    // assert_eq!(p1.x, p3.x);
    // assert_eq!(p1.y, p3.y);
    println!("Success");
}

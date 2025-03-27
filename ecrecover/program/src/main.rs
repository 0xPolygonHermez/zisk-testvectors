#![no_main]
ziskos::entrypoint!(main);

mod utils;

use tiny_keccak::{Hasher, Keccak};
use utils::{double_scalar_mul_with_g, sub};
use ziskos::syscalls::{
    arith256_mod::{syscall_arith256_mod, SyscallArith256ModParams},
    point256::SyscallPoint256,
};

// Secp256k1 prime field size
const P: [u64; 4] =
    [0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF];

// Secp256k1 scalar field size
const N: [u64; 4] =
    [0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
const N_MINUS_ONE: [u64; 4] =
    [0xBFD25E8CD0364140, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
const N_HALF: [u64; 4] =
    [0xDFE92F46681B20A0, 0x5D576E7357A4501D, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];

fn main() {
    // Test 1
    let hash = [0x6f365326cf807d68, 0x2bb4cc214d3220a3, 0x2b71fe008c98cc87, 0xd9eba16ed0ecae43];
    let r = [0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac];
    let s = [0x8cbf3034d73214b8, 0xabc6939a1710afc0, 0xcab9646c504576b3, 0x265e99e47ad31bb2];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xb7, 0xaf, 0x5e, 0x18, 0xc9, 0xd9, 0xe2, 0x94, 0xdf, 0x3f, 0xad, 0x2e, 0x64, 0x8f, 0x86,
        0xd5, 0x4a, 0x67, 0x44, 0xbc,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 2
    let hash = [0x6f365326cf807d68, 0x2bb4cc214d3220a3, 0x2b71fe008c98cc87, 0xd9eba16ed0ecae43];
    let r = [0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac];
    let s = [0x8cbf3034d73214b8, 0xabc6939a1710afc0, 0xcab9646c504576b3, 0x265e99e47ad31bb2];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xb8, 0xfd, 0x7c, 0xf6, 0x09, 0x76, 0xee, 0x5d, 0x63, 0x8f, 0x81, 0x37, 0x73, 0x5c, 0x4e,
        0x8d, 0xb3, 0xef, 0x3f, 0xee,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 3
    let hash = [0x6f365326cf807d68, 0x2bb4cc214d3220a3, 0x2b71fe008c98cc87, 0xd9eba16ed0ecae43];
    let r = [0x80948544508f3c63, 0xb513aa0028ec6c98, 0x56b4e35a077b9a11, 0xddd0a7290af95260];
    let s = [0x8cbf3034d73214b8, 0xabc6939a1710afc0, 0xcab9646c504576b3, 0x265e99e47ad31bb2];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x25, 0x93, 0xe5, 0x08, 0xb3, 0x97, 0xf9, 0xc9, 0x84, 0x84, 0xf1, 0x71, 0x9a, 0x4c, 0x0e,
        0x26, 0x97, 0x16, 0x79, 0x14,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 4
    let hash = [0x7194cbf7ebc1eebe, 0xccb41cee02d9d441, 0x77188e4fbd022f35, 0x3cc4cb050478c498];
    let r = [0xb777867db61f8a62, 0x13224cb4819e3833, 0xbe0e02edf967ce8f, 0x7dff8b06f4914ff0];
    let s = [0x450c889d597a16c4, 0xba2e787583036325, 0xa77344d5943e0228, 0x2bcf13b5e4f34a04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xc2, 0x63, 0x9d, 0x33, 0x0c, 0x26, 0x31, 0x0f, 0xf4, 0x6f, 0x87, 0x11, 0xd8, 0xd4, 0x4c,
        0xa2, 0x04, 0x0d, 0xc8, 0xbe,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 5
    let hash = [0xc3358f1822cec07d, 0x94378d777e418020, 0xfd9b03c4b17b59a5, 0xee43d51baa54831b];
    let r = [0x9cc38620099e0c65, 0x17c0eb75e6da8ecd, 0x77401b1bf67fd59e, 0xea678b4b3ebde1e8];
    let s = [0xff3d6a45bed2a6e8, 0xdda0688b9e965a4b, 0x97c4abbcede04a5e, 0x2b954333cfe2b4bf];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xb5, 0x71, 0x7a, 0x7c, 0x13, 0xd2, 0x9b, 0xc4, 0x09, 0xc1, 0xdf, 0x7a, 0xe7, 0x47, 0x86,
        0x0a, 0x18, 0xa2, 0x71, 0xd5,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 6
    let hash = [0x12bb42860d9d9c1f, 0x932bfe1c2ae7c21a, 0x3b958263c08db17c, 0xfd98b0bfc9eecc81];
    let r = [0x0b04af346cbf3ad2, 0x33de35822652144b, 0x139bc29378fd243d, 0x86b2f6d4bae0e1e1];
    let s = [0xcab710f26600e2fc, 0x53d4c57a2d832090, 0xdc2203ab8adab6ae, 0x5ec4a8672d44b21b];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x9c, 0x43, 0x27, 0xfe, 0xd5, 0xa3, 0x71, 0x3e, 0x10, 0x54, 0x9d, 0x75, 0x71, 0x26, 0x1c,
        0xe4, 0x36, 0x54, 0x85, 0x52,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 7
    let hash = [0xd36326dac17839e5, 0x2b70db9b738ab3f4, 0x928028def2818ec6, 0xc401c7d7baa568f5];
    let r = [0xa6394256dd188b33, 0x4d6deb59e5d524d1, 0x684815f4274d68d6, 0x4a95890f1102c6a6];
    let s = [0x74764bd790e42f51, 0x7c912be5b176329a, 0xc8ff4103da0740fd, 0x3e53619fe2f4c67a];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xfa, 0x89, 0xa8, 0xad, 0x22, 0xa2, 0x35, 0x1c, 0xcf, 0x31, 0xdd, 0x09, 0x04, 0xd5, 0x59,
        0xa4, 0x3e, 0x4c, 0xe2, 0xa4,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 8
    let hash = [0x56562d48c208002a, 0xccdd993d5322656c, 0xa5354613066d0d67, 0x60049b234e7fd86b];
    let r = [0xcb90210c66868e99, 0x329abee4f91c4027, 0x99ec35b0c4a85f5c, 0xf06fbfb021b185a5];
    let s = [0x4208f0385f37be1c, 0x710fe567a53d1a41, 0xa57b012b25bfd65f, 0x1e0e24cab3e119fe];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x82, 0xe3, 0x05, 0xa0, 0x78, 0x89, 0x9d, 0xfb, 0x48, 0x76, 0xcc, 0x84, 0x2b, 0xd3, 0x52,
        0xdb, 0xd6, 0xfd, 0x02, 0x23,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 9
    let hash = [0x340c902ff8f82d86, 0xbc97c448eec72348, 0x5d34f3c78fd9262e, 0xfda892e54ef8d0fc];
    let r = [0xcebcf25f546c0bb3, 0xc5bfe6611f56d8a2, 0x723ea73ff89244d1, 0xe9713e52d8ca16c7];
    let s = [0xd01a29012435fe02, 0x367a9b54ed9c3c54, 0x5b8e06ba56f22eed, 0x627566979c5b6e3a];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xee, 0xd9, 0xdb, 0xc4, 0xa8, 0xc1, 0x1d, 0x75, 0x59, 0xeb, 0xf0, 0x99, 0x4c, 0x68, 0x43,
        0xaa, 0x2c, 0x5b, 0x66, 0xcc,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 10
    let hash = [0x5ef44a3a0da75fd7, 0x0b6f4f7bc42fa400, 0xb734ef91a35a3184, 0x1df5d6cd09999848];
    let r = [0xed675602a00ebf21, 0x5326da91bf3af225, 0x16d34e6d1ceacfd7, 0x8c661a2e0ae1ffe7];
    let s = [0x8f55e8a4c9954000, 0x3b278bb1ac1f52fb, 0xae68326d7781ed90, 0x3de21452fd054750];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x62, 0x1e, 0x71, 0xbd, 0x8d, 0x72, 0x3a, 0x94, 0xdd, 0x90, 0x90, 0x83, 0xed, 0x2f, 0x3c,
        0x42, 0x8a, 0x35, 0x34, 0x1f,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 11
    let hash = [0x12168ce0ce5bc500, 0xf2913a407a15ee60, 0xa1ff7dbef2cbb063, 0x84254d72d3a17a61];
    let r = [0x246cd5c9fa76ff97, 0xe9c172d8b04b02c0, 0x520a70b8e8f6fb05, 0x4937d15fdde73a18];
    let s = [0x61d67bf49d1fc210, 0x151ea7a2cff0595c, 0xc902e317c6b5850b, 0x70ac180d31a5336b];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xe1, 0x59, 0xeb, 0xdc, 0x8a, 0x9e, 0xe2, 0x02, 0x60, 0xd0, 0xfe, 0x5c, 0x2a, 0xe2, 0xbb,
        0x95, 0x08, 0x0e, 0x47, 0x0c,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 12
    let hash = [0x8b810941a5693723, 0xe3dc7ec51f007ac7, 0xe821799805060a4b, 0xcbfb5477b23d3f14];
    let r = [0x3a980eb4642b4606, 0xeff5e020f38d541c, 0x29980b458bff07cd, 0x465e8a566e29f97b];
    let s = [0x80b6201a46703bf0, 0x3dbb7411ed4d9370, 0xf811c435a79a737d, 0x531eaeeeec12998a];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x47, 0xf3, 0x99, 0x29, 0x33, 0xee, 0xba, 0xf6, 0xfc, 0xdb, 0xe3, 0x1e, 0xf4, 0x69, 0x9b,
        0xb6, 0x22, 0xd2, 0x77, 0x67,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 13
    let hash = [0xd7325047aba2e081, 0xeed0b8949d3da51a, 0x47f91ff458ea71f6, 0xf27fb8414a5aaed9];
    let r = [0x1b935a8822f28890, 0x3548b71135e1d872, 0x0508b8eae88bf810, 0x493b8ca6e09c0645];
    let s = [0x0706588b6eb852a8, 0x4f2f4e085dfb9beb, 0xc48e92bd88761b45, 0x4dea2362974bb205];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x8b, 0x19, 0x3b, 0xb2, 0x45, 0xb3, 0xd2, 0x63, 0x93, 0x8d, 0x47, 0x78, 0x49, 0x28, 0x1f,
        0xca, 0xf3, 0xa9, 0x56, 0x1f,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 14
    let hash = [0x561504993be9ccca, 0x77a8a09dbfa7ccc2, 0xd8372f82f9fa700a, 0x7d7e073c17eb159a];
    let r = [0xe87fb438316db708, 0x4d875b2fd64df1db, 0xa641fe88235387a5, 0x8c23081e8211029c];
    let s = [0xabbdf7004d21a7b7, 0x64399a6ad23c2efd, 0x3c03d94771453667, 0x41c8e2f71966a655];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x0e, 0xb5, 0xf7, 0x96, 0x90, 0x2f, 0x23, 0x26, 0x5d, 0xea, 0x67, 0x97, 0x08, 0x9b, 0x2d,
        0xe5, 0x04, 0x38, 0x7c, 0x6a,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 15
    let hash = [0xddca2e9777e04183, 0xd5435e61e738a119, 0x714878d3729975af, 0x8aec5831f7b02d4f];
    let r = [0x56ff5e48fd943372, 0x32543c4f4c5ae6af, 0x461339633082c8a0, 0x49b0018d05b6f36d];
    let s = [0x4ce96ed4507393c1, 0x9207e5ccac214eb9, 0x330697bddbe5e25d, 0x34f096b3ee06d00f];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x0a, 0xcc, 0x2c, 0x19, 0x12, 0xcd, 0xc3, 0x86, 0xc6, 0x01, 0x43, 0x15, 0x59, 0x58, 0xed,
        0xa6, 0x8f, 0x17, 0x6f, 0xdd,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 16
    let hash = [0x195de61e3438585f, 0x45c53e76f26798cc, 0xd9f40da627cfefbc, 0xc2c0f5c01b3e244b];
    let r = [0x830af4200d4bf253, 0xe01c41f97b31e4f6, 0x8294911be669e953, 0x4a06e1f0012017c6];
    let s = [0x4f2291da2cf0e1f3, 0xe50f28ecf27a051b, 0x175812972ce89e54, 0x2eafb33fbb92b512];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x39, 0xc9, 0xd2, 0x91, 0x1c, 0x0e, 0x98, 0x7b, 0x4c, 0x1e, 0xae, 0xb1, 0x1b, 0xa5, 0x5f,
        0x56, 0xd8, 0x05, 0xfd, 0x5f,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 17
    let hash = [0xc128b453f76877a3, 0x7eb4845037bc344f, 0x54983e43f80a27a0, 0x1430fc999d7bfa89];
    let r = [0xdb2467d06445bed8, 0x386aa73a6bed50e8, 0x0cb6f9657e1650e1, 0x88843aea48fff679];
    let s = [0x0662ed779fb22ead, 0x6732d49715857069, 0x9f33431c9d4794a1, 0x779ce085139a5fc4];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xa6, 0x80, 0x5f, 0xab, 0xdf, 0x13, 0x43, 0xdf, 0x93, 0x99, 0x59, 0x5a, 0xb4, 0x0f, 0xde,
        0xfa, 0x7a, 0xe0, 0x29, 0xf3,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 18
    let hash = [0xe38162b18c2f2ff6, 0xbadf091e452f910d, 0x22e4a0f0f81a6cd5, 0x8bc6619ef176973b];
    let r = [0x2fa1c8d57ded6a5d, 0x6d1494c29f29cdc5, 0x692ffc7284fa2859, 0x347faebc1fc4c014];
    let s = [0xf416b80f82ee5ef9, 0x161a05e542afd29c, 0xaa56d9611f50bf3d, 0x597a18da2e6c3c1e];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xee, 0xa9, 0x13, 0xd1, 0x85, 0x41, 0x0c, 0x78, 0xd3, 0xb4, 0x20, 0xdf, 0xf1, 0x50, 0xfd,
        0x90, 0xb9, 0x59, 0x15, 0x41,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 19
    let hash = [0x392f51001c715006, 0x33133be5a697f076, 0xb8fc3d41d6df1768, 0xb3dc90532569a73a];
    let r = [0x78a80ec7c89666b9, 0x07f7fd572e118f42, 0xb587b1bdd3b77b12, 0xaf4592a0ec76c84b];
    let s = [0xe0a6868a2f10edb6, 0x2737b5b90ed4a03c, 0xb883d32006b79953, 0x0cb4bd62edd2d286];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xb1, 0x16, 0x77, 0x73, 0xbb, 0x72, 0x9b, 0x30, 0x66, 0x91, 0x53, 0xf4, 0x43, 0x07, 0xae,
        0xfd, 0xfb, 0xa1, 0xe1, 0xb2,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 20
    let hash = [0x5e5f7decafccbdc8, 0x47cca19ee828d661, 0x2fa06a8c2855c695, 0xc7367ffedb65fe02];
    let r = [0xb0e231c5aeeefb18, 0xb32ec2a445544fab, 0x6b37f4ad9b507ad3, 0xb7fd2fa91dd0ba81];
    let s = [0x0529b7bac9490742, 0x6b11b9397baaf29d, 0x3c3db9bda9b39d6e, 0x244c004f8b78dc3a];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x91, 0xae, 0xa7, 0x7a, 0x06, 0x5d, 0x36, 0x9d, 0xef, 0xb2, 0xc7, 0x8a, 0xff, 0x50, 0x55,
        0x7e, 0xe1, 0xaf, 0xdd, 0x95,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 21
    let hash = [0x762b51fecad5577c, 0x3d0b67842b551599, 0xe71bb3f6015410f3, 0x898a015948f4e12f];
    let r = [0xd797a729c003598b, 0xcb689f1800f71384, 0xabc59666e34cd4ac, 0xa0d427856db72164];
    let s = [0xc5d88d1f85656039, 0xaf198760e3ac5077, 0x3d75ed7182d81168, 0x514d41eca750ebe0];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xf8, 0xde, 0xbb, 0x8c, 0x79, 0x36, 0x54, 0x73, 0x28, 0x5f, 0xc4, 0x09, 0xa1, 0x8c, 0xe9,
        0xf2, 0xa3, 0xcf, 0x39, 0x9d,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 22
    let hash = [0xfe5e08e00531182e, 0x3d39831e5355e99b, 0x37d37430ccdda08b, 0xadd47d80decfc500];
    let r = [0x449846044f228d4a, 0xed091108ce03f7ef, 0x1b55fa4aeeebfb3e, 0xf74a32e691a8e0ee];
    let s = [0x45a1570286d94e41, 0x829490b57a561c9f, 0xe4a83c5e80c4f316, 0x308af50fef22673a];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x9f, 0x7c, 0xe9, 0x89, 0xd0, 0x97, 0x99, 0x26, 0x61, 0xdd, 0x6e, 0xe1, 0x98, 0x7e, 0xff,
        0x4d, 0xd2, 0xc3, 0xb0, 0x4a,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 23
    let hash = [0xf88ac5abadf83420, 0x9c475a28e687d943, 0xb0d3407969123c71, 0x8fc27577b5290a3a];
    let r = [0xdca02af69d8c29bd, 0xfa5446c2dbdd5e30, 0xd351b5dde35c0ebe, 0x8b9d9e9c4201b9b2];
    let s = [0xe275d286e45917f6, 0x8e6d3265426f602b, 0x59ee64aae40d4ba4, 0x047fb2ba1e4cc0a0];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x6e, 0xab, 0x4e, 0xb3, 0x14, 0xbe, 0xc2, 0xf3, 0xb7, 0xa5, 0x94, 0xa9, 0x0a, 0xf4, 0xd3,
        0x18, 0xab, 0x6a, 0x2c, 0xd0,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 24
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x256e9aea5e197a1f];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xf4, 0x5d, 0xb7, 0x8f, 0x09, 0x7b, 0x58, 0x8c, 0x33, 0x47, 0x97, 0xc3, 0x01, 0xb9, 0x3e,
        0x02, 0xd8, 0x25, 0xe3, 0x34,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 25
    let hash = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x7c, 0x4f, 0xe5, 0xf8, 0x8c, 0x2f, 0xea, 0x6a, 0x74, 0x9d, 0x28, 0x4e, 0xb7, 0xe0, 0x62,
        0xd6, 0x4c, 0x8c, 0x55, 0x2a,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 26
    let hash = [0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x7c, 0x4f, 0xe5, 0xf8, 0x8c, 0x2f, 0xea, 0x6a, 0x74, 0x9d, 0x28, 0x4e, 0xb7, 0xe0, 0x62,
        0xd6, 0x4c, 0x8c, 0x55, 0x2a,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 27
    let hash = [0xbfd25e8cd0364140, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xff, 0x62, 0x8f, 0xd3, 0xff, 0x47, 0xd2, 0x04, 0x0d, 0x82, 0x18, 0x66, 0x97, 0xc6, 0xfa,
        0x06, 0x9e, 0xba, 0x1a, 0xc4,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 28
    let hash = [0xbfd25e8cd0364142, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x09, 0x61, 0xa0, 0xf9, 0x6f, 0x79, 0xa1, 0x4d, 0xee, 0xf6, 0x06, 0x64, 0xa7, 0xaf, 0x8f,
        0xdd, 0x50, 0x3f, 0x34, 0x7a,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 29
    let hash = [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x09, 0x61, 0xa0, 0xf9, 0x6f, 0x79, 0xa1, 0x4d, 0xee, 0xf6, 0x06, 0x64, 0xa7, 0xaf, 0x8f,
        0xdd, 0x50, 0x3f, 0x34, 0x7a,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 30
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x32, 0x72, 0x81, 0x59, 0x3d, 0x9d, 0xae, 0x20, 0xee, 0xb9, 0x09, 0x63, 0xe3, 0x03, 0x83,
        0x95, 0x3c, 0xfd, 0x77, 0xe0,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 31
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 26;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 32
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 29;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 33
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 34
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 35
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0xbfd25e8cd0364142, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 36
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0xbfd25e8cd0364140, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
    let s = [0x0c368ae950852ada, 0x1e56992d0774dc34, 0x0bd448298cc2e207, 0x4f8ae3bd7535248d];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 37
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 38
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0xdfe92f46681b20a1, 0x5d576e7357a4501d, 0xffffffffffffffff, 0x7fffffffffffffff];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [
        0xa3, 0xb7, 0xe3, 0x3a, 0xfe, 0xe6, 0x97, 0x0a, 0xb3, 0x79, 0xbc, 0x02, 0x8a, 0xee, 0x8b,
        0xdd, 0xca, 0x45, 0xf4, 0x4e,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 39
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0xdfe92f46681b20a0, 0x5d576e7357a4501d, 0xffffffffffffffff, 0x7fffffffffffffff];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x8d, 0x61, 0x9a, 0x7e, 0xd8, 0x34, 0x81, 0xb2, 0x7e, 0xcd, 0x6e, 0xa9, 0xdf, 0x60, 0x16,
        0x40, 0xaa, 0x65, 0x9f, 0xb2,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 40
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0xdfe92f46681b20a2, 0x5d576e7357a4501d, 0xffffffffffffffff, 0x7fffffffffffffff];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [
        0x64, 0x45, 0xd5, 0x3b, 0xbe, 0x80, 0xc7, 0xd9, 0x53, 0x55, 0x0f, 0x9e, 0xf2, 0x55, 0x34,
        0xfe, 0xa7, 0x6a, 0x70, 0xfe,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 41
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0xbfd25e8cd0364140, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [
        0x0e, 0xa6, 0x32, 0x54, 0x34, 0x95, 0xd9, 0xa8, 0xb9, 0x65, 0x22, 0x04, 0x61, 0xa7, 0x85,
        0xab, 0xe4, 0xe2, 0x46, 0xc8,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 42
    let hash = [0x4c860fc0b0c64ef3, 0x4049a3ba34c2289b, 0x1af7a3e85a3212fa, 0x456e9aea5e197a1f];
    let r = [0x2664ac8038825608, 0x8eb630ea16aa137d, 0xc25603c231bc2f56, 0x9242685bf161793c];
    let s = [0xbfd25e8cd0364142, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 43
    let hash = [0x7194cbf7ebc1eebe, 0xccb41cee02d9d441, 0x77188e4fbd022f35, 0x3cc4cb050478c498];
    let r = [0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac];
    let s = [0x450c889d597a16c4, 0xba2e787583036325, 0xa77344d5943e0228, 0x2bcf13b5e4f34a04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xa3, 0x39, 0x6b, 0x62, 0x00, 0xc5, 0x61, 0xe0, 0xd7, 0xfa, 0x25, 0xf4, 0x58, 0x96, 0x54,
        0x26, 0x24, 0x5f, 0x8b, 0x3c,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 44
    let hash = [0x7194cbf7ebc1eebe, 0xccb41cee02d9d441, 0x77188e4fbd022f35, 0x3cc4cb050478c498];
    let r = [0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac];
    let s = [0x450c889d597a16c4, 0xba2e787583036325, 0xa77344d5943e0228, 0x2bcf13b5e4f34a04];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x9e, 0x91, 0xf3, 0x03, 0x56, 0xa4, 0xd1, 0x96, 0x8c, 0xeb, 0xb2, 0xa9, 0xb0, 0x19, 0x3c,
        0x23, 0xad, 0x26, 0x75, 0x68,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 45
    let hash = [0x7194cbf7ebc1eec0, 0xccb41cee02d9d441, 0x77188e4fbd022f35, 0x3cc4cb050478c498];
    let r = [0xabac09b95c709ee5, 0x5c778e4b8cef3ca7, 0x3045406e95c07cd8, 0xc6047f9441ed7d6d];
    let s = [0x450c889d597a16c8, 0xba2e787583036325, 0xa77344d5943e0228, 0x2bcf13b5e4f34a04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x1d, 0x89, 0xa1, 0xa3, 0xcc, 0x93, 0xc9, 0x04, 0x5a, 0x6b, 0xf3, 0x63, 0xfb, 0x0e, 0x4a,
        0xbd, 0x98, 0xa1, 0xfe, 0x89,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 46
    let hash = [0x7194cbf7ebc1eec0, 0xccb41cee02d9d441, 0x77188e4fbd022f35, 0x3cc4cb050478c498];
    let r = [0xabac09b95c709ee5, 0x5c778e4b8cef3ca7, 0x3045406e95c07cd8, 0xc6047f9441ed7d6d];
    let s = [0x450c889d597a16c8, 0xba2e787583036325, 0xa77344d5943e0228, 0x2bcf13b5e4f34a04];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x32, 0x14, 0x28, 0x4d, 0xec, 0xfb, 0xd6, 0xe3, 0x52, 0xf8, 0x65, 0x17, 0x20, 0x92, 0xa0,
        0x8d, 0x2e, 0x18, 0x13, 0xc6,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 47
    let hash = [0x7194cbf7ebc1eec1, 0xccb41cee02d9d441, 0x77188e4fbd022f35, 0x3cc4cb050478c498];
    let r = [0xabac09b95c709ee5, 0x5c778e4b8cef3ca7, 0x3045406e95c07cd8, 0xc6047f9441ed7d6d];
    let s = [0x450c889d597a16c8, 0xba2e787583036325, 0xa77344d5943e0228, 0x2bcf13b5e4f34a04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0x7e, 0xa1, 0xea, 0x3e, 0x01, 0x74, 0x5a, 0x82, 0x65, 0xee, 0x61, 0xa3, 0xdc, 0x0f, 0x31,
        0xfa, 0x1c, 0xbf, 0x72, 0x17,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 48
    let hash = [0x7194cbf7ebc1eebe, 0xccb41cee02d9d441, 0x77188e4fbd022f35, 0x3cc4cb050478c498];
    let r = [0x0000000000001798, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let s = [0x450c889d597a16c4, 0xba2e787583036325, 0xa77344d5943e0228, 0x2bcf13b5e4f34a04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xcb, 0xd5, 0xa2, 0x87, 0x57, 0xba, 0x98, 0x79, 0x43, 0xa9, 0xa8, 0xb2, 0x97, 0xdc, 0xae,
        0x3a, 0x7b, 0xd3, 0x46, 0x94,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 49
    let hash = [0x7194cbf7ebc1eebe, 0xccb41cee02d9d441, 0x77188e4fbd022f35, 0x3cc4cb050478c498];
    let r = [0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x001e667ef9dcbbac];
    let s = [0x450c889d597a16c4, 0xba2e787583036325, 0xa77344d5943e0228, 0x2bcf13b5e4f34a04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [
        0xb1, 0xb4, 0xd7, 0x9f, 0xd0, 0x2b, 0x1a, 0xa0, 0x75, 0x14, 0x73, 0xf7, 0xe6, 0x8d, 0xab,
        0x74, 0x36, 0x56, 0x90, 0x4c,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 50
    let hash = [0xbfd25e8cd0364142, 0xbaaedce6af48a03b, 0x000000000000003e, 0x0000000000000000];
    let r = [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let s = [0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffbf, 0xffffffffffffffff];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [
        0xe0, 0x8e, 0xcb, 0xd4, 0x6a, 0x3d, 0x92, 0xd1, 0x8b, 0xb2, 0x62, 0x22, 0xee, 0xda, 0xce,
        0x26, 0x83, 0x8c, 0xe3, 0x07,
    ];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);
}

/// Given a hash `hash`, a recovery parity `v`, a signature (`r`, `s`), and a signature mode `mode`,
/// this function computes the address that signed the hash.
///
/// It also returns an error code:
/// - 0: No error
/// - 1: r should be greater than 0
/// - 2: r should be less than `N_MINUS_ONE`
/// - 3: s should be greater than 0
/// - 4: s should be less than `N_MINUS_ONE` or `N_HALF`
/// - 5: v should be either 27 or 28
/// - 6: No square root found for `y_sq`
/// - 7: Invalid parity
/// - 8: The public key is the point at infinity
fn ecrecover(hash: &[u64; 4], v: u8, r: &[u64; 4], s: &[u64; 4], mode: bool) -> ([u8; 20], u8) {
    // Check r is in the range [1, n-1]
    if r == &[0, 0, 0, 0] {
        #[cfg(debug_assertions)]
        println!("r should be greater than 0");

        return ([0; 20], 1);
    } else if r >= &N_MINUS_ONE {
        #[cfg(debug_assertions)]
        println!("r should be less than N_MINUS_ONE: {:?}, but got {:?}", N_MINUS_ONE, r);

        return ([0; 20], 2);
    }

    // Check s is either in the range [1, n-1] or [1, (n-1)/2]
    let s_limit = if mode { N_MINUS_ONE } else { N_HALF };

    if s == &[0, 0, 0, 0] {
        #[cfg(debug_assertions)]
        println!("s should be greater than 0");

        return ([0; 20], 3);
    } else if s >= &s_limit {
        #[cfg(debug_assertions)]
        println!("s should be less than s_limit: {:?}, but got {:?}", s_limit, s);

        return ([0; 20], 4);
    }

    // Check v is either 27 or 28
    if v != 27 && v != 28 {
        #[cfg(debug_assertions)]
        println!("v should be either 27 or 28, but got {}", v);

        return ([0; 20], 5);
    }

    // Calculate the recovery id
    let parity = v - 27;

    // In Ethereum, signatures where the x-coordinate of the resulting point is
    // greater than N are considered invalid. Hence, r = x as integers
    let x = r;

    // Calculate the y-coordinate of the point: y = sqrt(x³ + 7)
    let x_copy = r;
    let mut params = SyscallArith256ModParams {
        a: &x,
        b: &x_copy,
        c: &[0, 0, 0, 0],
        module: &P,
        d: &mut [0, 0, 0, 0],
    };
    syscall_arith256_mod(&mut params);
    let x_sq = params.d;

    params.a = &x_sq;
    params.b = &x;
    params.c = &[7, 0, 0, 0];
    syscall_arith256_mod(&mut params);
    let y_sq = params.d;

    let y = match sqrt(y_sq, parity) {
        Some(y) => y,
        None => {
            #[cfg(debug_assertions)]
            println!("No square root found for y_sq: {:?}", y_sq);

            return ([0; 20], 6);
        }
    };

    // It y_sq has square root, get its parity
    let y = y.unwrap();
    let y_parity = y[0] & 1;
    if parity != y_parity {
        #[cfg(debug_assertions)]
        println!("Invalid parity: expected {}, but got {}", parity, y_parity);

        return ([0; 20], 7);
    }

    // Calculate the public key
    let r_inv = inv_n(r);

    // Compute k1 = (-hash * r_inv) % N
    params.a = &hash;
    params.b = &r_inv;
    params.c = &[0, 0, 0, 0];
    params.module = &N;
    syscall_arith256_mod(&mut params);
    let k1 = sub(&N, params.d);

    // Compute k2 = (s * r_inv) % N
    params.a = &s;
    params.b = &r_inv;
    syscall_arith256_mod(&mut params);
    let k2 = params.d;

    // Calculate the public key
    let p = SyscallPoint256 { x: *x, y };
    let (pk_is_infinity, pk) = double_scalar_mul_with_g(&k1, k2, &p);
    if pk_is_infinity {
        return ([0; 20], 8);
    }

    // Compute the hash of the public key
    // Q: Is it better to use a hash API that accepts u64 instead of u8?
    // Q: This is quite optimal, but check how it can be done more low-level
    let pk_x: [u8; 32];
    let pk_y: [u8; 32];
    for i in 0..4 {
        pk_x[i * 8..(i + 1) * 8].copy_from_slice(&pk.x[i].to_le_bytes());
        pk_y[i * 8..(i + 1) * 8].copy_from_slice(&pk.y[i].to_le_bytes());
    }

    let mut pk_hash = [0u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(&pk_x);
    keccak.update(&pk_y);
    keccak.finalize(&mut pk_hash);

    // Return the least significant 20 bytes of the hash
    // Q: Should I better return u64?
    let addr: [u8; 20];
    for i in 0..20 {
        addr[i] = pk_hash[i];
    }
    (addr, 0)
}

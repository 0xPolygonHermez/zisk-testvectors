#![no_main]
ziskos::entrypoint!(main);

mod utils;

use tiny_keccak::{Hasher, Keccak};
use utils::{double_scalar_mul_with_g, sub};
use ziskos::syscalls::{
    arith256_mod::{syscall_arith256_mod, SyscallArith256ModParams},
    point256::SyscallPoint256,
};

/// Secp256k1 prime field size
const P: [u64; 4] =
    [0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF];

/// Secp256k1 scalar field size
const N: [u64; 4] =
    [0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
const N_MINUS_ONE: [u64; 4] =
    [0xBFD25E8CD0364140, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
const N_HALF: [u64; 4] =
    [0xDFE92F46681B20A0, 0x5D576E7357A4501D, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];

fn main() {
    // Test 1
    let hash = [0x6F365326CF807D68, 0x2BB4CC214D3220A3, 0x2B71FE008C98CC87, 0xD9EBA16ED0ECAE43];
    let r = [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC];
    let s = [0x8CBF3034D73214B8, 0xABC6939A1710AFC0, 0xCAB9646C504576B3, 0x265E99E47AD31BB2];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xB7, 0xAF, 0x5E, 0x18, 0xC9, 0xD9, 0xE2, 0x94, 0xDF, 0x3F, 0xAD, 0x2E, 0x64, 0x8F, 0x86, 0xD5, 0x4A, 0x67, 0x44, 0xBC];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 2
    let hash = [0x6F365326CF807D68, 0x2BB4CC214D3220A3, 0x2B71FE008C98CC87, 0xD9EBA16ED0ECAE43];
    let r = [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC];
    let s = [0x8CBF3034D73214B8, 0xABC6939A1710AFC0, 0xCAB9646C504576B3, 0x265E99E47AD31BB2];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xB8, 0xFD, 0x7C, 0xF6, 0x09, 0x76, 0xEE, 0x5D, 0x63, 0x8F, 0x81, 0x37, 0x73, 0x5C, 0x4E, 0x8D, 0xB3, 0xEF, 0x3F, 0xEE];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 3
    let hash = [0x6F365326CF807D68, 0x2BB4CC214D3220A3, 0x2B71FE008C98CC87, 0xD9EBA16ED0ECAE43];
    let r = [0x80948544508F3C63, 0xB513AA0028EC6C98, 0x56B4E35A077B9A11, 0xDDD0A7290AF95260];
    let s = [0x8CBF3034D73214B8, 0xABC6939A1710AFC0, 0xCAB9646C504576B3, 0x265E99E47AD31BB2];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x25, 0x93, 0xE5, 0x08, 0xB3, 0x97, 0xF9, 0xC9, 0x84, 0x84, 0xF1, 0x71, 0x9A, 0x4C, 0x0E, 0x26, 0x97, 0x16, 0x79, 0x14];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 4
    let hash = [0x7194CBF7EBC1EEBE, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0xB777867DB61F8A62, 0x13224CB4819E3833, 0xBE0E02EDF967CE8F, 0x7DFF8B06F4914FF0];
    let s = [0x450C889D597A16C4, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xC2, 0x63, 0x9D, 0x33, 0x0C, 0x26, 0x31, 0x0F, 0xF4, 0x6F, 0x87, 0x11, 0xD8, 0xD4, 0x4C, 0xA2, 0x04, 0x0D, 0xC8, 0xBE];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 5
    let hash = [0xC3358F1822CEC07D, 0x94378D777E418020, 0xFD9B03C4B17B59A5, 0xEE43D51BAA54831B];
    let r = [0x9CC38620099E0C65, 0x17C0EB75E6DA8ECD, 0x77401B1BF67FD59E, 0xEA678B4B3EBDE1E8];
    let s = [0xFF3D6A45BED2A6E8, 0xDDA0688B9E965A4B, 0x97C4ABBCEDE04A5E, 0x2B954333CFE2B4BF];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xB5, 0x71, 0x7A, 0x7C, 0x13, 0xD2, 0x9B, 0xC4, 0x09, 0xC1, 0xDF, 0x7A, 0xE7, 0x47, 0x86, 0x0A, 0x18, 0xA2, 0x71, 0xD5];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 6
    let hash = [0x12BB42860D9D9C1F, 0x932BFE1C2AE7C21A, 0x3B958263C08DB17C, 0xFD98B0BFC9EECC81];
    let r = [0x0B04AF346CBF3AD2, 0x33DE35822652144B, 0x139BC29378FD243D, 0x86B2F6D4BAE0E1E1];
    let s = [0xCAB710F26600E2FC, 0x53D4C57A2D832090, 0xDC2203AB8ADAB6AE, 0x5EC4A8672D44B21B];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x9C, 0x43, 0x27, 0xFE, 0xD5, 0xA3, 0x71, 0x3E, 0x10, 0x54, 0x9D, 0x75, 0x71, 0x26, 0x1C, 0xE4, 0x36, 0x54, 0x85, 0x52];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 7
    let hash = [0xD36326DAC17839E5, 0x2B70DB9B738AB3F4, 0x928028DEF2818EC6, 0xC401C7D7BAA568F5];
    let r = [0xA6394256DD188B33, 0x4D6DEB59E5D524D1, 0x684815F4274D68D6, 0x4A95890F1102C6A6];
    let s = [0x74764BD790E42F51, 0x7C912BE5B176329A, 0xC8FF4103DA0740FD, 0x3E53619FE2F4C67A];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xFA, 0x89, 0xA8, 0xAD, 0x22, 0xA2, 0x35, 0x1C, 0xCF, 0x31, 0xDD, 0x09, 0x04, 0xD5, 0x59, 0xA4, 0x3E, 0x4C, 0xE2, 0xA4];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 8
    let hash = [0x56562D48C208002A, 0xCCDD993D5322656C, 0xA5354613066D0D67, 0x60049B234E7FD86B];
    let r = [0xCB90210C66868E99, 0x329ABEE4F91C4027, 0x99EC35B0C4A85F5C, 0xF06FBFB021B185A5];
    let s = [0x4208F0385F37BE1C, 0x710FE567A53D1A41, 0xA57B012B25BFD65F, 0x1E0E24CAB3E119FE];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x82, 0xE3, 0x05, 0xA0, 0x78, 0x89, 0x9D, 0xFB, 0x48, 0x76, 0xCC, 0x84, 0x2B, 0xD3, 0x52, 0xDB, 0xD6, 0xFD, 0x02, 0x23];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 9
    let hash = [0x340C902FF8F82D86, 0xBC97C448EEC72348, 0x5D34F3C78FD9262E, 0xFDA892E54EF8D0FC];
    let r = [0xCEBCF25F546C0BB3, 0xC5BFE6611F56D8A2, 0x723EA73FF89244D1, 0xE9713E52D8CA16C7];
    let s = [0xD01A29012435FE02, 0x367A9B54ED9C3C54, 0x5B8E06BA56F22EED, 0x627566979C5B6E3A];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xEE, 0xD9, 0xDB, 0xC4, 0xA8, 0xC1, 0x1D, 0x75, 0x59, 0xEB, 0xF0, 0x99, 0x4C, 0x68, 0x43, 0xAA, 0x2C, 0x5B, 0x66, 0xCC];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 10
    let hash = [0x5EF44A3A0DA75FD7, 0x0B6F4F7BC42FA400, 0xB734EF91A35A3184, 0x1DF5D6CD09999848];
    let r = [0xED675602A00EBF21, 0x5326DA91BF3AF225, 0x16D34E6D1CEACFD7, 0x8C661A2E0AE1FFE7];
    let s = [0x8F55E8A4C9954000, 0x3B278BB1AC1F52FB, 0xAE68326D7781ED90, 0x3DE21452FD054750];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x62, 0x1E, 0x71, 0xBD, 0x8D, 0x72, 0x3A, 0x94, 0xDD, 0x90, 0x90, 0x83, 0xED, 0x2F, 0x3C, 0x42, 0x8A, 0x35, 0x34, 0x1F];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 11
    let hash = [0x12168CE0CE5BC500, 0xF2913A407A15EE60, 0xA1FF7DBEF2CBB063, 0x84254D72D3A17A61];
    let r = [0x246CD5C9FA76FF97, 0xE9C172D8B04B02C0, 0x520A70B8E8F6FB05, 0x4937D15FDDE73A18];
    let s = [0x61D67BF49D1FC210, 0x151EA7A2CFF0595C, 0xC902E317C6B5850B, 0x70AC180D31A5336B];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xE1, 0x59, 0xEB, 0xDC, 0x8A, 0x9E, 0xE2, 0x02, 0x60, 0xD0, 0xFE, 0x5C, 0x2A, 0xE2, 0xBB, 0x95, 0x08, 0x0E, 0x47, 0x0C];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 12
    let hash = [0x8B810941A5693723, 0xE3DC7EC51F007AC7, 0xE821799805060A4B, 0xCBFB5477B23D3F14];
    let r = [0x3A980EB4642B4606, 0xEFF5E020F38D541C, 0x29980B458BFF07CD, 0x465E8A566E29F97B];
    let s = [0x80B6201A46703BF0, 0x3DBB7411ED4D9370, 0xF811C435A79A737D, 0x531EAEEEEC12998A];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x47, 0xF3, 0x99, 0x29, 0x33, 0xEE, 0xBA, 0xF6, 0xFC, 0xDB, 0xE3, 0x1E, 0xF4, 0x69, 0x9B, 0xB6, 0x22, 0xD2, 0x77, 0x67];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 13
    let hash = [0xD7325047ABA2E081, 0xEED0B8949D3DA51A, 0x47F91FF458EA71F6, 0xF27FB8414A5AAED9];
    let r = [0x1B935A8822F28890, 0x3548B71135E1D872, 0x0508B8EAE88BF810, 0x493B8CA6E09C0645];
    let s = [0x0706588B6EB852A8, 0x4F2F4E085DFB9BEB, 0xC48E92BD88761B45, 0x4DEA2362974BB205];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x8B, 0x19, 0x3B, 0xB2, 0x45, 0xB3, 0xD2, 0x63, 0x93, 0x8D, 0x47, 0x78, 0x49, 0x28, 0x1F, 0xCA, 0xF3, 0xA9, 0x56, 0x1F];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 14
    let hash = [0x561504993BE9CCCA, 0x77A8A09DBFA7CCC2, 0xD8372F82F9FA700A, 0x7D7E073C17EB159A];
    let r = [0xE87FB438316DB708, 0x4D875B2FD64DF1DB, 0xA641FE88235387A5, 0x8C23081E8211029C];
    let s = [0xABBDF7004D21A7B7, 0x64399A6AD23C2EFD, 0x3C03D94771453667, 0x41C8E2F71966A655];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0E, 0xB5, 0xF7, 0x96, 0x90, 0x2F, 0x23, 0x26, 0x5D, 0xEA, 0x67, 0x97, 0x08, 0x9B, 0x2D, 0xE5, 0x04, 0x38, 0x7C, 0x6A];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 15
    let hash = [0xDDCA2E9777E04183, 0xD5435E61E738A119, 0x714878D3729975AF, 0x8AEC5831F7B02D4F];
    let r = [0x56FF5E48FD943372, 0x32543C4F4C5AE6AF, 0x461339633082C8A0, 0x49B0018D05B6F36D];
    let s = [0x4CE96ED4507393C1, 0x9207E5CCAC214EB9, 0x330697BDDBE5E25D, 0x34F096B3EE06D00F];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0A, 0xCC, 0x2C, 0x19, 0x12, 0xCD, 0xC3, 0x86, 0xC6, 0x01, 0x43, 0x15, 0x59, 0x58, 0xED, 0xA6, 0x8F, 0x17, 0x6F, 0xDD];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 16
    let hash = [0x195DE61E3438585F, 0x45C53E76F26798CC, 0xD9F40DA627CFEFBC, 0xC2C0F5C01B3E244B];
    let r = [0x830AF4200D4BF253, 0xE01C41F97B31E4F6, 0x8294911BE669E953, 0x4A06E1F0012017C6];
    let s = [0x4F2291DA2CF0E1F3, 0xE50F28ECF27A051B, 0x175812972CE89E54, 0x2EAFB33FBB92B512];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x39, 0xC9, 0xD2, 0x91, 0x1C, 0x0E, 0x98, 0x7B, 0x4C, 0x1E, 0xAE, 0xB1, 0x1B, 0xA5, 0x5F, 0x56, 0xD8, 0x05, 0xFD, 0x5F];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 17
    let hash = [0xC128B453F76877A3, 0x7EB4845037BC344F, 0x54983E43F80A27A0, 0x1430FC999D7BFA89];
    let r = [0xDB2467D06445BED8, 0x386AA73A6BED50E8, 0x0CB6F9657E1650E1, 0x88843AEA48FFF679];
    let s = [0x0662ED779FB22EAD, 0x6732D49715857069, 0x9F33431C9D4794A1, 0x779CE085139A5FC4];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xA6, 0x80, 0x5F, 0xAB, 0xDF, 0x13, 0x43, 0xDF, 0x93, 0x99, 0x59, 0x5A, 0xB4, 0x0F, 0xDE, 0xFA, 0x7A, 0xE0, 0x29, 0xF3];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 18
    let hash = [0xE38162B18C2F2FF6, 0xBADF091E452F910D, 0x22E4A0F0F81A6CD5, 0x8BC6619EF176973B];
    let r = [0x2FA1C8D57DED6A5D, 0x6D1494C29F29CDC5, 0x692FFC7284FA2859, 0x347FAEBC1FC4C014];
    let s = [0xF416B80F82EE5EF9, 0x161A05E542AFD29C, 0xAA56D9611F50BF3D, 0x597A18DA2E6C3C1E];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xEE, 0xA9, 0x13, 0xD1, 0x85, 0x41, 0x0C, 0x78, 0xD3, 0xB4, 0x20, 0xDF, 0xF1, 0x50, 0xFD, 0x90, 0xB9, 0x59, 0x15, 0x41];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 19
    let hash = [0x392F51001C715006, 0x33133BE5A697F076, 0xB8FC3D41D6DF1768, 0xB3DC90532569A73A];
    let r = [0x78A80EC7C89666B9, 0x07F7FD572E118F42, 0xB587B1BDD3B77B12, 0xAF4592A0EC76C84B];
    let s = [0xE0A6868A2F10EDB6, 0x2737B5B90ED4A03C, 0xB883D32006B79953, 0x0CB4BD62EDD2D286];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xB1, 0x16, 0x77, 0x73, 0xBB, 0x72, 0x9B, 0x30, 0x66, 0x91, 0x53, 0xF4, 0x43, 0x07, 0xAE, 0xFD, 0xFB, 0xA1, 0xE1, 0xB2];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 20
    let hash = [0x5E5F7DECAFCCBDC8, 0x47CCA19EE828D661, 0x2FA06A8C2855C695, 0xC7367FFEDB65FE02];
    let r = [0xB0E231C5AEEEFB18, 0xB32EC2A445544FAB, 0x6B37F4AD9B507AD3, 0xB7FD2FA91DD0BA81];
    let s = [0x0529B7BAC9490742, 0x6B11B9397BAAF29D, 0x3C3DB9BDA9B39D6E, 0x244C004F8B78DC3A];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x91, 0xAE, 0xA7, 0x7A, 0x06, 0x5D, 0x36, 0x9D, 0xEF, 0xB2, 0xC7, 0x8A, 0xFF, 0x50, 0x55, 0x7E, 0xE1, 0xAF, 0xDD, 0x95];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 21
    let hash = [0x762B51FECAD5577C, 0x3D0B67842B551599, 0xE71BB3F6015410F3, 0x898A015948F4E12F];
    let r = [0xD797A729C003598B, 0xCB689F1800F71384, 0xABC59666E34CD4AC, 0xA0D427856DB72164];
    let s = [0xC5D88D1F85656039, 0xAF198760E3AC5077, 0x3D75ED7182D81168, 0x514D41ECA750EBE0];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xF8, 0xDE, 0xBB, 0x8C, 0x79, 0x36, 0x54, 0x73, 0x28, 0x5F, 0xC4, 0x09, 0xA1, 0x8C, 0xE9, 0xF2, 0xA3, 0xCF, 0x39, 0x9D];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 22
    let hash = [0xFE5E08E00531182E, 0x3D39831E5355E99B, 0x37D37430CCDDA08B, 0xADD47D80DECFC500];
    let r = [0x449846044F228D4A, 0xED091108CE03F7EF, 0x1B55FA4AEEEBFB3E, 0xF74A32E691A8E0EE];
    let s = [0x45A1570286D94E41, 0x829490B57A561C9F, 0xE4A83C5E80C4F316, 0x308AF50FEF22673A];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x9F, 0x7C, 0xE9, 0x89, 0xD0, 0x97, 0x99, 0x26, 0x61, 0xDD, 0x6E, 0xE1, 0x98, 0x7E, 0xFF, 0x4D, 0xD2, 0xC3, 0xB0, 0x4A];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 23
    let hash = [0xF88AC5ABADF83420, 0x9C475A28E687D943, 0xB0D3407969123C71, 0x8FC27577B5290A3A];
    let r = [0xDCA02AF69D8C29BD, 0xFA5446C2DBDD5E30, 0xD351B5DDE35C0EBE, 0x8B9D9E9C4201B9B2];
    let s = [0xE275D286E45917F6, 0x8E6D3265426F602B, 0x59EE64AAE40D4BA4, 0x047FB2BA1E4CC0A0];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x6E, 0xAB, 0x4E, 0xB3, 0x14, 0xBE, 0xC2, 0xF3, 0xB7, 0xA5, 0x94, 0xA9, 0x0A, 0xF4, 0xD3, 0x18, 0xAB, 0x6A, 0x2C, 0xD0];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 24
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x256E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xF4, 0x5D, 0xB7, 0x8F, 0x09, 0x7B, 0x58, 0x8C, 0x33, 0x47, 0x97, 0xC3, 0x01, 0xB9, 0x3E, 0x02, 0xD8, 0x25, 0xE3, 0x34];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 25
    let hash = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x7C, 0x4F, 0xE5, 0xF8, 0x8C, 0x2F, 0xEA, 0x6A, 0x74, 0x9D, 0x28, 0x4E, 0xB7, 0xE0, 0x62, 0xD6, 0x4C, 0x8C, 0x55, 0x2A];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 26
    let hash = [0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x7C, 0x4F, 0xE5, 0xF8, 0x8C, 0x2F, 0xEA, 0x6A, 0x74, 0x9D, 0x28, 0x4E, 0xB7, 0xE0, 0x62, 0xD6, 0x4C, 0x8C, 0x55, 0x2A];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 27
    let hash = [0xBFD25E8CD0364140, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xFF, 0x62, 0x8F, 0xD3, 0xFF, 0x47, 0xD2, 0x04, 0x0D, 0x82, 0x18, 0x66, 0x97, 0xC6, 0xFA, 0x06, 0x9E, 0xBA, 0x1A, 0xC4];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 28
    let hash = [0xBFD25E8CD0364142, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x09, 0x61, 0xA0, 0xF9, 0x6F, 0x79, 0xA1, 0x4D, 0xEE, 0xF6, 0x06, 0x64, 0xA7, 0xAF, 0x8F, 0xDD, 0x50, 0x3F, 0x34, 0x7A];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 29
    let hash = [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x09, 0x61, 0xA0, 0xF9, 0x6F, 0x79, 0xA1, 0x4D, 0xEE, 0xF6, 0x06, 0x64, 0xA7, 0xAF, 0x8F, 0xDD, 0x50, 0x3F, 0x34, 0x7A];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 30
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x32, 0x72, 0x81, 0x59, 0x3D, 0x9D, 0xAE, 0x20, 0xEE, 0xB9, 0x09, 0x63, 0xE3, 0x03, 0x83, 0x95, 0x3C, 0xFD, 0x77, 0xE0];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 31
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 26;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 32
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 29;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 33
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 34
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 35
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0xBFD25E8CD0364142, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 36
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0xBFD25E8CD0364140, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 37
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 38
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0xDFE92F46681B20A1, 0x5D576E7357A4501D, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [0xA3, 0xB7, 0xE3, 0x3A, 0xFE, 0xE6, 0x97, 0x0A, 0xB3, 0x79, 0xBC, 0x02, 0x8A, 0xEE, 0x8B, 0xDD, 0xCA, 0x45, 0xF4, 0x4E];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 39
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0xDFE92F46681B20A0, 0x5D576E7357A4501D, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x8D, 0x61, 0x9A, 0x7E, 0xD8, 0x34, 0x81, 0xB2, 0x7E, 0xCD, 0x6E, 0xA9, 0xDF, 0x60, 0x16, 0x40, 0xAA, 0x65, 0x9F, 0xB2];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 40
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0xDFE92F46681B20A2, 0x5D576E7357A4501D, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [0x64, 0x45, 0xD5, 0x3B, 0xBE, 0x80, 0xC7, 0xD9, 0x53, 0x55, 0x0F, 0x9E, 0xF2, 0x55, 0x34, 0xFE, 0xA7, 0x6A, 0x70, 0xFE];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 41
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0xBFD25E8CD0364140, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [0x0E, 0xA6, 0x32, 0x54, 0x34, 0x95, 0xD9, 0xA8, 0xB9, 0x65, 0x22, 0x04, 0x61, 0xA7, 0x85, 0xAB, 0xE4, 0xE2, 0x46, 0xC8];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 42
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0xBFD25E8CD0364142, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 43
    let hash = [0x7194CBF7EBC1EEBE, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC];
    let s = [0x450C889D597A16C4, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xA3, 0x39, 0x6B, 0x62, 0x00, 0xC5, 0x61, 0xE0, 0xD7, 0xFA, 0x25, 0xF4, 0x58, 0x96, 0x54, 0x26, 0x24, 0x5F, 0x8B, 0x3C];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 44
    let hash = [0x7194CBF7EBC1EEBE, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC];
    let s = [0x450C889D597A16C4, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x9E, 0x91, 0xF3, 0x03, 0x56, 0xA4, 0xD1, 0x96, 0x8C, 0xEB, 0xB2, 0xA9, 0xB0, 0x19, 0x3C, 0x23, 0xAD, 0x26, 0x75, 0x68];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 45
    let hash = [0x7194CBF7EBC1EEC0, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0xABAC09B95C709EE5, 0x5C778E4B8CEF3CA7, 0x3045406E95C07CD8, 0xC6047F9441ED7D6D];
    let s = [0x450C889D597A16C8, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x1D, 0x89, 0xA1, 0xA3, 0xCC, 0x93, 0xC9, 0x04, 0x5A, 0x6B, 0xF3, 0x63, 0xFB, 0x0E, 0x4A, 0xBD, 0x98, 0xA1, 0xFE, 0x89];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 46
    let hash = [0x7194CBF7EBC1EEC0, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0xABAC09B95C709EE5, 0x5C778E4B8CEF3CA7, 0x3045406E95C07CD8, 0xC6047F9441ED7D6D];
    let s = [0x450C889D597A16C8, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x32, 0x14, 0x28, 0x4D, 0xEC, 0xFB, 0xD6, 0xE3, 0x52, 0xF8, 0x65, 0x17, 0x20, 0x92, 0xA0, 0x8D, 0x2E, 0x18, 0x13, 0xC6];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 47
    let hash = [0x7194CBF7EBC1EEC1, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0xABAC09B95C709EE5, 0x5C778E4B8CEF3CA7, 0x3045406E95C07CD8, 0xC6047F9441ED7D6D];
    let s = [0x450C889D597A16C8, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x7E, 0xA1, 0xEA, 0x3E, 0x01, 0x74, 0x5A, 0x82, 0x65, 0xEE, 0x61, 0xA3, 0xDC, 0x0F, 0x31, 0xFA, 0x1C, 0xBF, 0x72, 0x17];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 48
    let hash = [0x7194CBF7EBC1EEBE, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0x0000000000001798, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let s = [0x450C889D597A16C4, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xCB, 0xD5, 0xA2, 0x87, 0x57, 0xBA, 0x98, 0x79, 0x43, 0xA9, 0xA8, 0xB2, 0x97, 0xDC, 0xAE, 0x3A, 0x7B, 0xD3, 0x46, 0x94];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 49
    let hash = [0x7194CBF7EBC1EEBE, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x001E667EF9DCBBAC];
    let s = [0x450C889D597A16C4, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xB1, 0xB4, 0xD7, 0x9F, 0xD0, 0x2B, 0x1A, 0xA0, 0x75, 0x14, 0x73, 0xF7, 0xE6, 0x8D, 0xAB, 0x74, 0x36, 0x56, 0x90, 0x4C];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 50
    let hash = [0xBFD25E8CD0364142, 0xBAAEDCE6AF48A03B, 0x000000000000003E, 0x0000000000000000];
    let r = [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let s = [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFBF, 0xFFFFFFFFFFFFFFFF];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [0xE0, 0x8E, 0xCB, 0xD4, 0x6A, 0x3D, 0x92, 0xD1, 0x8B, 0xB2, 0x62, 0x22, 0xEE, 0xDA, 0xCE, 0x26, 0x83, 0x8C, 0xE3, 0x07];
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

    // Check the parity of the y-coordinate is correct
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

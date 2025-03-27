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

// cargo-zisk build --release
// RUST_BACKTRACE=full ../zisk/target/release/ziskemu -x -e target/riscv64ima-polygon-ziskos-elf/release/ecrecover
fn main() {
    // Test 1
    let hash = [0x6F365326CF807D68, 0x2BB4CC214D3220A3, 0x2B71FE008C98CC87, 0xD9EBA16ED0ECAE43];
    let r = [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC];
    let s = [0x8CBF3034D73214B8, 0xABC6939A1710AFC0, 0xCAB9646C504576B3, 0x265E99E47AD31BB2];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x94E2D9C9185EAFB7, 0xD5868F642EAD3FDF, 0x00000000BC44674A];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 2
    let hash = [0x6F365326CF807D68, 0x2BB4CC214D3220A3, 0x2B71FE008C98CC87, 0xD9EBA16ED0ECAE43];
    let r = [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC];
    let s = [0x8CBF3034D73214B8, 0xABC6939A1710AFC0, 0xCAB9646C504576B3, 0x265E99E47AD31BB2];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x5DEE7609F67CFDB8, 0x8D4E5C7337818F63, 0x00000000EE3FEFB3];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 3
    let hash = [0x6F365326CF807D68, 0x2BB4CC214D3220A3, 0x2B71FE008C98CC87, 0xD9EBA16ED0ECAE43];
    let r = [0x80948544508F3C63, 0xB513AA0028EC6C98, 0x56B4E35A077B9A11, 0xDDD0A7290AF95260];
    let s = [0x8CBF3034D73214B8, 0xABC6939A1710AFC0, 0xCAB9646C504576B3, 0x265E99E47AD31BB2];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xC9F997B308E59325, 0x260E4C9A71F18484, 0x0000000014791697];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 4
    let hash = [0x7194CBF7EBC1EEBE, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0xB777867DB61F8A62, 0x13224CB4819E3833, 0xBE0E02EDF967CE8F, 0x7DFF8B06F4914FF0];
    let s = [0x450C889D597A16C4, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0F31260C339D63C2, 0xA24CD4D811876FF4, 0x00000000BEC80D04];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 5
    let hash = [0xC3358F1822CEC07D, 0x94378D777E418020, 0xFD9B03C4B17B59A5, 0xEE43D51BAA54831B];
    let r = [0x9CC38620099E0C65, 0x17C0EB75E6DA8ECD, 0x77401B1BF67FD59E, 0xEA678B4B3EBDE1E8];
    let s = [0xFF3D6A45BED2A6E8, 0xDDA0688B9E965A4B, 0x97C4ABBCEDE04A5E, 0x2B954333CFE2B4BF];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xC49BD2137C7A71B5, 0x0A8647E77ADFC109, 0x00000000D571A218];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 6
    let hash = [0x12BB42860D9D9C1F, 0x932BFE1C2AE7C21A, 0x3B958263C08DB17C, 0xFD98B0BFC9EECC81];
    let r = [0x0B04AF346CBF3AD2, 0x33DE35822652144B, 0x139BC29378FD243D, 0x86B2F6D4BAE0E1E1];
    let s = [0xCAB710F26600E2FC, 0x53D4C57A2D832090, 0xDC2203AB8ADAB6AE, 0x5EC4A8672D44B21B];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x3E71A3D5FE27439C, 0xE41C2671759D5410, 0x0000000052855436];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 7
    let hash = [0xD36326DAC17839E5, 0x2B70DB9B738AB3F4, 0x928028DEF2818EC6, 0xC401C7D7BAA568F5];
    let r = [0xA6394256DD188B33, 0x4D6DEB59E5D524D1, 0x684815F4274D68D6, 0x4A95890F1102C6A6];
    let s = [0x74764BD790E42F51, 0x7C912BE5B176329A, 0xC8FF4103DA0740FD, 0x3E53619FE2F4C67A];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x1C35A222ADA889FA, 0xA459D50409DD31CF, 0x00000000A4E24C3E];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 8
    let hash = [0x56562D48C208002A, 0xCCDD993D5322656C, 0xA5354613066D0D67, 0x60049B234E7FD86B];
    let r = [0xCB90210C66868E99, 0x329ABEE4F91C4027, 0x99EC35B0C4A85F5C, 0xF06FBFB021B185A5];
    let s = [0x4208F0385F37BE1C, 0x710FE567A53D1A41, 0xA57B012B25BFD65F, 0x1E0E24CAB3E119FE];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xFB9D8978A005E382, 0xDB52D32B84CC7648, 0x000000002302FDD6];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 9
    let hash = [0x340C902FF8F82D86, 0xBC97C448EEC72348, 0x5D34F3C78FD9262E, 0xFDA892E54EF8D0FC];
    let r = [0xCEBCF25F546C0BB3, 0xC5BFE6611F56D8A2, 0x723EA73FF89244D1, 0xE9713E52D8CA16C7];
    let s = [0xD01A29012435FE02, 0x367A9B54ED9C3C54, 0x5B8E06BA56F22EED, 0x627566979C5B6E3A];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x751DC1A8C4DBD9EE, 0xAA43684C99F0EB59, 0x00000000CC665B2C];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 10
    let hash = [0x5EF44A3A0DA75FD7, 0x0B6F4F7BC42FA400, 0xB734EF91A35A3184, 0x1DF5D6CD09999848];
    let r = [0xED675602A00EBF21, 0x5326DA91BF3AF225, 0x16D34E6D1CEACFD7, 0x8C661A2E0AE1FFE7];
    let s = [0x8F55E8A4C9954000, 0x3B278BB1AC1F52FB, 0xAE68326D7781ED90, 0x3DE21452FD054750];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x943A728DBD711E62, 0x423C2FED839090DD, 0x000000001F34358A];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 11
    let hash = [0x12168CE0CE5BC500, 0xF2913A407A15EE60, 0xA1FF7DBEF2CBB063, 0x84254D72D3A17A61];
    let r = [0x246CD5C9FA76FF97, 0xE9C172D8B04B02C0, 0x520A70B8E8F6FB05, 0x4937D15FDDE73A18];
    let s = [0x61D67BF49D1FC210, 0x151EA7A2CFF0595C, 0xC902E317C6B5850B, 0x70AC180D31A5336B];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x02E29E8ADCEB59E1, 0x95BBE22A5CFED060, 0x000000000C470E08];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 12
    let hash = [0x8B810941A5693723, 0xE3DC7EC51F007AC7, 0xE821799805060A4B, 0xCBFB5477B23D3F14];
    let r = [0x3A980EB4642B4606, 0xEFF5E020F38D541C, 0x29980B458BFF07CD, 0x465E8A566E29F97B];
    let s = [0x80B6201A46703BF0, 0x3DBB7411ED4D9370, 0xF811C435A79A737D, 0x531EAEEEEC12998A];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xF6BAEE332999F347, 0xB69B69F41EE3DBFC, 0x000000006777D222];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 13
    let hash = [0xD7325047ABA2E081, 0xEED0B8949D3DA51A, 0x47F91FF458EA71F6, 0xF27FB8414A5AAED9];
    let r = [0x1B935A8822F28890, 0x3548B71135E1D872, 0x0508B8EAE88BF810, 0x493B8CA6E09C0645];
    let s = [0x0706588B6EB852A8, 0x4F2F4E085DFB9BEB, 0xC48E92BD88761B45, 0x4DEA2362974BB205];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x63D2B345B23B198B, 0xCA1F284978478D93, 0x000000001F56A9F3];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 14
    let hash = [0x561504993BE9CCCA, 0x77A8A09DBFA7CCC2, 0xD8372F82F9FA700A, 0x7D7E073C17EB159A];
    let r = [0xE87FB438316DB708, 0x4D875B2FD64DF1DB, 0xA641FE88235387A5, 0x8C23081E8211029C];
    let s = [0xABBDF7004D21A7B7, 0x64399A6AD23C2EFD, 0x3C03D94771453667, 0x41C8E2F71966A655];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x26232F9096F7B50E, 0xE52D9B089767EA5D, 0x000000006A7C3804];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 15
    let hash = [0xDDCA2E9777E04183, 0xD5435E61E738A119, 0x714878D3729975AF, 0x8AEC5831F7B02D4F];
    let r = [0x56FF5E48FD943372, 0x32543C4F4C5AE6AF, 0x461339633082C8A0, 0x49B0018D05B6F36D];
    let s = [0x4CE96ED4507393C1, 0x9207E5CCAC214EB9, 0x330697BDDBE5E25D, 0x34F096B3EE06D00F];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x86C3CD12192CCC0A, 0xA6ED5859154301C6, 0x00000000DD6F178F];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 16
    let hash = [0x195DE61E3438585F, 0x45C53E76F26798CC, 0xD9F40DA627CFEFBC, 0xC2C0F5C01B3E244B];
    let r = [0x830AF4200D4BF253, 0xE01C41F97B31E4F6, 0x8294911BE669E953, 0x4A06E1F0012017C6];
    let s = [0x4F2291DA2CF0E1F3, 0xE50F28ECF27A051B, 0x175812972CE89E54, 0x2EAFB33FBB92B512];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x7B980E1C91D2C939, 0x565FA51BB1AE1E4C, 0x000000005FFD05D8];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 17
    let hash = [0xC128B453F76877A3, 0x7EB4845037BC344F, 0x54983E43F80A27A0, 0x1430FC999D7BFA89];
    let r = [0xDB2467D06445BED8, 0x386AA73A6BED50E8, 0x0CB6F9657E1650E1, 0x88843AEA48FFF679];
    let s = [0x0662ED779FB22EAD, 0x6732D49715857069, 0x9F33431C9D4794A1, 0x779CE085139A5FC4];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xDF4313DFAB5F80A6, 0xFADE0FB45A599993, 0x00000000F329E07A];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 18
    let hash = [0xE38162B18C2F2FF6, 0xBADF091E452F910D, 0x22E4A0F0F81A6CD5, 0x8BC6619EF176973B];
    let r = [0x2FA1C8D57DED6A5D, 0x6D1494C29F29CDC5, 0x692FFC7284FA2859, 0x347FAEBC1FC4C014];
    let s = [0xF416B80F82EE5EF9, 0x161A05E542AFD29C, 0xAA56D9611F50BF3D, 0x597A18DA2E6C3C1E];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x780C4185D113A9EE, 0x90FD50F1DF20B4D3, 0x00000000411559B9];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 19
    let hash = [0x392F51001C715006, 0x33133BE5A697F076, 0xB8FC3D41D6DF1768, 0xB3DC90532569A73A];
    let r = [0x78A80EC7C89666B9, 0x07F7FD572E118F42, 0xB587B1BDD3B77B12, 0xAF4592A0EC76C84B];
    let s = [0xE0A6868A2F10EDB6, 0x2737B5B90ED4A03C, 0xB883D32006B79953, 0x0CB4BD62EDD2D286];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x309B72BB737716B1, 0xFDAE0743F4539166, 0x00000000B2E1A1FB];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 20
    let hash = [0x5E5F7DECAFCCBDC8, 0x47CCA19EE828D661, 0x2FA06A8C2855C695, 0xC7367FFEDB65FE02];
    let r = [0xB0E231C5AEEEFB18, 0xB32EC2A445544FAB, 0x6B37F4AD9B507AD3, 0xB7FD2FA91DD0BA81];
    let s = [0x0529B7BAC9490742, 0x6B11B9397BAAF29D, 0x3C3DB9BDA9B39D6E, 0x244C004F8B78DC3A];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x9D365D067AA7AE91, 0x7E5550FF8AC7B2EF, 0x0000000095DDAFE1];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 21
    let hash = [0x762B51FECAD5577C, 0x3D0B67842B551599, 0xE71BB3F6015410F3, 0x898A015948F4E12F];
    let r = [0xD797A729C003598B, 0xCB689F1800F71384, 0xABC59666E34CD4AC, 0xA0D427856DB72164];
    let s = [0xC5D88D1F85656039, 0xAF198760E3AC5077, 0x3D75ED7182D81168, 0x514D41ECA750EBE0];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x735436798CBBDEF8, 0xF2E98CA109C45F28, 0x000000009D39CFA3];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 22
    let hash = [0xFE5E08E00531182E, 0x3D39831E5355E99B, 0x37D37430CCDDA08B, 0xADD47D80DECFC500];
    let r = [0x449846044F228D4A, 0xED091108CE03F7EF, 0x1B55FA4AEEEBFB3E, 0xF74A32E691A8E0EE];
    let s = [0x45A1570286D94E41, 0x829490B57A561C9F, 0xE4A83C5E80C4F316, 0x308AF50FEF22673A];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x269997D089E97C9F, 0x4DFF7E98E16EDD61, 0x000000004AB0C3D2];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 23
    let hash = [0xF88AC5ABADF83420, 0x9C475A28E687D943, 0xB0D3407969123C71, 0x8FC27577B5290A3A];
    let r = [0xDCA02AF69D8C29BD, 0xFA5446C2DBDD5E30, 0xD351B5DDE35C0EBE, 0x8B9D9E9C4201B9B2];
    let s = [0xE275D286E45917F6, 0x8E6D3265426F602B, 0x59EE64AAE40D4BA4, 0x047FB2BA1E4CC0A0];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xF3C2BE14B34EAB6E, 0x18D3F40AA994A5B7, 0x00000000D02C6AAB];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 24
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x256E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x8C587B098FB75DF4, 0x023EB901C3974733, 0x0000000034E325D8];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 25
    let hash = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x6AEA2F8CF8E54F7C, 0xD662E0B74E289D74, 0x000000002A558C4C];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 26
    let hash = [0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x6AEA2F8CF8E54F7C, 0xD662E0B74E289D74, 0x000000002A558C4C];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 27
    let hash = [0xBFD25E8CD0364140, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x04D247FFD38F62FF, 0x06FAC6976618820D, 0x00000000C41ABA9E];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 28
    let hash = [0xBFD25E8CD0364142, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x4DA1796FF9A06109, 0xDD8FAFA76406F6EE, 0x000000007A343F50];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 29
    let hash = [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x4DA1796FF9A06109, 0xDD8FAFA76406F6EE, 0x000000007A343F50];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 30
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x20AE9D3D59817232, 0x958303E36309B9EE, 0x00000000E077FD3C];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 31
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 26;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 32
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 29;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 33
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 34
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 35
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0xBFD25E8CD0364142, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 36
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0xBFD25E8CD0364140, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let s = [0x0C368AE950852ADA, 0x1E56992D0774DC34, 0x0BD448298CC2E207, 0x4F8AE3BD7535248D];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 37
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 38
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0xDFE92F46681B20A1, 0x5D576E7357A4501D, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [0x0A97E6FE3AE3B7A3, 0xDD8BEE8A02BC79B3, 0x000000004EF445CA];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 39
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0xDFE92F46681B20A0, 0x5D576E7357A4501D, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xB28134D87E9A618D, 0x401660DFA96ECD7E, 0x00000000B29F65AA];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 40
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0xDFE92F46681B20A2, 0x5D576E7357A4501D, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [0xD9C780BE3BD54564, 0xFE3455F29E0F5553, 0x00000000FE706AA7];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 41
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0xBFD25E8CD0364140, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [0xA8D995345432A60E, 0xAB85A761042265B9, 0x00000000C846E2E4];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 42
    let hash = [0x4C860FC0B0C64EF3, 0x4049A3BA34C2289B, 0x1AF7A3E85A3212FA, 0x456E9AEA5E197A1F];
    let r = [0x2664AC8038825608, 0x8EB630EA16AA137D, 0xC25603C231BC2F56, 0x9242685BF161793C];
    let s = [0xBFD25E8CD0364142, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 43
    let hash = [0x7194CBF7EBC1EEBE, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC];
    let s = [0x450C889D597A16C4, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xE061C500626B39A3, 0x26549658F425FAD7, 0x000000003C8B5F24];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 44
    let hash = [0x7194CBF7EBC1EEBE, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC];
    let s = [0x450C889D597A16C4, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x96D1A45603F3919E, 0x233C19B0A9B2EB8C, 0x00000000687526AD];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 45
    let hash = [0x7194CBF7EBC1EEC0, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0xABAC09B95C709EE5, 0x5C778E4B8CEF3CA7, 0x3045406E95C07CD8, 0xC6047F9441ED7D6D];
    let s = [0x450C889D597A16C8, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x04C993CCA3A1891D, 0xBD4A0EFB63F36B5A, 0x0000000089FEA198];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 46
    let hash = [0x7194CBF7EBC1EEC0, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0xABAC09B95C709EE5, 0x5C778E4B8CEF3CA7, 0x3045406E95C07CD8, 0xC6047F9441ED7D6D];
    let s = [0x450C889D597A16C8, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 28;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xE3D6FBEC4D281432, 0x8DA092201765F852, 0x00000000C613182E];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 47
    let hash = [0x7194CBF7EBC1EEC1, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0xABAC09B95C709EE5, 0x5C778E4B8CEF3CA7, 0x3045406E95C07CD8, 0xC6047F9441ED7D6D];
    let s = [0x450C889D597A16C8, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x825A74013EEAA17E, 0xFA310FDCA361EE65, 0x000000001772BF1C];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 48
    let hash = [0x7194CBF7EBC1EEBE, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0x0000000000001798, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let s = [0x450C889D597A16C4, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0x7998BA5787A2D5CB, 0x3AAEDC97B2A8A943, 0x000000009446D37B];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 49
    let hash = [0x7194CBF7EBC1EEBE, 0xCCB41CEE02D9D441, 0x77188E4FBD022F35, 0x3CC4CB050478C498];
    let r = [0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x001E667EF9DCBBAC];
    let s = [0x450C889D597A16C4, 0xBA2E787583036325, 0xA77344D5943E0228, 0x2BCF13B5E4F34A04];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, false);
    let addr_expected = [0xA01A2BD09FD7B4B1, 0x74AB8DE6F7731475, 0x000000004C905636];
    assert_eq!(error_code, 0);
    assert_eq!(addr, addr_expected);

    // Test 50
    let hash = [0xBFD25E8CD0364142, 0xBAAEDCE6AF48A03B, 0x000000000000003E, 0x0000000000000000];
    let r = [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];
    let s = [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFBF, 0xFFFFFFFFFFFFFFFF];
    let v = 27;
    let (addr, error_code) = ecrecover(&hash, v, &r, &s, true);
    let addr_expected = [0xD1923D6AD4CB8EE0, 0x26CEDAEE2262B28B, 0x0000000007E38C83];
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
fn ecrecover(hash: &[u64; 4], v: u8, r: &[u64; 4], s: &[u64; 4], mode: bool) -> ([u64; 3], u8) {
    // Check r is in the range [1, n-1]
    if r == &[0, 0, 0, 0] {
        #[cfg(debug_assertions)]
        println!("r should be greater than 0");

        return ([064; 3], 1);
    } else if r >= &N_MINUS_ONE {
        #[cfg(debug_assertions)]
        println!("r should be less than N_MINUS_ONE: {:?}, but got {:?}", N_MINUS_ONE, r);

        return ([064; 3], 2);
    }

    // Check s is either in the range [1, n-1] or [1, (n-1)/2]
    let s_limit = if mode { N_MINUS_ONE } else { N_HALF };
    if s == &[0, 0, 0, 0] {
        #[cfg(debug_assertions)]
        println!("s should be greater than 0");

        return ([064; 3], 3);
    } else if s >= &s_limit {
        #[cfg(debug_assertions)]
        println!("s should be less than s_limit: {:?}, but got {:?}", s_limit, s);

        return ([064; 3], 4);
    }

    // Check v is either 27 or 28
    if v != 27 && v != 28 {
        #[cfg(debug_assertions)]
        println!("v should be either 27 or 28, but got {}", v);

        return ([064; 3], 5);
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
    let x_sq = params.d.clone();
    params.a = &x_sq;
    params.b = &x;
    params.c = &[7, 0, 0, 0];
    syscall_arith256_mod(&mut params);
    let y_sq = params.d.clone();

    // let y = match sqrt(y_sq, parity) {
    //     Some(y) => y,
    //     None => {
    //         #[cfg(debug_assertions)]
    //         println!("No square root found for y_sq: {:?}", y_sq);

    //         return ([064; 3], 6);
    //     }
    // };
    let y = [0x63b82f6f04ef2777,0x02e84bb7597aabe6,0xa25b0403f1eef757,0xb7c52588d95c3b9a];

    // Check the parity of the y-coordinate is correct
    let y_parity = (y[0] & 1) as u8;
    if parity != y_parity {
        #[cfg(debug_assertions)]
        println!("Invalid parity: expected {}, but got {}", parity, y_parity);

        return ([064; 3], 7);
    }

    // Calculate the public key
    // let r_inv = inv_n(r);
    let r_inv = [0xc0b8d7a6dec520fe, 0xc115d26ccbe1f572, 0x0a95e8b9fd31f60a, 0x1dd887b3eaf15326];

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
        return ([064; 3], 8);
    }

    // Compute the hash of the public key
    // Q: Is it better to use a hash API that accepts u64 instead of u8?
    // Q: Substitute the function by low-level stuff!
    let mut buf = [0u8; 64];
    for i in 0..4 {
        buf[i * 8..(i + 1) * 8].copy_from_slice(&pk.x[3 - i].to_be_bytes());
        buf[32 + i * 8..32 + (i + 1) * 8].copy_from_slice(&pk.y[3 - i].to_be_bytes());
    }

    let mut pk_hash = [0u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(&buf);
    keccak.finalize(&mut pk_hash);

    // Return the least significant 20 bytes of the hash
    let mut addr = [0u64; 3];
    for i in 0..20 {
        addr[i / 8] |= (pk_hash[31 - i] as u64) << (8 * (i % 8));
    }
    (addr, 0)
}
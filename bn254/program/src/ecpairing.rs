use ziskos::ecpairing;

use crate::constants::P;

pub fn ecpairing_valid_tests() {
    // 0 inputs should return 1
    let g1_points = [];
    let g2_points = [];
    let (res, error_code) = ecpairing(&g1_points, &g2_points);
    let res_exp = true;
    assert_eq!(error_code, 0);
    assert_eq!(res, res_exp);

    ///////////////////////
    // Tests with one point
    ///////////////////////
    // Degenerate tests: e(0,Q) = 1 or e(P,0) = 1 therefore the pairing equation is trivally satisfied
    // and in fact this is the only possibility for the pairing equation to be satisfied with one pair of P,Q
    let g1_points = [[0; 8]];
    let g2_points = [[
        0x46DEBD5CD992F6ED,
        0x674322D4F75EDADD,
        0x426A00665E5C4479,
        0x1800DEEF121F1E76,
        0x97E485B7AEF312C2,
        0xF1AA493335A9E712,
        0x7260BFB731FB5D25,
        0x198E9393920D483A,
        0x4CE6CC0166FA7DAA,
        0xE3D1E7690C43D37B,
        0x4AAB71808DCB408F,
        0x12C85EA5DB8C6DEB,
        0x55ACDADCD122975B,
        0xBC4B313370B38EF3,
        0xEC9E99AD690C3395,
        0x090689D0585FF075,
    ]];
    let (res, error_code) = ecpairing(&g1_points, &g2_points);
    let res_exp = true;
    assert_eq!(error_code, 0);
    assert_eq!(res, res_exp);

    let g1_points = [[
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000002,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ]];
    let g2_points = [[0; 16]];
    let (res, error_code) = ecpairing(&g1_points, &g2_points);
    let res_exp = true;
    assert_eq!(error_code, 0);
    assert_eq!(res, res_exp);

    /////////////////////////
    // Tests with two points
    /////////////////////////
    let g1_points = [
        [
            0x86B21FB1B76E18DA,
            0x5BC9EEB6A3D147C1,
            0x86308B7AF7AF02AC,
            0x2CF44499D5D27BB1,
            0xFE16D3242DC715F6,
            0x0B0C868DF0E7BDE1,
            0xE69108924926E45F,
            0x2C0F001F52110CCF,
        ],
        [
            0x0000000000000001,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x3C208C16D87CFD45,
            0x97816A916871CA8D,
            0xB85045B68181585D,
            0x30644E72E131A029,
        ],
    ];
    let g2_points = [
        [
            0x79D9159ECA2D98D9,
            0x4FFE2F2F3504DE8A,
            0x914E03E21DF544C3,
            0x22606845FF186793,
            0xAEF31E3CFAFF3EBC,
            0x61CD63919354BC06,
            0x4E2A32234DA8212F,
            0x1FB19BB476F6B9E4,
            0x950BB16041A0A85E,
            0x91E66F59BE6BD763,
            0xF0FF1743CBAC6BA2,
            0x2FE02E47887507AD,
            0xD3AB3698D63E4F90,
            0x48EEA9ABFDD85D7E,
            0xCB5FA81FC26CF3F0,
            0x2BD368E28381E8EC,
        ],
        [
            0xF5ABFEF9AB163BC7,
            0xD6C104E9E9EFF40B,
            0x5733CBDDDFED0FD8,
            0x091058A314182298,
            0xAAD45F40EC133EB4,
            0xEDE09CC4328F5A62,
            0x3CAAF13CBF443C1A,
            0x1971FF0471B09FA9,
            0x54DE6C7E0AFDC1FC,
            0x422EBC0E834613F9,
            0xB548A4487DA97B02,
            0x23A8EB0B0996252C,
            0x8FC02C2E907BAEA2,
            0x0AF8C212D9DC9ACD,
            0x96C1F4E453A370EB,
            0x2A23AF9A5CE2BA27,
        ],
    ];
    let (res, error_code) = ecpairing(&g1_points, &g2_points);
    let res_exp = true;
    assert_eq!(error_code, 0);
    assert_eq!(res, res_exp);

    let g1_points = [
        [
            0x22C1B60D9C3D371C,
            0x5C0D55457F73D737,
            0x4044ED5B178CBD9A,
            0x2D8754F7DF66EE87,
            0xBD98871C9E20EA26,
            0xB66B1EBBBD5C0512,
            0x453B49CFF4E22FE7,
            0x2E561BBCC48488B4,
        ],
        [
            0x93892192F3EC4AFF,
            0xC67953AF7C6C5013,
            0x34B7573EA322A6D4,
            0x07CC2683202C9AF0,
            0x8C035746CC29FC35,
            0x932859AE31CEAB7A,
            0xC2A4028CFA6C9771,
            0x04AF793591654C06,
        ],
    ];
    let g2_points = [
        [
            0xAD1E71427745F2AB,
            0xD775349E758FE469,
            0x4106013A9528A980,
            0x08DE4D1AB2AB3AF7,
            0x5EBF7D640B0DB6B9,
            0x26141B88D1004B8E,
            0x412D4BD787A4145B,
            0x2A09D8EDD776DE0B,
            0x01A8C63433F243DD,
            0xDB58F6F3CE71FC3F,
            0x65BDAFF0DB3E2BC9,
            0x28D6A2C0F79312C5,
            0xAB68710F94A8C557,
            0x42BA8E41589EBA82,
            0x6195B8D98984954C,
            0x0C250D0082ED5192,
        ],
        [
            0x46DEBD5CD992F6ED,
            0x674322D4F75EDADD,
            0x426A00665E5C4479,
            0x1800DEEF121F1E76,
            0x97E485B7AEF312C2,
            0xF1AA493335A9E712,
            0x7260BFB731FB5D25,
            0x198E9393920D483A,
            0x4CE6CC0166FA7DAA,
            0xE3D1E7690C43D37B,
            0x4AAB71808DCB408F,
            0x12C85EA5DB8C6DEB,
            0x55ACDADCD122975B,
            0xBC4B313370B38EF3,
            0xEC9E99AD690C3395,
            0x090689D0585FF075,
        ],
    ];
    let (res, error_code) = ecpairing(&g1_points, &g2_points);
    let res_exp = true;
    assert_eq!(error_code, 0);
    assert_eq!(res, res_exp);

    /////////////////////////
    // Tests with three points
    /////////////////////////
    let g1_points = [
        [
            0x98E1EE7AE320C3C3,
            0xD79FD15C58C73002,
            0x191FF3ADA02D3897,
            0x111856DB77486AAC,
            0xAECB64238D7FB4D3,
            0xC4D6EA4FBE8A7D80,
            0x08FA89E27086D0CC,
            0x130E628AAECE426D,
        ],
        [
            0xBFD4D9E5FBCCB874,
            0x188E566ACBC386FE,
            0x31612C872EFF08C2,
            0x01513623DC50D3DB,
            0xAC31EDC7BF340833,
            0x9200B686EECD0CBE,
            0x8F751B2A7CD31288,
            0x22AB71A6BD4168E8,
        ],
        [
            0x0000000000000001,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000002,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ],
    ];
    let g2_points = [
        [
            0xC50E803B2905D2B5,
            0xCC6C5869DD5556EB,
            0x4CA5A6A011224B1F,
            0x09E7FAA4D0A6418E,
            0x9F53EA4AB0FE3850,
            0xDAEA7CE73B73C225,
            0x7DDAA1FCCF2F9D30,
            0x1124A4DAA825B6B9,
            0x3766C9B06BFD4808,
            0x938B7D071F6648AE,
            0x91E1EC731DDAABE4,
            0x24D96462424C33D3,
            0xF1FD9B21ACDA77F6,
            0x02486C6B89FEC3C4,
            0x859B983483EAB957,
            0x000A9BE583901982,
        ],
        [
            0x46DEBD5CD992F6ED,
            0x674322D4F75EDADD,
            0x426A00665E5C4479,
            0x1800DEEF121F1E76,
            0x97E485B7AEF312C2,
            0xF1AA493335A9E712,
            0x7260BFB731FB5D25,
            0x198E9393920D483A,
            0x4CE6CC0166FA7DAA,
            0xE3D1E7690C43D37B,
            0x4AAB71808DCB408F,
            0x12C85EA5DB8C6DEB,
            0x55ACDADCD122975B,
            0xBC4B313370B38EF3,
            0xEC9E99AD690C3395,
            0x090689D0585FF075,
        ],
        [0; 16],
    ];
    let (res, error_code) = ecpairing(&g1_points, &g2_points);
    let res_exp = true;
    assert_eq!(error_code, 0);
    assert_eq!(res, res_exp);

    let g1_points = [
        [
            0xF238A8582D280E02,
            0xC2139A6E3CDA76A6,
            0x06B6C625361E638A,
            0x2D1EDF584564CBD4,
            0xA862A59EA692D328,
            0xCD4CE89A15C726DF,
            0x156232A7CE8C5A20,
            0x240C90E53A4C11CD,
        ],
        [
            0x5E2E4A3812D3B419,
            0x8EFB46BEE52C0936,
            0x0D6EA82259BF287E,
            0x0D692D095AD2C105,
            0x031D289DF0EC6C7E,
            0x3F9DBE0B867CFF10,
            0xE778802C56A002CC,
            0x0404989D8528292C,
        ],
        [
            0xBB836557B95B42A8,
            0xCEDE593A6C242A85,
            0x8B4A501506A8802C,
            0x0B660528352CAD5F,
            0x9F8F51482FCE336A,
            0xA34CDBA30C612D41,
            0x1379742525BE69F8,
            0x278299A8FF8C7E61,
        ],
    ];
    let g2_points = [
        [
            0xAEFCE49F99080BCC,
            0x44C80D121EF22062,
            0x11C31232A264FFB9,
            0x105D7CD95025BF27,
            0xE07640D35AE95CEA,
            0x4A3B691B9DE15F60,
            0x8D66A553AC96D91D,
            0x2AD0EF9EF58E7F0C,
            0xFAD21EA1E43960DF,
            0x540BD2BD377FE74C,
            0xEB46FCDAB2986694,
            0x1732E421B677DF24,
            0x4DC44588F9C3DB76,
            0x0CB9017B5B9D2B89,
            0x2FB907D8FB040EAD,
            0x1D41A6F360F038BC,
        ],
        [
            0xAEFCE49F99080BCC,
            0x44C80D121EF22062,
            0x11C31232A264FFB9,
            0x105D7CD95025BF27,
            0xE07640D35AE95CEA,
            0x4A3B691B9DE15F60,
            0x8D66A553AC96D91D,
            0x2AD0EF9EF58E7F0C,
            0xFAD21EA1E43960DF,
            0x540BD2BD377FE74C,
            0xEB46FCDAB2986694,
            0x1732E421B677DF24,
            0x4DC44588F9C3DB76,
            0x0CB9017B5B9D2B89,
            0x2FB907D8FB040EAD,
            0x1D41A6F360F038BC,
        ],
        [
            0x46DEBD5CD992F6ED,
            0x674322D4F75EDADD,
            0x426A00665E5C4479,
            0x1800DEEF121F1E76,
            0x97E485B7AEF312C2,
            0xF1AA493335A9E712,
            0x7260BFB731FB5D25,
            0x198E9393920D483A,
            0x4CE6CC0166FA7DAA,
            0xE3D1E7690C43D37B,
            0x4AAB71808DCB408F,
            0x12C85EA5DB8C6DEB,
            0x55ACDADCD122975B,
            0xBC4B313370B38EF3,
            0xEC9E99AD690C3395,
            0x090689D0585FF075,
        ],
    ];
    let (res, error_code) = ecpairing(&g1_points, &g2_points);
    let res_exp = true;
    assert_eq!(error_code, 0);
    assert_eq!(res, res_exp);

    /////////////////////////
    // Tests with four points
    /////////////////////////
    let g1_points = [
        [
            0x25AE0A5FEBBA8F99,
            0x4B3BA8640505B88E,
            0xC6DF02D0ABF21170,
            0x028CE4D966BE4FBB,
            0x50EB63F054990EF9,
            0x0AAD77D8F6C038B7,
            0x8C380C1768C9350F,
            0x104B8050045227FF,
        ],
        [
            0xD72903D08C80ADFD,
            0xE3F972AE9604A23C,
            0x74AECAE4D77BD7FE,
            0x12F64ACE183D47E8,
            0x49E3FC8AFCA6F1DA,
            0x48BE27577D2CE336,
            0x9CAE580F4A2CE69D,
            0x2E6D1232CED638A5,
        ],
        [
            0xD1D19C3E86E04D51,
            0xB9ECD61D16E078AC,
            0xD889D58528A4C40B,
            0x290689E143233493,
            0x4D3B31525E254301,
            0xD09D11C059B40EF2,
            0xC11F2E1304B2C432,
            0x27130E0ABE121F5F,
        ],
        [
            0x9D30EDB9A1A497E4,
            0x2B6C29D7B71EDD54,
            0xB1736580933B339D,
            0x2D05ACB642143D9F,
            0x1433732717560205,
            0x6E61D4E538EA5F04,
            0x764005D3C322969B,
            0x0D5CE48C6D3B20C7,
        ],
    ];
    let g2_points = [
        [
            0x16DBECB2A5E3BB78,
            0xF71BC618DA762D71,
            0x026FB3B37EDB47A1,
            0x2BA37CABA48F3BA2,
            0xCCC56AF711C1A9B4,
            0x080DBF3676C68A76,
            0xD7FDE4E6139BBD1F,
            0x14BAA8D83B22434C,
            0xBF4633EFD6428E04,
            0x258229F26F59BA52,
            0x641A31FF5F76FE8C,
            0x16BA40B8AC8A1345,
            0xB6BFDD34A3A4CE25,
            0xC2F25BB39BC3E584,
            0x0ED0660C7BFD671D,
            0x00A162C00BC667E7,
        ],
        [
            0x16DBECB2A5E3BB78,
            0xF71BC618DA762D71,
            0x026FB3B37EDB47A1,
            0x2BA37CABA48F3BA2,
            0xCCC56AF711C1A9B4,
            0x080DBF3676C68A76,
            0xD7FDE4E6139BBD1F,
            0x14BAA8D83B22434C,
            0xBF4633EFD6428E04,
            0x258229F26F59BA52,
            0x641A31FF5F76FE8C,
            0x16BA40B8AC8A1345,
            0xB6BFDD34A3A4CE25,
            0xC2F25BB39BC3E584,
            0x0ED0660C7BFD671D,
            0x00A162C00BC667E7,
        ],
        [
            0x46DEBD5CD992F6ED,
            0x674322D4F75EDADD,
            0x426A00665E5C4479,
            0x1800DEEF121F1E76,
            0x97E485B7AEF312C2,
            0xF1AA493335A9E712,
            0x7260BFB731FB5D25,
            0x198E9393920D483A,
            0x4CE6CC0166FA7DAA,
            0xE3D1E7690C43D37B,
            0x4AAB71808DCB408F,
            0x12C85EA5DB8C6DEB,
            0x55ACDADCD122975B,
            0xBC4B313370B38EF3,
            0xEC9E99AD690C3395,
            0x090689D0585FF075,
        ],
        [
            0x46DEBD5CD992F6ED,
            0x674322D4F75EDADD,
            0x426A00665E5C4479,
            0x1800DEEF121F1E76,
            0x97E485B7AEF312C2,
            0xF1AA493335A9E712,
            0x7260BFB731FB5D25,
            0x198E9393920D483A,
            0x4CE6CC0166FA7DAA,
            0xE3D1E7690C43D37B,
            0x4AAB71808DCB408F,
            0x12C85EA5DB8C6DEB,
            0x55ACDADCD122975B,
            0xBC4B313370B38EF3,
            0xEC9E99AD690C3395,
            0x090689D0585FF075,
        ],
    ];
    let (res, error_code) = ecpairing(&g1_points, &g2_points);
    let res_exp = true;
    assert_eq!(error_code, 0);
    assert_eq!(res, res_exp);
}

pub fn ecpairing_invalid_tests() {
    // Fails if a g1 point is invalid in some coordinate
    let g1_points = [[P[0], P[1], P[2], P[3], 0, 0, 0, 0]];
    let g2_points = [[0; 16]];
    let (_, error_code) = ecpairing(&g1_points, &g2_points);
    assert_eq!(error_code, 1);

    let g1_points = [[0, 0, 0, 0, P[0], P[1], P[2], P[3]]];
    let g2_points = [[0; 16]];
    let (_, error_code) = ecpairing(&g1_points, &g2_points);
    assert_eq!(error_code, 1);

    // Fails if a g2 point is invalid in some coordinate
    let g1_points = [[0; 8]];
    let g2_points = [[P[0], P[1], P[2], P[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]];
    let (_, error_code) = ecpairing(&g1_points, &g2_points);
    assert_eq!(error_code, 1);

    let g1_points = [[0; 8]];
    let g2_points = [[0, 0, 0, 0, P[0], P[1], P[2], P[3], 0, 0, 0, 0, 0, 0, 0, 0]];
    let (_, error_code) = ecpairing(&g1_points, &g2_points);
    assert_eq!(error_code, 1);

    let g1_points = [[0; 8]];
    let g2_points = [[0, 0, 0, 0, 0, 0, 0, 0, P[0], P[1], P[2], P[3], 0, 0, 0, 0]];
    let (_, error_code) = ecpairing(&g1_points, &g2_points);
    assert_eq!(error_code, 1);

    let g1_points = [[0; 8]];
    let g2_points = [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, P[0], P[1], P[2], P[3]]];
    let (_, error_code) = ecpairing(&g1_points, &g2_points);
    assert_eq!(error_code, 1);

    // Fails if a g1 point is not on the curve
    let g1_points = [[
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ]];
    let g2_points = [[0; 16]];
    let (_, error_code) = ecpairing(&g1_points, &g2_points);
    assert_eq!(error_code, 1);

    // Fails if a g2 point is not on the curve
    let g1_points = [[0; 8]];
    let g2_points = [[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]];
    let (_, error_code) = ecpairing(&g1_points, &g2_points);
    assert_eq!(error_code, 1);

    // Fails if a g2 point is not on the subgroup
    let g1_points = [[0; 8]];
    let g2_points = [[
        0xE642D1780FA77460,
        0x940C7100CC3B163F,
        0x9E35DB46F7250AFC,
        0x1ED91A62C98A6383,
        0x9E87C23424EE0063,
        0x12859810070565E9,
        0x03CE49ABC798B83F,
        0x181BAE8231C1F263,
        0x6B283DE32DD4D366,
        0xFE4EED8EF8036477,
        0x49D7F9C268537017,
        0x1B2D40EFDB1326CC,
        0xE0A118CFA3E0D8D7,
        0x9A3C9ECF0C83F1D7,
        0x28D70CD532462E40,
        0x07D105D0066EC703,
    ]];
    let (_, error_code) = ecpairing(&g1_points, &g2_points);
    assert_eq!(error_code, 1);
}

use crypto::CustomEvmCrypto;
use revm::precompile::Crypto;

/// Helper to convert a decimal string to 32-byte big-endian array
fn decimal_to_32(dec: &str) -> [u8; 32] {
    let n = dec.parse::<num_bigint::BigUint>().expect("valid decimal");
    let bytes = n.to_bytes_be();
    let mut arr = [0u8; 32];
    let start = 32 - bytes.len();
    arr[start..].copy_from_slice(&bytes);
    arr
}

/// Helper to build a G1 point (64 bytes) from x and y coordinates (decimal strings)
fn build_g1_point(x: &str, y: &str) -> [u8; 64] {
    let mut point = [0u8; 64];
    point[..32].copy_from_slice(&decimal_to_32(x));
    point[32..].copy_from_slice(&decimal_to_32(y));
    point
}

// Helper to build a G2 point (128 bytes) from x1, x2, y1, y2 coordinates (decimal strings)
// G2 point format: x1 (32 bytes) || x2 (32 bytes) || y1 (32 bytes) || y2 (32 bytes)
fn build_g2_point(x1: &str, x2: &str, y1: &str, y2: &str) -> [u8; 128] {
    let mut point = [0u8; 128];
    point[..32].copy_from_slice(&decimal_to_32(x1));
    point[32..64].copy_from_slice(&decimal_to_32(x2));
    point[64..96].copy_from_slice(&decimal_to_32(y1));
    point[96..].copy_from_slice(&decimal_to_32(y2));
    point
}

/// Helper to check if result is the point at infinity (all zeros)
fn is_infinity(result: &[u8; 64]) -> bool {
    result.iter().all(|&b| b == 0)
}

pub fn bn254_tests(crypto: &CustomEvmCrypto) {
    g1_add_tests(crypto);
    g1_mul_tests(crypto);
    pairing_check_tests(crypto);
}

fn g1_add_tests(crypto: &CustomEvmCrypto) {
    // 1] 0 + 0 = 0 (infinity + infinity = infinity)
    let p1 = build_g1_point("0", "0");
    let p2 = build_g1_point("0", "0");
    let result = crypto.bn254_g1_add(&p1, &p2).expect("Test 1 should succeed");
    assert!(is_infinity(&result), "Test 1: 0 + 0 should be 0");

    // 2] 0 + P = P (infinity + P = P)
    let p1 = build_g1_point("0", "0");
    let p2 = build_g1_point("1", "2"); // Generator point G
    let result = crypto.bn254_g1_add(&p1, &p2).expect("Test 2 should succeed");
    let expected = build_g1_point("1", "2");
    assert_eq!(result, expected, "Test 2: 0 + P should be P");

    // 3] P + 0 = P (P + infinity = P)
    let p1 = build_g1_point("1", "2"); // Generator point G
    let p2 = build_g1_point("0", "0");
    let result = crypto.bn254_g1_add(&p1, &p2).expect("Test 3 should succeed");
    let expected = build_g1_point("1", "2");
    assert_eq!(result, expected, "Test 3: P + 0 should be P");

    // 4a] P1.x not in range (x >= P) - should fail
    let p1 = build_g1_point(
        "21888242871839275222246405745257275088696311157297823662689037894645226208584",
        "2",
    );
    let p2 = build_g1_point("3", "3");
    let result = crypto.bn254_g1_add(&p1, &p2);
    assert!(result.is_err(), "Test 4a: P1.x out of range should fail");

    // 4b] P1.y not in range (y >= P) - should fail
    let p1 = build_g1_point(
        "1",
        "21888242871839275222246405745257275088696311157297823662689037894645226208585",
    );
    let p2 = build_g1_point("3", "3");
    let result = crypto.bn254_g1_add(&p1, &p2);
    assert!(result.is_err(), "Test 4b: P1.y out of range should fail");

    // 5a] P2.x not in range (x >= P) - should fail
    let p1 = build_g1_point("1", "2");
    let p2 = build_g1_point(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        "0",
    );
    let result = crypto.bn254_g1_add(&p1, &p2);
    assert!(result.is_err(), "Test 5a: P2.x out of range should fail");

    // 5b] P2.y not in range (y >= P) - should fail
    let p1 = build_g1_point("1", "2");
    let p2 = build_g1_point(
        "0",
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    );
    let result = crypto.bn254_g1_add(&p1, &p2);
    assert!(result.is_err(), "Test 5b: P2.y out of range should fail");

    // 6a] P1 not on curve (1, 0) - should fail
    let p1 = build_g1_point("1", "0");
    let p2 = build_g1_point("0", "0");
    let result = crypto.bn254_g1_add(&p1, &p2);
    assert!(result.is_err(), "Test 6a: P1 not on curve should fail");

    // 6b] P1 not on curve with valid P2 - should fail
    let p1 = build_g1_point("1", "0");
    let p2 = build_g1_point("1", "2");
    let result = crypto.bn254_g1_add(&p1, &p2);
    assert!(result.is_err(), "Test 6b: P1 not on curve should fail");

    // 7a] P2 not on curve (1, 0) with infinity P1 - should fail
    let p1 = build_g1_point("0", "0");
    let p2 = build_g1_point("1", "0");
    let result = crypto.bn254_g1_add(&p1, &p2);
    assert!(result.is_err(), "Test 7a: P2 not on curve should fail");

    // 7b] P2 not on curve with valid P1 - should fail
    let p1 = build_g1_point("1", "2");
    let p2 = build_g1_point("1", "0");
    let result = crypto.bn254_g1_add(&p1, &p2);
    assert!(result.is_err(), "Test 7b: P2 not on curve should fail");

    // 8] P + (-P) = 0 (point + negation = infinity)
    let p1 = build_g1_point(
        "10744596414106452074759370245733544594153395043370666422502510773307029471145",
        "848677436511517736191562425154572367705380862894644942948681172815252343932",
    );
    let p2 = build_g1_point(
        "10744596414106452074759370245733544594153395043370666422502510773307029471145",
        "21039565435327757486054843320102702720990930294403178719740356721829973864651",
    );
    let result = crypto.bn254_g1_add(&p1, &p2).expect("Test 8 should succeed");
    assert!(is_infinity(&result), "Test 8: P + (-P) should be 0");

    // 9a] P + Q when P != Q (regular addition)
    let p1 = build_g1_point(
        "2893332206675025542079383054128180540025417352513932043566889211329192179032",
        "6530629491743359417280396166892081514007566149119717903717756741482263401518",
    );
    let p2 = build_g1_point(
        "15490799329273967747501973647822742581714860109251269127154113506193693607878",
        "4229358293223510599397432508631487048670295788986070026939193461742686527076",
    );
    let result = crypto.bn254_g1_add(&p1, &p2).expect("Test 9a should succeed");
    let expected = build_g1_point(
        "13154776318592227270778558029295227935378730842313609923118896637591559850250",
        "11035980320923476543935377623718958678920911311849399323950347759358969041431",
    );
    assert_eq!(result, expected, "Test 9a: P + Q failed");

    // 9b] Another P + Q test
    let p1 = build_g1_point(
        "1745860766704548035074878643814414425056208216948549237180537806484993001172",
        "10428992577810537311515619307712828512800028181521723820412159824785899508051",
    );
    let p2 = build_g1_point(
        "10744596414106452074759370245733544594153395043370666422502510773307029471145",
        "848677436511517736191562425154572367705380862894644942948681172815252343932",
    );
    let result = crypto.bn254_g1_add(&p1, &p2).expect("Test 9b should succeed");
    let expected = build_g1_point(
        "20109137777308224484751705964830245061785572657602899297228633767392913518415",
        "14499175368639637950478596677291617168262069295802020711454610174461584835979",
    );
    assert_eq!(result, expected, "Test 9b: P + Q failed");

    // 10a] P + P (point doubling)
    let p1 = build_g1_point(
        "2893332206675025542079383054128180540025417352513932043566889211329192179032",
        "6530629491743359417280396166892081514007566149119717903717756741482263401518",
    );
    let p2 = build_g1_point(
        "2893332206675025542079383054128180540025417352513932043566889211329192179032",
        "6530629491743359417280396166892081514007566149119717903717756741482263401518",
    );
    let result = crypto.bn254_g1_add(&p1, &p2).expect("Test 10a should succeed");
    let expected = build_g1_point(
        "11220622501868821308995844886766009822833441579384302982823096531245924405698",
        "2355690023525969090855462437460037724073976772193253577110863269987724684477",
    );
    assert_eq!(result, expected, "Test 10a: P + P (doubling) failed");

    // 10b] Another doubling test
    let p1 = build_g1_point(
        "15490799329273967747501973647822742581714860109251269127154113506193693607878",
        "4229358293223510599397432508631487048670295788986070026939193461742686527076",
    );
    let p2 = build_g1_point(
        "15490799329273967747501973647822742581714860109251269127154113506193693607878",
        "4229358293223510599397432508631487048670295788986070026939193461742686527076",
    );
    let result = crypto.bn254_g1_add(&p1, &p2).expect("Test 10b should succeed");
    let expected = build_g1_point(
        "14301632400969957113316344359548233118734763289927867040319376723985850943059",
        "19259402839901377893267670172732143592044261932601111690978918426524987173751",
    );
    assert_eq!(result, expected, "Test 10b: P + P (doubling) failed");

    // 10c] Another doubling test
    let p1 = build_g1_point(
        "1745860766704548035074878643814414425056208216948549237180537806484993001172",
        "10428992577810537311515619307712828512800028181521723820412159824785899508051",
    );
    let p2 = build_g1_point(
        "1745860766704548035074878643814414425056208216948549237180537806484993001172",
        "10428992577810537311515619307712828512800028181521723820412159824785899508051",
    );
    let result = crypto.bn254_g1_add(&p1, &p2).expect("Test 10c should succeed");
    let expected = build_g1_point(
        "7635241416710394435863784018619353890364763495262225661273147225960091861733",
        "21716464559528323959695889215160185865818678200951896286120725092340748527691",
    );
    assert_eq!(result, expected, "Test 10c: P + P (doubling) failed");

    // 10d] Another doubling test
    let p1 = build_g1_point(
        "10744596414106452074759370245733544594153395043370666422502510773307029471145",
        "848677436511517736191562425154572367705380862894644942948681172815252343932",
    );
    let p2 = build_g1_point(
        "10744596414106452074759370245733544594153395043370666422502510773307029471145",
        "848677436511517736191562425154572367705380862894644942948681172815252343932",
    );
    let result = crypto.bn254_g1_add(&p1, &p2).expect("Test 10d should succeed");
    let expected = build_g1_point(
        "4444740815889402603535294170722302758225367627362056425101568584910268024244",
        "10537263096529483164618820017164668921386457028564663708352735080900270541420",
    );
    assert_eq!(result, expected, "Test 10d: P + P (doubling) failed");

    println!("All BN254 G1 Add tests passed!");
}

fn g1_mul_tests(crypto: &CustomEvmCrypto) {
    // 1] 0·O = O (zero scalar times infinity = infinity)
    let point = build_g1_point("0", "0");
    let scalar = decimal_to_32("0");
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 1 should succeed");
    assert!(is_infinity(&result), "Test 1: 0·O should be O");

    // 2] k·O = O (any scalar times infinity = infinity)
    let point = build_g1_point("0", "0");
    let scalar = decimal_to_32("5");
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 2 should succeed");
    assert!(is_infinity(&result), "Test 2: k·O should be O");

    // 3] 0·P = O (zero scalar times any point = infinity)
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32("0");
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 3 should succeed");
    assert!(is_infinity(&result), "Test 3: 0·P should be O");

    // 4a] P.x not in range (x >= P) - should fail
    let point = build_g1_point(
        "21888242871839275222246405745257275088696311157297823662689037894645226208584",
        "2",
    );
    let scalar = decimal_to_32("0");
    let result = crypto.bn254_g1_mul(&point, &scalar);
    assert!(result.is_err(), "Test 4a: P.x out of range should fail");

    // 4b] P.y not in range (y >= P) - should fail
    let point = build_g1_point(
        "1",
        "21888242871839275222246405745257275088696311157297823662689037894645226208585",
    );
    let scalar = decimal_to_32("0");
    let result = crypto.bn254_g1_mul(&point, &scalar);
    assert!(result.is_err(), "Test 4b: P.y out of range should fail");

    // 5a] P not on curve with k=0 - should fail
    let point = build_g1_point("1", "0");
    let scalar = decimal_to_32("0");
    let result = crypto.bn254_g1_mul(&point, &scalar);
    assert!(result.is_err(), "Test 5a: P not on curve should fail");

    // 5b] P not on curve with k=65 - should fail
    let point = build_g1_point("1", "0");
    let scalar = decimal_to_32("65");
    let result = crypto.bn254_g1_mul(&point, &scalar);
    assert!(result.is_err(), "Test 5b: P not on curve should fail");

    // 6a] 1·G = G
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32("1");
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6a should succeed");
    let expected = build_g1_point("1", "2");
    assert_eq!(result, expected, "Test 6a: 1·G should be G");

    // 6b] 2·G
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32("2");
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6b should succeed");
    let expected = build_g1_point(
        "1368015179489954701390400359078579693043519447331113978918064868415326638035",
        "9918110051302171585080402603319702774565515993150576347155970296011118125764",
    );
    assert_eq!(result, expected, "Test 6b: 2·G failed");

    // 6c] 65·G
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32("65");
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6c should succeed");
    let expected = build_g1_point(
        "21184532036463169063041779836861514142873086093180850953095098556309204188255",
        "16870949628445799017882714788639508275834535486794531840392367353784571921174",
    );
    assert_eq!(result, expected, "Test 6c: 65·G failed");

    // 6d] 10000000089·G
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32("10000000089");
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6d should succeed");
    let expected = build_g1_point(
        "4768044760451824005417871472283223457728569810854115125480649095031772328870",
        "21389337952468851259287213083493638952853622949895525580347877121675081015727",
    );
    assert_eq!(result, expected, "Test 6d: 10000000089·G failed");

    // 6e] 57·P (different base point)
    let point = build_g1_point(
        "1745860766704548035074878643814414425056208216948549237180537806484993001172",
        "10428992577810537311515619307712828512800028181521723820412159824785899508051",
    );
    let scalar = decimal_to_32("57");
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6e should succeed");
    let expected = build_g1_point(
        "21092868577100313210583214784627729175513062432513303686654820611840644382013",
        "10293123368529248350591404721829100625076077203595282162629899903703630633665",
    );
    assert_eq!(result, expected, "Test 6e: 57·P failed");

    // 6f] 123456789·P
    let point = build_g1_point(
        "1745860766704548035074878643814414425056208216948549237180537806484993001172",
        "10428992577810537311515619307712828512800028181521723820412159824785899508051",
    );
    let scalar = decimal_to_32("123456789");
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6f should succeed");
    let expected = build_g1_point(
        "9551410454255481932113938269904288675272239827491596157984458647610565008967",
        "17781856861347070862134441477208204792978952663354273425763774350233183876915",
    );
    assert_eq!(result, expected, "Test 6f: 123456789·P failed");

    // 6g] r·G = O (scalar equals group order)
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    );
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6g should succeed");
    assert!(is_infinity(&result), "Test 6g: r·G should be O");

    // 6h] (r+1)·G = G
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32(
        "21888242871839275222246405745257275088548364400416034343698204186575808495618",
    );
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6h should succeed");
    let expected = build_g1_point("1", "2");
    assert_eq!(result, expected, "Test 6h: (r+1)·G should be G");

    // 6i] P (field modulus) · G
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    );
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6i should succeed");
    let expected = build_g1_point(
        "7793429943220682609834519115512946233910458086191548249060013461061457526887",
        "16460968250425543446028981775631045522280113359306664586749259656855967130574",
    );
    assert_eq!(result, expected, "Test 6i: P·G failed");

    // 6j] (P+1) · G
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32(
        "21888242871839275222246405745257275088696311157297823662689037894645226208584",
    );
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6j should succeed");
    let expected = build_g1_point(
        "15886422571275617715400903250697722692198979607302343556925904858625057687404",
        "9788557113822741943783365060165103517008620829146475047263378292709661309554",
    );
    assert_eq!(result, expected, "Test 6j: (P+1)·G failed");

    // 6k] Large scalar (2^256 - 1) · G
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32(
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    );
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 6k should succeed");
    let expected = build_g1_point(
        "21415159568991615317144600033915305503576371596506956373206836402282692989778",
        "8573070896319864868535933562264623076420652926303237982078693068147657243287",
    );
    assert_eq!(result, expected, "Test 6k: (2^256-1)·G failed");

    // 7] Worst case scenario: scalar with highest Hamming weight < r (2^253 - 1)
    let point = build_g1_point("1", "2");
    let scalar = decimal_to_32(
        "14474011154664524427946373126085988481658748083205070504932198000989141204991",
    );
    let result = crypto.bn254_g1_mul(&point, &scalar).expect("Test 7 should succeed");
    let expected = build_g1_point(
        "3739418567393436576913511739065691570763034865122368432616000129799288055432",
        "18298856760603404171434473181920219106007178146585940397845192637485681860518",
    );
    assert_eq!(result, expected, "Test 7: worst case scalar multiplication failed");

    println!("All BN254 G1 Mul tests passed!");
}

fn pairing_check_tests(crypto: &CustomEvmCrypto) {
    // 1] 0 inputs should return true (empty pairing)
    let pairs: &[(&[u8], &[u8])] = &[];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 1 should succeed");
    assert!(result, "Test 1: empty pairing should return true");

    // 2] Tests with 1 pair
    // 2.1] Invalid inputs - G1 point not on curve (0, 1)
    let g1 = build_g1_point("0", "1");
    let g2 = build_g2_point(
        "2046729899889901964437012741252570163462327955511008570480857952505584629957",
        "4351401811647638138392695977895401859084096897123577305203754529537814663109",
        "14316075702276096164483565793667862351398527813470041574939773541551376891710",
        "322506915963699862059245473966830598387691259163658767351233132602858049743",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.1a: G1 (0,1) not on curve should fail");

    // 2.1b] Invalid G2 point (wrong y coordinate)
    let g1 = build_g1_point("0", "0");
    let g2 = build_g2_point(
        "2046729899889901964437012741252570163462327955511008570480857952505584629957",
        "4351401811647638138392695977895401859084096897123577305203754529537814663108", // wrong
        "14316075702276096164483565793667862351398527813470041574939773541551376891710",
        "322506915963699862059245473966830598387691259163658767351233132602858049743",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.1b: G2 not on curve should fail");

    // 2.1c] Invalid - G1 on curve but G2 not on curve
    let g1 = build_g1_point("1", "2");
    let g2 = build_g2_point(
        "2046729899889901964437012741252570163462327955511008570480857952505584629957",
        "4351401811647638138392695977895401859084096897123577305203754529537814663108", // wrong
        "14316075702276096164483565793667862351398527813470041574939773541551376891710",
        "322506915963699862059245473966830598387691259163658767351233132602858049743",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.1c: G2 not on curve should fail");

    // 2.1d] Invalid - G1 not on curve (1, 1)
    let g1 = build_g1_point("1", "1");
    let g2 = build_g2_point("0", "0", "0", "0");
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.1d: G1 (1,1) not on curve should fail");

    // 2.1e] Invalid - G2 not on curve (1, 2, 3, 3)
    let g1 = build_g1_point("0", "0");
    let g2 = build_g2_point("1", "2", "3", "3");
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.1e: G2 (1,2,3,3) not on curve should fail");

    // 2.2] Out of range tests - G1.x >= P
    let g1 = build_g1_point(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        "1",
    );
    let g2 = build_g2_point("0", "0", "0", "0");
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.2a: G1.x >= P should fail");

    // 2.2b] G1.y >= P
    let g1 = build_g1_point(
        "1",
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    );
    let g2 = build_g2_point("0", "0", "0", "0");
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.2b: G1.y >= P should fail");

    // 2.2c] G2.x1 >= P
    let g1 = build_g1_point("1", "2");
    let g2 = build_g2_point(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        "0",
        "0",
        "0",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.2c: G2.x1 >= P should fail");

    // 2.2d] G2.x2 >= P
    let g1 = build_g1_point("1", "2");
    let g2 = build_g2_point(
        "0",
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        "0",
        "0",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.2d: G2.x2 >= P should fail");

    // 2.2e] G2.y1 >= P
    let g1 = build_g1_point("1", "2");
    let g2 = build_g2_point(
        "0",
        "0",
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        "0",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.2e: G2.y1 >= P should fail");

    // 2.2f] G2.y2 >= P
    let g1 = build_g1_point("1", "2");
    let g2 = build_g2_point(
        "0",
        "0",
        "0",
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs);
    assert!(result.is_err(), "Test 2.2f: G2.y2 >= P should fail");

    // 2.3] Degenerate tests: e(0,Q) = 1 or e(P,0) = 1
    // e(0, Q) = 1
    let g1 = build_g1_point("0", "0");
    let g2 = build_g2_point(
        "2046729899889901964437012741252570163462327955511008570480857952505584629957",
        "4351401811647638138392695977895401859084096897123577305203754529537814663109",
        "14316075702276096164483565793667862351398527813470041574939773541551376891710",
        "322506915963699862059245473966830598387691259163658767351233132602858049743",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 2.3a should succeed");
    assert!(result, "Test 2.3a: e(0, Q) should be 1");

    // e(P, 0) = 1
    let g1 = build_g1_point("1", "2");
    let g2 = build_g2_point("0", "0", "0", "0");
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 2.3b should succeed");
    assert!(result, "Test 2.3b: e(P, 0) should be 1");

    // e(0, G2_generator) = 1
    let g1 = build_g1_point("0", "0");
    let g2 = build_g2_point(
        "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
        "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        "8495653923123431417604973247489272438418190587263600148770280649306958101930",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 2.3c should succeed");
    assert!(result, "Test 2.3c: e(0, G2) should be 1");

    // e(0, another G2 point) = 1
    let g1 = build_g1_point("0", "0");
    let g2 = build_g2_point(
        "11509234998032783125480266028213992619847908725038453197451386571405359529652",
        "4099696940551850412667065443628214990719002449715926250279745743126938401735",
        "19060191254988907833052035421850065496347936631097225966803157637464336346786",
        "16129402215257578064845163124174157135534373400489420174780024516864802406908",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1, &g2)];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 2.3d should succeed");
    assert!(result, "Test 2.3d: e(0, G2) should be 1");

    // 3] Tests with 2 pairs (12 inputs)

    // Ethereum example
    let g1_1 = build_g1_point(
        "20333349487611174579608837001148061570648440167819460274134014152400656275674",
        "19928268888036365434500215951569291213336085054454884806456691094014419998198",
    );
    let g2_1 = build_g2_point(
        "14335504872549532354210489828671972911333347940534076142795111812609903378108",
        "15548973838770842196102442698708122006189018193868154757846481038796366125273",
        "19822981108166058814837087071162475941148726886187076297764129491697321004944",
        "21654797034782659092642090020723114658730107139270194997413654453096686856286",
    );
    let g1_2 = build_g1_point(
        "1",
        "21888242871839275222246405745257275088696311157297823662689037894645226208581",
    );
    let g2_2 = build_g2_point(
        "11509234998032783125480266028213992619847908725038453197451386571405359529652",
        "4099696940551850412667065443628214990719002449715926250279745743126938401735",
        "19060191254988907833052035421850065496347936631097225966803157637464336346786",
        "16129402215257578064845163124174157135534373400489420174780024516864802406908",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1_1, &g2_1), (&g1_2, &g2_2)];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 3a should succeed");
    assert!(result, "Test 3a: Ethereum example pairing should be true");

    // KZG proof with one poly and one evaluation (test 1)
    let g1_1 = build_g1_point(
        "20593188969319011263398594823255811823444990825298196162496264072013322991388",
        "20958531318718262179638310844977035402258325676941759254411716094948903283238",
    );
    let g2_1 = build_g2_point(
        "19014538453489502551198430834271851224745298622671277274539119640314913863353",
        "4011274991290276638756079424799286249285264639232842260296401218902340006571",
        "5493217260886730300768636259682920882409386426126823957476482234761131640151",
        "18471742500483808444303896273620229467289887099913869033627754256214290219997",
    );
    let g1_2 = build_g1_point(
        "3526892542800189419786189901545486150149308978725362430328886936745555020543",
        "2119286186166371280112264238015778473404141003919064027522145193839708208181",
    );
    let g2_2 = build_g2_point(
        "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
        "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        "8495653923123431417604973247489272438418190587263600148770280649306958101930",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1_1, &g2_1), (&g1_2, &g2_2)];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 3b should succeed");
    assert!(result, "Test 3b: KZG proof pairing should be true");

    // KZG proof with one poly and one evaluation (test 2)
    let g1_1 = build_g1_point(
        "7732322222446307127032679746925673403013840763103947213960757438494804067267",
        "8619360092012773279112944586645719683585858765189162557863470404130431808723",
    );
    let g2_1 = build_g2_point(
        "7754062701624777074058760614745676120554164137217320298195308357000412149840",
        "4480687189204505779534873101802061566996023148878380905742776654135663383221",
        "18744429014512523574338799100424477374744612401726532054975840530120472566",
        "16667361185745910936700318129097219900413959552154798924397125501722669434888",
    );
    let g1_2 = build_g1_point(
        "595801121933130257838893357109567932541713044978712091132608377833002940532",
        "15681552092527426161541501125159206079106959026991100968107368848241580050483",
    );
    let g2_2 = build_g2_point(
        "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
        "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        "8495653923123431417604973247489272438418190587263600148770280649306958101930",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1_1, &g2_1), (&g1_2, &g2_2)];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 3c should succeed");
    assert!(result, "Test 3c: KZG proof pairing should be true");

    // 4] Tests with 3 pairs (18 inputs)

    // 3 pairs with last pair being (G1, 0)
    let g1_1 = build_g1_point(
        "7732322222446307127032679746925673403013840763103947213960757438494804067267",
        "8619360092012773279112944586645719683585858765189162557863470404130431808723",
    );
    let g2_1 = build_g2_point(
        "7754062701624777074058760614745676120554164137217320298195308357000412149840",
        "4480687189204505779534873101802061566996023148878380905742776654135663383221",
        "18744429014512523574338799100424477374744612401726532054975840530120472566",
        "16667361185745910936700318129097219900413959552154798924397125501722669434888",
    );
    let g1_2 = build_g1_point(
        "595801121933130257838893357109567932541713044978712091132608377833002940532",
        "15681552092527426161541501125159206079106959026991100968107368848241580050483",
    );
    let g2_2 = build_g2_point(
        "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
        "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        "8495653923123431417604973247489272438418190587263600148770280649306958101930",
    );
    let g1_3 = build_g1_point("1", "2");
    let g2_3 = build_g2_point("0", "0", "0", "0");
    let pairs: &[(&[u8], &[u8])] = &[(&g1_1, &g2_1), (&g1_2, &g2_2), (&g1_3, &g2_3)];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 4a should succeed");
    assert!(result, "Test 4a: 3 pairs with (G1, 0) should be true");

    // Another 3-pair test
    let g1_1 = build_g1_point(
        "20408625067408993290064640368727791004970573998302586029702220794326757674498",
        "16305464745216061320718924810220361252899630638785881184214175311729150579496",
    );
    let g2_1 = build_g2_point(
        "19366297632879679637284621799459008574776307690134846433263569915955921902826",
        "7402184029652592179271650707149396214555402416834379616679103713331638701004",
        "13233069919494729038860025360853108843397419493559475327647450442468969143158",
        "10493112377715503836766497500954305714610771526749266396762372159550562853087",
    );
    let g1_2 = build_g1_point(
        "6065896804174124393372571703959114319291624137637105019419069942189555692569",
        "1817372094771574002977021734119138264961743925299214620753363200235482672254",
    );
    let g2_2 = build_g2_point(
        "19366297632879679637284621799459008574776307690134846433263569915955921902826",
        "7402184029652592179271650707149396214555402416834379616679103713331638701004",
        "13233069919494729038860025360853108843397419493559475327647450442468969143158",
        "10493112377715503836766497500954305714610771526749266396762372159550562853087",
    );
    let g1_3 = build_g1_point(
        "5155695327752856721154364733178772660419613502017586895566245903460009198248",
        "17870951736543108265510715325941304521966082260796939666348236029204261385066",
    );
    let g2_3 = build_g2_point(
        "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
        "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        "8495653923123431417604973247489272438418190587263600148770280649306958101930",
    );
    let pairs: &[(&[u8], &[u8])] = &[(&g1_1, &g2_1), (&g1_2, &g2_2), (&g1_3, &g2_3)];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 4b should succeed");
    assert!(result, "Test 4b: 3 pairs pairing should be true");

    // 5] Tests with 4 pairs (24 inputs)
    let g1_1 = build_g1_point(
        "1153563745531144946586097928621095258348432585499389732309707300454996283289",
        "7370404687973809887690049462468892748861464831518247317487007737601322454777",
    );
    let g2_1 = build_g2_point(
        "9376055848676368316410365621777214987372973768688270899357881297879508822452",
        "19738309004667351906306506105426292998739264612662465709107894554928292805496",
        "285143926121120094170748007008262512509578107228129423236125884572189904421",
        "10279962913447536422932523162364510093030414102832227875578519449385249705476",
    );
    let g1_2 = build_g1_point(
        "8576791937965657966843713337336683588215881223744955532549571901036035091965",
        "20999102966105130950411191886633074956452730563320480529699815227954081231322",
    );
    let g2_2 = build_g2_point(
        "9376055848676368316410365621777214987372973768688270899357881297879508822452",
        "19738309004667351906306506105426292998739264612662465709107894554928292805496",
        "285143926121120094170748007008262512509578107228129423236125884572189904421",
        "10279962913447536422932523162364510093030414102832227875578519449385249705476",
    );
    let g1_3 = build_g1_point(
        "18556379486610508840908277815073629329531616761731760569700551412487192333649",
        "17673868103043290791894327402153901008120365354485186198280340860768344163073",
    );
    let g2_3 = build_g2_point(
        "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
        "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        "8495653923123431417604973247489272438418190587263600148770280649306958101930",
    );
    let g1_4 = build_g1_point(
        "20364104435611758595377721340560864676183708759135257849771131236782155536356",
        "6044194345605039714961350342623860353524318320217972076629496104743557530117",
    );
    let g2_4 = build_g2_point(
        "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
        "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        "8495653923123431417604973247489272438418190587263600148770280649306958101930",
    );
    let pairs: &[(&[u8], &[u8])] =
        &[(&g1_1, &g2_1), (&g1_2, &g2_2), (&g1_3, &g2_3), (&g1_4, &g2_4)];
    let result = crypto.bn254_pairing_check(pairs).expect("Test 5 should succeed");
    assert!(result, "Test 5: 4 pairs pairing should be true");

    println!("All BN254 Pairing Check tests passed!");
}

#![no_main]
ziskos::entrypoint!(main);

use ziskos::exp_power_of_two_self;

fn main() {
    let mut x: [u64; 4] =
        [0xc9b03b176c169088, 0xd1d94829bb3cc946, 0x39349d1bf4b794cf, 0x004e92b17f7142c5];
    let module: [u64; 4] =
        [0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];
    let expected: [u64; 4] =
        [0x3d7573f55003f36e, 0x1b217887da15fdac, 0xb069b2742d79dc5e, 0x73e89cfc6bb8fa9e];

    exp_power_of_two_self(&mut x, &module, 10);
    assert_eq!(x, expected);

    let mut x: [u64; 4] =
        [0xc9b03b176c169088, 0xd1d94829bb3cc946, 0x39349d1bf4b794cf, 0x004e92b17f7142c5];
    let expected: [u64; 4] =
        [0x95b59929f9ea03da, 0x67cc3f4fd5301d0c, 0x422b3a9b826a93de, 0x429e698354dcbaaa];
    exp_power_of_two_self(&mut x, &module, 80);
    assert_eq!(x, expected);

    let mut x: [u64; 4] =
        [0xc9b03b176c169088, 0xd1d94829bb3cc946, 0x39349d1bf4b794cf, 0x004e92b17f7142c5];
    let expected: [u64; 4] =
        [0x3e288b8628a05fe0, 0x578b5d1f083bee72, 0x91fc47418f5e2985, 0xbc0fb7af2f7fb40f];
    exp_power_of_two_self(&mut x, &module, 255);
    assert_eq!(x, expected);

    let mut x: [u64; 4] =
        [0xc9b03b176c169088, 0xd1d94829bb3cc946, 0x39349d1bf4b794cf, 0x004e92b17f7142c5];
    let expected: [u64; 4] =
        [0x3e288b8628a05fe0, 0x578b5d1f083bee72, 0x91fc47418f5e2985, 0xbc0fb7af2f7fb40f];
    exp_power_of_two_self(&mut x, &module, 255);
    assert_eq!(x, expected);

    let mut x: [u64; 4] =
        [0x3459b1f9580b9677, 0xc125fab48e837e21, 0xa5282714b8c69f4c, 0x0e091dcd4a038928];
    exp_power_of_two_self(&mut x, &module, 1313);

    let expected: [u64; 4] =
        [0x6f492348f0f5a6f4, 0x0bb6684a47500bdd, 0x8304fa7877bfbc3f, 0x31148b042c7790f2];
    assert_eq!(x, expected);

    let mut x: [u64; 4] =
        [0x3459b1f9580b9677, 0xc125fab48e837e21, 0xa5282714b8c69f4c, 0x0e091dcd4a038928];
    exp_power_of_two_self(&mut x, &module, 0);

    let expected: [u64; 4] =
        [0x3459b1f9580b9677, 0xc125fab48e837e21, 0xa5282714b8c69f4c, 0x0e091dcd4a038928];
    assert_eq!(x, expected);

    let mut x: [u64; 4] =
        [0x3459b1f9580b9677, 0xc125fab48e837e21, 0xa5282714b8c69f4c, 0x0e091dcd4a038928];
    exp_power_of_two_self(&mut x, &module, 1);

    let expected: [u64; 4] =
        [0x0748d85c03db12e3, 0x7c796302363bd056, 0xcd48b1ae22dea873, 0xc0cd0f9f5328c690];
    assert_eq!(x, expected);

    println!("Success");
}

#![no_main]
#![cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
ziskos::entrypoint!(main);

/// This program does not use input. To verify, you can use
/// keccak/program/build/input.bin

fn main() {
    // 38 x 126^4 + 100 * 24^4 = 16134
    // 38 x 126^4 + 100 * 25^4 = 16144
    // 38 x 126^4 + 100 * 26^4 = 16155
    // 38 x 126^4 + 100 * 27^4 = 16168 (16168-16077)/100=0.91
    // 38 x 126^4 + 337 * 27^4 = 16384
    let result = intense_loop(38, 126);
    println!("Result1: {}", result);
    let result = intense_loop(337, 27);
    println!("Result2: {}", result);
}

/// The intensive loop uses up to four nested loops and only performs
/// operations where intermediate values remain small (<= 384). These
/// operations are included in FROPS and therefore do not generate extra
/// instances.

#[inline(never)]
pub fn intense_loop(n: u64, loops_4: u64) -> u64 {
    let mut result: u64;

    unsafe {
        core::arch::asm!(
            // Initialize result counter
            "mv {result}, zero",
            "mv t6, {loops_4}",        // t6 = upper limit (L)
            // Outer loop: repeat `n` times
            "mv t0, {n}",              // t0 = n (outer counter)
            "2:",                      // label outer_loop
            "beqz t0, 3f",             // if t0 == 0, jump to end

            // First L-loop: iterate i from 0 to L-1
            "li t1, 0",                // Initialize i = 0
            "4:",                      // label loop_i
            "bge t1, t6, 5f",          // if i >= L, jump to next_outer

            // Second L-loop: iterate j from 0 to L-1
            "li t2, 0",                // Initialize j = 0
            "6:",                      // label loop_j
            "bge t2, t6, 7f",          // if j >= L, jump to next_i

            // Third L-loop: iterate k from 0 to L-1
            "li t3, 0",                // Initialize k = 0
            "8:",                      // label loop_k
            "bge t3, t6, 9f",          // if k >= L, jump to next_j

            // Fourth L-loop: iterate l from 0 to L-1
            "li t4, 0",                // Initialize l = 0
            "10:",                     // label loop_l
            "bge t4, t6, 11f",         // if l >= L, jump to next_k

            // Perform a small operation; ensure intermediates stay <= 384
            // so they remain inside FROPS and avoid creating extra instances.
            "and t5, t1, t2",
            "xor t5, t5, t3",
            "and t5, t5, t4",
            "xor {result}, {result}, t5",

            // Increment l and continue innermost loop
            "addi t4, t4, 1",           // l++
            "j 10b",                    // jump to loop_l

            "11:",                      // label next_k
            // Increment k and continue (this will reset l)
            "addi t3, t3, 1",           // k++
            "j 8b",                     // jump to loop_k

            "9:",                       // label next_j
            // Increment j and continue (this will reset k and l)
            "addi t2, t2, 1",           // j++
            "j 6b",                     // jump to loop_j

            "7:",                       // label next_i
            // Increment i and continue (this will reset j, k, and l)
            "addi t1, t1, 1",           // i++
            "j 4b",                     // jump to loop_i

            "5:",                       // label next_outer
            // Decrement outer counter and continue (this will reset i, j, k, l)
            "addi t0, t0, -1",          // n--
            "j 2b",                     // jump to outer_loop

            "3:",                       // label end

            n = in(reg) n,
            loops_4 = in(reg) loops_4,
            result = out(reg) result,
            out("t0") _,
            out("t1") _,
            out("t2") _,
            out("t3") _,
            out("t4") _,
            out("t5") _,
            out("t6") _,
            options(nostack),
        );
    }

    result
}

// FX-03: Kani bounded execution unwind depth overflow
#[kani::proof]
#[kani::unwind(1)]
fn fx03_unwind() {
    let mut i = 0;
    while i < 100 {
        i += 1;
    }
}

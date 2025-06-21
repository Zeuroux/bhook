use bhook::hook_fn;

hook_fn! {
    fn shup(ar: u64, ar2: u32) -> u64 = {
        println!("haha ni troll");
        ar + ar2 as u64
    }
}
fn main() {
    shutup(32, 64);
    unsafe {
        shup::hook_address(shutup as *mut u8);
    }
    shutup(9, 8);
}
#[inline(never)]
fn shutup(ar: u64, ar2: u32) -> u64 {
    println!("haha get troll");
    0
}

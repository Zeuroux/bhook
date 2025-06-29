# Bhook
This is a very lightweight hooking crate, which supports the
x86, x86_64, arm and aarch64 architectures, you can also use this crate on no-std too by
disabling the std feature.
here is a quick example of it (with the std feature)
```rust
use bhook::hook_fn;
hook_fn! {
     fn hook(val: u64, val2:u32) -> u64 = {
        let orig = unsafe { call_original(val, val2) };
        println!("testhook: val1: {val} val2: {val2}");
        println!("ret: {orig}");
        orig
    }
}
fn main() {
    numbers(98, 87);
    unsafe {
        hook::hook_address(numbers as *mut u8);
    }
    numbers(68, 92);
}
#[inline(never)]
fn numbers(n1: u64, n2: u32) -> u64 {
    println!("im numbers");
    n1 + n2 as u64
}
```
## How does it work??
It writes a simple branch to the target to redirect calls using with instructions suitable for the platform,
the maximum amount of bytes it will overwrite is in the `BRANCH_LEN` constant, however it generally will try to use
the least amount of bytes to do the branch

## Notices
The BIG disadvantage of the `hook_fn` macro is that `call_original` will undo
the hook until the call finishes, which can be very unsuitable for mulithreaded envoiroments
you can use the functions in the utils module to do things more manually, or use `raw_hook`

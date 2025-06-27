#![allow(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(feature = "std"), no_std)]
//! Very simple hooking crate, you can use this on no-std too by
//! disabling the std feature.
//!
//! here is a quick example of it (with the std feature):
//! ```rust
//! use bhook::hook_fn;
//! hook_fn! {
//!      fn hook(val: u64, val2:u32) -> u64 = {
//!         let orig = unsafe { call_original(val, val2) };
//!         println!("testhook: val1: {val} val2: {val2}");
//!         println!("ret: {orig}");
//!         orig
//!     }
//! }
//! fn main() {
//!     numbers(98, 87);
//!     unsafe {
//!         hook::hook_address(numbers as *mut u8);
//!     }
//!     numbers(68, 92);
//! }
//! #[inline(never)]
//! fn numbers(n1: u64, n2: u32) -> u64 {
//!     println!("im numbers");
//!     n1 + n2 as u64
//! }
//! ```
//! The BIG disadvantage of this macro is that call_original will undo
//! the hook until the call finishes, which can be very bad in mulithreaded envoiromemts
//! (also the hook redo and undo is not thread safe so yikes)
//! you can use the functions in the utils module to do things more manually
mod raw;
pub use raw::BACKUP_LEN;

#[cfg(feature = "std")]
mod utils;
#[cfg(feature = "std")]
pub use utils::*;
/// Branch hook a function.
///
/// This function will write a basic hook in the memory you give it,
/// differently from other hooking libraries, the method is very crude, as its literally
/// just a branch instruction to 'hook_fn', this has the benefit of not needing high complexity
/// at the cost of not being able to make a trampoline
///
/// # Safety
///
/// The target function needs to be accesible for writing, also the hook
/// must have the exact same abi as the target function, as if that is not true
/// there *will* be undefined behaviour, the target pointer must ideally point to the
/// start of the target function
#[inline(always)]
pub unsafe fn raw_hook(target: *mut u8, hook_fn: usize) {
    unsafe {
        raw::hook_impl(target, hook_fn);
        clean_cache(target, BACKUP_LEN);
    }
}
#[inline(always)]
pub(crate) unsafe fn clean_cache(ptr: *const u8, len: usize) -> bool {
    #[cfg(feature = "cache_cleaning")]
    unsafe {
        clear_cache::clear_cache(ptr, ptr.add(len))
    }
    #[cfg(not(feature = "cache_cleaning"))]
    {
        let _ptr = ptr;
        let _len = len;
        false
    }
}

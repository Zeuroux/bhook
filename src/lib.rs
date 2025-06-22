#![allow(clippy::unsafe_op_in_unsafe_fn)]
use clear_cache::clear_cache;
use core::mem::transmute;
use core::ptr;
use region::{Protection, protect_with_handle};
#[derive(Debug)]
enum HookingError {
    MemoryProtection(region::Error),
}
mod raw;
pub use raw::BACKUP_LEN;
use raw::hook_impl;
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
    unsafe { hook_impl(target, hook_fn) }
}
/// Handle memory protection and save backup bytes before doing branch hooking.
/// You can use 'unsetup_hook' to call the original function using this
///
/// # Safety
///
/// Same requirements as 'raw_hook' but the target address must be able to be safely
/// written to by disabling write protection
pub unsafe fn setup_hook(
    orig_fn: *mut u8,
    hook_fn: *const u8,
) -> Result<[u8; BACKUP_LEN], region::Error> {
    unsafe {
        #[cfg(not(target_arch = "arm"))]
        let offset_fn = orig_fn;
        #[cfg(target_arch = "arm")]
        let offset_fn = orig_fn.offset(-1);
        let _handle = protect_with_handle(offset_fn, BACKUP_LEN, Protection::READ_WRITE_EXECUTE)?;
        let result = ptr::read_unaligned(offset_fn as *mut [u8; BACKUP_LEN]);
        raw_hook(orig_fn, hook_fn as usize);
        clean_cache(offset_fn as *const u8, BACKUP_LEN);
        Ok(result)
    }
}

/// Handle memory protection and then write back the backup bytes.
///
/// # Safety
///
/// Dont copy the backup bytes to somewhere they dont belong, ever
pub unsafe fn unsetup_hook(
    orig_fn: *mut u8,
    orig_code: [u8; BACKUP_LEN],
) -> Result<(), region::Error> {
    unsafe {
        #[cfg(target_arch = "arm")]
        let orig_fn = orig_fn.offset(-1);
        let _handle = protect_with_handle(orig_fn, BACKUP_LEN, Protection::READ_WRITE_EXECUTE)?;
        ptr::write_unaligned(orig_fn as *mut [u8; BACKUP_LEN], orig_code);
        clean_cache(orig_fn as *const u8, BACKUP_LEN);
    }
    Ok(())
}

#[inline(always)]
unsafe fn clean_cache(ptr: *const u8, len: usize) -> bool {
    unsafe { clear_cache(ptr, ptr.add(len)) }
}

#[macro_export]
macro_rules! hook_fn {
    (fn $name:ident($($arg_name:ident : $arg_ty:ty),*) -> $ret_type:ty = $body:expr )  => {
        mod $name {
            static mut CONTEXT: Option<HookCtx> = None;
            struct HookCtx {
                original: *mut u8,
                hook: *const u8,
                backup: [u8; bhook::BACKUP_LEN]
            }
                pub unsafe fn hook_address(original_addr: *mut u8) {
                    unsafe {
                    let backup = bhook::setup_hook(original_addr, mainhook as *const u8);
                    CONTEXT = Some(HookCtx {
                        original: original_addr,
                        hook: mainhook as *const u8,
                        backup: backup.unwrap(),
                    })
                    }
                }


            unsafe fn call_original($($arg_name : $arg_ty), *) -> $ret_type {
                unsafe {
                    let sus = CONTEXT.as_ref().unwrap();
                    bhook::unsetup_hook(sus.original, sus.backup).unwrap();
                    let original = core::mem::transmute::<*mut u8, fn($($arg_ty),*) -> $ret_type>(sus.original);
                    let result = original($($arg_name),*);
                    bhook::setup_hook(sus.original, sus.hook).unwrap();
                    result
                }
            }
            unsafe extern "C" fn mainhook( $($arg_name: $arg_ty),*) -> $ret_type {unsafe {$body }}
        }
    };
}

use crate::raw::BACKUP_LEN;
use region::{Protection, protect_with_handle};

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
        let result = offset_fn.cast::<[u8; BACKUP_LEN]>().read_unaligned();
        crate::raw_hook(orig_fn, hook_fn as usize);
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
        orig_fn
            .cast::<[u8; BACKUP_LEN]>()
            .write_unaligned(orig_code);
        crate::clean_cache(orig_fn.cast_const(), BACKUP_LEN);
    }
    Ok(())
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

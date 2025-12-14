#[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
use core::{ffi::c_void, ptr};

unsafe extern "C" {
    unsafe fn dlsym(handle: *mut c_void, symbol: *const u32) -> *mut c_void;
}

type PatchFn = extern "C" fn(*mut c_void, *const c_void, usize) -> *mut c_void;

const RTLD_DEFAULT: *mut c_void = ptr::null_mut();

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
#[inline(always)]
unsafe fn patch(a: *mut c_void, d: *const c_void, s: usize) -> bool {
    let symbol_name = b"mcpelauncher_patch\0".as_ptr() as *const u32;
    let mcp_patch_ptr = dlsym(RTLD_DEFAULT, symbol_name);
    if mcp_patch_ptr.is_null() {
        return false;
    }
    let patch_fn: PatchFn = std::mem::transmute(mcp_patch_ptr);
    patch_fn(a, d, s);
    
    true
}

#[cfg(target_arch = "aarch64")]
pub const BACKUP_LEN: usize = 16;

#[cfg(target_arch = "aarch64")]
pub unsafe fn hook_impl(t: *mut u8, h: usize) {
    let o = h.wrapping_sub(t as usize) as i32;
    if (-0x2000000..=0x1ffffff).contains(&o) {
        let b = (0x14000000 | (o & 0x03ffffff)).to_ne_bytes();
        if !patch(t as _, b.as_ptr() as _, 4) {
            ptr::write_unaligned(t.cast(), u32::from_ne_bytes(b));
        }
    } else {
        const C: [u8; 8] = [0x50,0x00,0x00,0x58,0x00,0x02,0x1F,0xD6];
        let mut x = [0u8;16]; x[..8].copy_from_slice(&C); x[8..].copy_from_slice(&h.to_ne_bytes());
        if !patch(t as _, x.as_ptr() as _, 16) {
            ptr::write_unaligned(t.cast(), [usize::from_ne_bytes(C), h]);
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub const BACKUP_LEN: usize = 12;

#[cfg(target_arch = "x86_64")]
pub unsafe fn hook_impl(target: *mut u8, hook_fn: usize) {
    let mut code: [u8; 12] = [
        0x48, 0xb8, // movabs rax, <ptr>
        0, 0, 0, 0, 0, 0, 0, 0, // <ptr>
        0xff, 0xe0, // jmp rax
    ];
    code[2..10].copy_from_slice(&hook_fn.to_ne_bytes());
    
    if !patch(target as _, code.as_ptr() as _, 12) {
        (target as *mut [u8; 12]).write_unaligned(code);
    }
}

#[cfg(target_arch = "x86")]
pub const BACKUP_LEN: usize = 7;

#[cfg(target_arch = "x86")]
pub unsafe fn hook_impl(target: *mut u8, hook_fn: usize) {
    let mut code: [u8; 7] = [
        0xB8, // mov eax, <ptr>
        0, 0, 0, 0, // <ptr>
        0xFF, 0xE0, // jmp eax
    ];
    code[1..5].copy_from_slice(&hook_fn.to_ne_bytes());
    
    if !patch(target as _, code.as_ptr() as _, 7) {
        (target as *mut [u8; 7]).write_unaligned(code);
    }
}

#[cfg(target_arch = "arm")]
fn is_thumb(addr: u32) -> bool {
    addr & 1 != 0
}
#[cfg(target_arch = "arm")]
fn clear_thumb_bit(addr: u32) -> u32 {
    addr & 0xfffffffe
}
#[cfg(target_arch = "arm")]
fn is_aligned(addr: u32) -> bool {
    addr % 4 == 0
}
#[cfg(target_arch = "arm")]
// Magic value: code len (4) + pointer length(4) + align(1)
pub const BACKUP_LEN: usize = 9;
#[cfg(target_arch = "arm")]
pub unsafe fn hook_impl(target: *mut u8, hook_fn: usize) {
    // Small explanation for the logic in this
    // in arm, the pointer width is 32bit, which is the same as regular arm instruction width
    // but thumb is u16
    let target_addr = target as u32;
    if is_thumb(target_addr) {
        // asm: nop
        const THUMB_NOOP: u16 = 0xbf00;
        // asm: ldr.w pc, [pc]
        const LDR_PC_PC: [u16; 2] = [0xf8df, 0xf000];
        let target_addr = clear_thumb_bit(target_addr);
        let mut target = target_addr as *mut u16;
        if !is_aligned(target_addr) {
            unsafe {
                target.write_unaligned(THUMB_NOOP);
                target = target.offset(1);
            }
        }
        unsafe {
            (target as *mut [u16; 2]).write_unaligned(LDR_PC_PC);
            (target.offset(2) as *mut usize).write_unaligned(hook_fn);
        }
    } else {
        // asm: ldr pc, [pc, -4]
        const CODE: usize = 0xe51ff004;
        let arm_insns = target_addr as *mut usize;
        unsafe {
            arm_insns.write_unaligned(CODE);
            arm_insns.offset(1).write_unaligned(hook_fn);
        }
    }
}
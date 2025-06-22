use core::ptr;
#[cfg(target_arch = "aarch64")]
// Magic value: code len (8) + pointer length (8)
pub const BACKUP_LEN: usize = 16;
#[cfg(target_arch = "aarch64")]
pub unsafe fn hook_impl(target: *mut u8, hook_fn: usize) {
    let offset = (hook_fn as isize - target as isize) as i32 / 4;
    let branch_binary: i32 = 0x14000000;
    if !(-0x2000000..=0x1ffffff).contains(&offset) {
        const CODE: [u8; 8] = [
            0x50, 0x00, 0x00, 0x58, // ldr x16, +0x8
            0x00, 0x02, 0x1F, 0xD6, // br x16
        ];
        const CODE_USIZE: usize = usize::from_ne_bytes(CODE);
        unsafe {
            ptr::write(target as *mut [usize; 2], [CODE_USIZE, hook_fn]);
        }
    } else {
        let branch_inst: u32 = (branch_binary | (offset & 0x03ffffff)) as u32;
        unsafe {
            ptr::write(target as *mut u32, branch_inst);
        }
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
                *target = THUMB_NOOP;
                target = target.offset(1);
            }
        }
        unsafe {
            *(target as *mut [u16; 2]) = LDR_PC_PC;
            *(target.offset(2) as *mut usize) = hook_fn;
        }
    } else {
        // asm: ldr pc, [pc, -4]
        const CODE: usize = 0xe51ff004;
        let arm_insns = target_addr as *mut usize;
        unsafe {
            *arm_insns = CODE;
            *arm_insns.offset(1) = hook_fn;
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub const BACKUP_LEN: usize = 12;
#[cfg(target_arch = "x86_64")]
pub unsafe fn hook_impl(target: *mut u8, hook_fn: usize) {
    let mut code: [u8; 12] = [
        0x48, 0xb8, // movabs rax, <ptr>
        0, 0, 0, 0, 0, 0, 0, 0, // <ptr>, we copy the real ptr later
        0xff, 0xe0, // jmp rax
    ];
    code[2..10].copy_from_slice(&hook_fn.to_ne_bytes());
    (target as *mut [u8; 12]).write(code);
}

#[cfg(target_arch = "x86")]
// Magic value: mov length (1) + pointer length (4) + jmp len (2)
pub const BACKUP_LEN: usize = 7;
#[cfg(target_arch = "x86")]
pub unsafe fn hook_impl(target: *mut u8, hook_fn: usize) {
    let mut code: [u8; 7] = [
        0xB8, // mov eax, <ptr>
        0, 0, 0, 0, // <ptr>, we copy the real ptr later
        0xFF, 0xE0, // jmp eax
    ];
    code[1..5].copy_from_slice(&hook_fn.to_ne_bytes());
    (target as *mut [u8; 5]).write(code);
}

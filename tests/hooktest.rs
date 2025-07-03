use bhook::{BACKUP_LEN, hook_fn};
#[test]
fn hook_test() {
    assert_eq!(original(), 0);
    unsafe {
        hook::hook_address(original as *mut u8);
    }
    assert_eq!(original(), 255);
}
#[inline(never)]
fn original() -> u8 {
    0
}
hook_fn! {
    fn hook() -> u8 = {
        255
    }
}

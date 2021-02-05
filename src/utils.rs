#![allow(dead_code)]


unsafe fn u16_ptr_len(ptr: *const u16) -> usize {
    let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
    return len;
}

fn compare_str_u16(s: &str, u: *const u16) -> bool {
    unsafe {
        let len = (0..).take_while(|&i| *u.offset(i) != 0).count();
        let slice = core::slice::from_raw_parts(u, len);
        let s_len = s.len();
        if len != s_len {
            return false;
        }
        let ss = s.as_bytes();
        for i in 0..len {
            if slice[i] != ss[i] as u16 {
                return false;
            }
        }
        return true;
    }
}

// TODO: use alloc
pub fn str_to_u16_ptr(s: &str, buf: &mut [u16]) {
    let s_len = s.len();
    let s_bytes = s.as_bytes();

    // for i in 0..255 {

    // }
    // let buf = vec![0u16;s_len+1];
    for i in 0..s_len {
        buf[i] = s_bytes[i] as _;
    }
    buf[s_len] = 0;
    //    buf.as_ptr()
}

use num_traits::Num;

pub fn compare_raw_str<T>(s: *const T, u: *const T) -> bool
where
    T: Num,
{
    unsafe {
        let u_len = (0..).take_while(|&i| !(*u.offset(i)).is_zero()).count();
        let u_slice = core::slice::from_raw_parts(u, u_len);

        let s_len = (0..).take_while(|&i| !(*s.offset(i)).is_zero()).count();
        let s_slice = core::slice::from_raw_parts(s, s_len);

        if s_len != u_len {
            return false;
        }
        for i in 0..s_len {
            if s_slice[i] != u_slice[i] {
                return false;
            }
        }
        return true;
    }
}

fn compare_str_u8(s: &str, u: *const u8) -> bool {
    unsafe {
        let len = (0..).take_while(|&i| *u.offset(i) != 0).count();
        let slice = core::slice::from_raw_parts(u, len);
        let s_len = s.len();
        if len != s_len {
            return false;
        }
        let ss = s.as_bytes();
        for i in 0..len {
            if slice[i] != ss[i] as u8 {
                return false;
            }
        }
        return true;
    }
}

fn str_to_i8(s: &str) -> *const i8 {
    s.as_bytes().as_ptr() as *const i8
}

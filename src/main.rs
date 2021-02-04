#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]
#![feature(asm)]
#![feature(link_args)]
use core::{ptr::null_mut, slice, usize};

mod binds;
mod utils;
use arrayvec::ArrayString;
use binds::*;
use utils::*;
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
// use winapi::um::libloaderapi::LoadLibraryA;
// pub type LLA = extern "stdcall" LoadLibraryA;
#[no_mangle]
// #[link_section = ".text.prologue"]
pub extern "C" fn main() -> ! {
    // "KERNEL32.DLL"
    unsafe {
        asm!("mov rcx, 0", "mov rdx, 0",);
    }
    let KERNEL32_STR: [u16; 13] = [75, 69, 82, 78, 69, 76, 51, 50, 46, 68, 76, 76, 0];
    // let KERNEL32_STR = "KERNEL32.DLL";
    // username: Username::try_from_str("user")?,
    // let KERNEL32_STR = KK20::try_from_str("KERNEL32.DLL");
    let kk = get_module_by_name(KERNEL32_STR.as_ptr());
    // println!("kernel32: {:p}", kk);
    // let kk = get_module_by_name(12);
    let OutputDebugStringA_STR: [u8; 19] = [
        79, 117, 116, 112, 117, 116, 68, 101, 98, 117, 103, 83, 116, 114, 105, 110, 103, 65, 0,
    ];
    let dbg_addr = get_func_by_name(kk, OutputDebugStringA_STR.as_ptr());
    // "LoadLibraryA"
    let LoadLibraryA_STR: [u8; 13] = [76, 111, 97, 100, 76, 105, 98, 114, 97, 114, 121, 65, 0];
    let load_library = get_func_by_name(kk, LoadLibraryA_STR.as_ptr());

    // "GetProcAddress"
    let GetProcAddress_STR: [u8; 15] = [
        71, 101, 116, 80, 114, 111, 99, 65, 100, 100, 114, 101, 115, 115, 0,
    ];
    let get_proc = get_func_by_name(kk, GetProcAddress_STR.as_ptr());
    // println!("dbg_addr: {:p}", dbg_addr);
    // println!("load_library: {:p}", load_library);

    let LoadLibraryA: extern "system" fn(lpFileName: LPCSTR) -> PVOID =
        unsafe { core::mem::transmute(load_library) };
    // let LoadLibraryA_ :LoadLibraryA = unsafe { core::mem::transmute(load_library) };
    // let a = "user32.dll";
    // let c_str = CString::new("user32.dll").unwrap();
    // let c_world: *const c_char = c_str.as_ptr() as *const c_char;
    let c_world = b"user32.dll\0".as_ptr() as *const i8;
    // let c_world: [i8; 11] = [117, 115, 101, 114, 51, 50, 46, 100, 108, 108, 0];

    unsafe {
        asm!("push rax");
    }
    let u32_dll = LoadLibraryA(c_world);
    // println!("u32_dll: {:p}", u32_dll);

    // pub unsafe extern "system" fn GetProcAddress(
    //     hModule: HMODULE,
    //     lpProcName: LPCSTR
    // ) -> FARPROC

    let GetProcAddress: extern "system" fn(hmodule: PVOID, name: LPCSTR) -> PVOID =
        unsafe { core::mem::transmute(get_proc) };

    // let c_str = CString::new("MessageBoxA").unwrap();
    // let c_world: *const c_char = c_str.as_ptr() as *const c_char;
    let c_world = b"MessageBoxA\0".as_ptr() as *const i8;
    // let c_world: [i8; 12] = [77, 101, 115, 115, 97, 103, 101, 66, 111, 120, 65, 0];
    // let c_world1 = b"xxx";
    let c_world1 = "title\0";
    // let c_world1 = aa + "123";
    // c_world1.to_uppercase();
    // let mut u = ArrayString::from_byte_string(b"hello world").unwrap();
    // u.push_str("abc");
    let message_box_ptr = GetProcAddress(u32_dll, c_world);

    // println!("message_box_ptr: {:p}", message_box_ptr);

    let MessageBoxA: extern "system" fn(h: PVOID, text: LPCSTR, cation: LPCSTR, t: u32) -> u32 =
        unsafe { core::mem::transmute(message_box_ptr) };

    MessageBoxA(null_mut(), c_world, c_world1.as_ptr() as _, 0x30);
    // https://stackoverflow.com/questions/46134477/how-can-i-call-a-raw-address-from-rust
    let OutputDebugStringA: extern "C" fn(*const i8) = unsafe { core::mem::transmute(dbg_addr) };
    // let c_str = CString::new("helloxx").unwrap();
    // let c_world: *const c_char = c_str.as_ptr() as *const c_char;
    // let c_str = "helloxxx123";
    // let c_str:[u8;3] = [0x41,0x42,0x0];
    // let c_world = c_str.as_ptr();
    // // // // println!("1: {:?}", c_world);
    // let msg = b"mmmmsg";
    // let msg: &[u8] = [b'a', b'b'];
    //let a = "abc";

    // OutputDebugStringA(msg.as_ptr() as _);
    loop {}
}

fn get_module_by_name(module_name: *const u16) -> PVOID {
    unsafe {
        let peb: *mut PEB;
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
        );
        let ldr = (*peb).Ldr;
        let mut list = &((*ldr).InLoadOrderModuleList);
        let mut curr_module: *mut LDR_DATA_TABLE_ENTRY = &mut list as *mut _ as *mut _;
        loop {
            // println!("loop start");
            if curr_module.is_null() || (*curr_module).BaseAddress.is_null() {
                // println!(
                //     "gg, {}, {}",
                //     curr_module.is_null(),
                //     (*curr_module).BaseAddress.is_null()
                // );
                // break;
            }
            let mut curr_name = (*curr_module).BaseDllName.Buffer;
            if curr_name.is_null() {
                // continue;
            }
            // curr_name = curr_name.offset(1)
            // // println!("1");
            let mut i: isize = 0;
            // // println!("2");
            // // println!("curr_name: {:?}", curr_name);

            if curr_name.is_null() {
            } else {
                // let name = u16_ptr_to_string(curr_name);
                // let name = "";
                // // // println!("name===: {} {:?}", name.len(), name);
                // if name_len == module_name.len()  {
                if compare_raw_str(module_name, curr_name) {
                    // println!("base: {:?}", (*curr_module).BaseAddress);
                    // break;
                    return (*curr_module).BaseAddress;
                }
            }
            // for
            // break;
            let flink = (*curr_module).InLoadOrderModuleList.Flink;
            curr_module = flink as *mut LDR_DATA_TABLE_ENTRY;
        }
        // // // println!("")
    }
}

// type LoadLibraryA

fn get_func_by_name(module: PVOID, func_name: *const u8) -> PVOID {
    let idh: *const IMAGE_DOS_HEADER = module as *const _;
    unsafe {
        if (*idh).e_magic != IMAGE_DOS_SIGNATURE {
            // // println!("e_magic eror");
        } else {
        }
        let e_lfanew = (*idh).e_lfanew;
        // dbg!(e_lfanew);
        let nt_headers: *const IMAGE_NT_HEADERS =
            (module as *const u8).offset(e_lfanew as isize) as *const _;
        let op_header = &(*nt_headers).OptionalHeader;
        let exp_dir = &op_header.DataDirectory[0];

        let exp_addr = exp_dir.VirtualAddress;
        if exp_addr == 0 {
            // // println!("virtualaddr error");
        } else {
            // // println!("virtualAddr: 0x{:x} {}", exp_addr, exp_addr);
        }
        // let exp_dir_raw = exp_dir as *const _ as *const u8;
        let exp: *const IMAGE_EXPORT_DIRECTORY = (module as *const u8).offset(exp_addr as _) as _; // this case error?
        let names_count = (*exp).NumberOfNames;
        let funcs_rva = (*exp).AddressOfFunctions;
        let func_names_rva = (*exp).AddressOfNames;
        let names_ords_rva = (*exp).AddressOfNameOrdinals;

        // // println!("names_count: {}", names_count);
        for i in 0..names_count {
            // // // println!("=== {} ===", i);
            let name_rva: *const DWORD =
                (module as *const u8).offset((func_names_rva + i * 4) as isize) as *const _;
            let name_index: *const WORD =
                (module as *const u8).offset((names_ords_rva + i * 2) as isize) as *const _;
            let name_i = name_index.as_ref().unwrap();
            let mut off1: u32 = (4 * name_i) as u32;
            off1 = off1 + funcs_rva;
            let func_rva: *const DWORD = (module as *const u8).offset(off1 as isize) as *const _;

            let mut rav_i = name_rva.as_ref().unwrap();
            let curr_name = (module as *const u8).offset(*rav_i as isize);

            if *curr_name == 0 {
                continue;
                // let bla= CString::from_raw(curr_name as _);
            }
            // let len = (0..).take_while(|&i| *curr_name.offset(i) != 0).count();
            // let slice = core::slice::from_raw_parts(curr_name, len);
            // // // println!("cur_name: {:?}",slice);
            // OutputDebugStringA
            // if slice[0] == 'O' as u8 && slice[6] == 'D' as u8 {
            if compare_raw_str(func_name, curr_name) {
                // for i in slice {
                //print!("{}", *i as char);
                // }
                // // println!("");
                // break;
                let mo = (module as *const u8).offset(*func_rva as isize);
                // return 0;
                return mo as _;
            }
            // let c_string = CString::new("LoadLibraryA").expect("CString::new failed");
            // let load_library = c_string.as_bytes();

            // for i in 0..load_library.len() {
            //     if load_library[i] == slice[i] {
            //         continue
            //     } else {
            //         // // println!("{} => {}", i, load_library.len());
            //         if load_library.len() - i < 2 {
            //             // // println!("got it: {:?}", slice);
            //         }
            //         break;

            //     }
            // }

            // i
        }
    }
    return 0 as _;
}

// pub unsafe extern "system" fn LoadLibraryA(lp_lib_file_name: *const i8) -> isize;
// pub unsafe extern "system" fn OutputDebugStringA(lpOutputString: LPCSTR)

#[allow(unused_attributes)]
#[cfg(target_env = "msvc")]
#[link_args = "/GS- /MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB /EMITPOGOPHASEINFO /DEBUG:NONE"]
extern "C" {}
/// NT Status type.

extern "C" {
    // /// `DbgPrint` routine sends a message to the kernel debugger.
    // pub fn DbgPrint(Format: *const u8, ...) -> NTSTATUS;
    // /// The `DbgPrintEx` routine sends a string to the kernel debugger if certain conditions are met.
    // pub fn DbgPrintEx(ComponentId: u32, Level: u32, Format: *const u8, ...) -> NTSTATUS;
}

// #[macro_export]
// macro_rules! KdPrint {
// 	($msg:expr $(, $arg:expr)*) => { unsafe { DbgPrint( concat!($msg, "\0").as_ptr() $(, $arg )* )} };
// }

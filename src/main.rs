#![allow(non_camel_case_types)]
#![allow(overflowing_literals)]
// #![no_std]
#![no_main]
#![feature(asm)]

use core::{ptr::null_mut, usize};
use std::ffi::OsString;
use std::os::windows::prelude::*;
// use ntapi::winapi_local::um::winnt::__readgsqword;
// #[panic_handler]
// fn panic(_: &core::panic::PanicInfo) -> ! {
//     loop {}
// }
// https://stackoverflow.com/questions/48586816/converting-raw-pointer-to-16-bit-unicode-character-to-file-path-in-rust
unsafe fn u16_ptr_to_string(ptr: *const u16) -> OsString {
    let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
    let slice = std::slice::from_raw_parts(ptr, len);

    OsString::from_wide(slice)
}
#[no_mangle]
// #[link_section = ".text.prologue"]
pub extern "C" fn main() -> ! {
    // __readgsqword(0x60);
    // KdPrint!("hello\n");
    unsafe {

        let peb: *mut PEB;
        // let mut status: IO_STATUS_BLOCK = core::mem::zeroed();
        
        // Get PEB from reserved register `GS`
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
        );
        
        // Get STDOUT handle from PEB
        // let handle = (*(*peb).ProcessParameters).StandardOutput;
        let ldr = (*peb).Ldr;
        let mut list = &((*ldr).InLoadOrderModuleList);

        let mut curr_module: *mut LDR_DATA_TABLE_ENTRY = &mut list as *mut _ as *mut _ ;
        println!("curr_module: {:p}", curr_module);
        println!("BaseAddress: {:p}", (*curr_module).BaseAddress);
        // let kernel32: &[u16] = wch_c!("kernel32.dll");
        let kernel32: &[u16] = &[107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108, 0];
        loop {
            println!("start1...");

            // if curr_module
            if curr_module.is_null() || (*curr_module).BaseAddress.is_null() {
                println!("gg, {}, {}",curr_module.is_null() ,  (*curr_module).BaseAddress.is_null());
                // break;
            } 
            let mut curr_name = (*curr_module).BaseDllName.Buffer;
            if curr_name.is_null() {
                // continue;
            }
            // curr_name = curr_name.offset(1)
            println!("1");
            let mut i: isize = 0;
            println!("2");
            println!("curr_name: {:?}", curr_name);
            if curr_name.is_null() {

            } else {

                println!("name===: {:?}", u16_ptr_to_string(curr_name));
            }
            // loop {
            //     println!("3");
            //     // let cur = *curr_name.offset(i);
            //     let cur = curr_name.offset(i).as_ref();
            //     // println!("4");
            //     let kur =&kernel32[i as usize];
            //     // println!("5");
            //     println!("cur: {:?}, kur: {:?}", cur, kur);
            //     // if cur == 0 || kur == &0 {
            //     //     break;
            //     // }
            //     // if  kur != &cur {
            //     //     break;
            //     // }
            //     i +=1;
            // }
            // if 

            // for
                // break;
            let flink = (*curr_module).InLoadOrderModuleList.Flink;
            // let curr_module1: *mut LDR_DATA_TABLE_ENTRY = flink as *mut _ ;
            curr_module = flink as *mut LDR_DATA_TABLE_ENTRY ;
            // curr_module
        }
    }
    loop {}
}
/// NT Status type.
pub type NTSTATUS = Status;

/// A specialized `Result` type for NT operations.
pub type Result<T> = ::core::result::Result<T, Status>;


/// NT Status code.
#[repr(C)]
#[derive(Clone, Copy)]
pub enum Status {
	success = 0,
	unsuccessful = 0xC0000001,
}

extern "C"
{
	// /// `DbgPrint` routine sends a message to the kernel debugger.
	// pub fn DbgPrint(Format: *const u8, ...) -> NTSTATUS;
	// /// The `DbgPrintEx` routine sends a string to the kernel debugger if certain conditions are met.
	// pub fn DbgPrintEx(ComponentId: u32, Level: u32, Format: *const u8, ...) -> NTSTATUS;
}

// #[macro_export]
// macro_rules! KdPrint {
// 	($msg:expr $(, $arg:expr)*) => { unsafe { DbgPrint( concat!($msg, "\0").as_ptr() $(, $arg )* )} };
// }
pub enum c_void {}
type BOOLEAN = u8;
type HANDLE = *mut c_void;
type PVOID = *mut c_void;
type ULONG = u32;
#[repr(C)]
pub struct PEB {
  pub InheritedAddressSpace: BOOLEAN,
  pub ReadImageFileExecOptions: BOOLEAN,
  pub BeingDebugged: BOOLEAN,
  pub BitField: BOOLEAN,
  pub Mutant: HANDLE,
  pub ImageBaseAddress: PVOID,
  pub Ldr: *mut PEB_LDR_DATA,
  pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
  pub Length: ULONG,
  pub Initialized: BOOLEAN,
  pub SsHandle: HANDLE,
  pub InLoadOrderModuleList: LIST_ENTRY,
  // ...
}


#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub BaseAddress: PVOID,
    pub EntryPoint: PVOID,
    pub SizeOfImage: ULONG,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,

    // ...
}


type USHORT = u16;
type PWCH = *mut u16;


#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWCH,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}
#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
  pub MaximumLength: ULONG,
  pub Length: ULONG,
  pub Flags: ULONG,
  pub DebugFlags: ULONG,
  pub ConsoleHandle: HANDLE,
  pub ConsoleFlags: ULONG,
  pub StandardInput: HANDLE,
  pub StandardOutput: HANDLE,
  pub StandardError: HANDLE,
}


type PULONG = *mut ULONG;
#[repr(C)]
pub struct IO_STATUS_BLOCK {
  _1: IO_STATUS_BLOCK_u,
  _2: PULONG,
}

#[repr(C)]
pub union IO_STATUS_BLOCK_u {
  _1: NTSTATUS,
  _2: PVOID,
}
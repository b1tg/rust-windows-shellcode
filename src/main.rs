use anyhow::Result;
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;

fn main() -> Result<()> {
    let src_path = "shellcode\\target\\x86_64-pc-windows-msvc\\release\\shellcode.exe";
    let mut file = File::open(src_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let pe = PE::parse(&mut buffer)?;
    let standard_fileds = pe.header.optional_header.unwrap().standard_fields;
    let entry_offset = standard_fileds.address_of_entry_point - standard_fileds.base_of_code;
    for section in pe.sections {
        let name = String::from_utf8(section.name.to_vec())?;
        if !name.starts_with(".text") {
            continue;
        }
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let dst_path = "shellcode\\target\\x86_64-pc-windows-msvc\\release\\shellcode.bin";
        let shellcode = File::create(dst_path)?;
        let mut buf_writer = BufWriter::new(shellcode);
        println!("[*] section text addr: 0x{:x}, size: 0x{:x}", start, size);
        println!("[*] entry offset: 0x{:x}", entry_offset);
        println!("== before patch ==");
        show_disassemble(&buffer[start..start + size], 5);
        if entry_offset >= 0x100 {
            buffer[0 + start] = 0xe9;
            let hi = (entry_offset - 2) / 0x100;
            let li = (entry_offset - 2) % 0x100;
            dbg!(hi, li);
            buffer[1 + start] = li as _;
            buffer[2 + start] = hi as _;
            buffer[3 + start] = 0 as _;
            buffer[4 + start] = 0 as _;
        } else if entry_offset >= 0x80 {
            buffer[0 + start] = 0xe9;
            buffer[1 + start] = (entry_offset - 5) as _;
            buffer[2 + start] = 0 as _;
            buffer[3 + start] = 0 as _;
            buffer[4 + start] = 0 as _;
        } else {
            buffer[0 + start] = 0xeb;
            buffer[1 + start] = (entry_offset - 2) as _;
        }
        println!("== after patch ==");
        show_disassemble(&buffer[start..start + size], 5);
        for i in start..start + size {
            buf_writer.write(&[buffer[i]])?;
        }
        buf_writer.flush().unwrap();
        println!("done! shellcode saved in {}", dst_path);
    }
    Ok(())
}
pub fn show_disassemble(bytes: &[u8], max_line: u32) {
    let mut decoder = Decoder::new(EXAMPLE_CODE_BITNESS, bytes, DecoderOptions::NONE);
    decoder.set_ip(EXAMPLE_CODE_RIP);
    let mut formatter = NasmFormatter::new();
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);
    let mut output = String::new();
    let mut instruction = Instruction::default();
    let mut i = 0;
    while decoder.can_decode() {
        i += 1;
        if i > max_line {
            println!("....\n");
            break;
        }
        decoder.decode_out(&mut instruction);
        output.clear();
        formatter.format(&instruction, &mut output);
        print!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - EXAMPLE_CODE_RIP) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("  ");
            }
        }
        println!(" {}", output);
    }
}

const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;
const EXAMPLE_CODE_BITNESS: u32 = 64;
const EXAMPLE_CODE_RIP: u64 = 0x0000_0001_4000_1000; // 0000 0001 4000 1000

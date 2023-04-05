use peekmore::PeekMore;

use std::time::*;

use wasabi_wasm::BinaryOp::I32Xor;
use wasabi_wasm::LoadOp::I32Load;
use wasabi_wasm::Module;
use wasabi_wasm::Val;
use wasabi_wasm::Val::I32;
use wasabi_wasm::{Code, Instr::*};

pub fn harden_module(module: &mut Module) {
    let canary = generate_le_canary();
    let func_ptr_addresses = find_and_crypt_func_ptrs(module, canary);
    encrypt_func_ptrs_in_data_sections(module, &func_ptr_addresses, canary);
}

fn generate_le_canary() -> u32 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        // Mike: Ensure that the first function pointer starts with a null terminator when encrypted
        Ok(duration) => (duration.as_nanos() as u32 & 0xFFFFFF00) | 0x00000001,
        Err(_) => 0x6B694D00,
    }
}

fn remove_dup_addresses(func_ptr_addresses: &mut Vec<u32>) {
    func_ptr_addresses.sort_unstable();
    func_ptr_addresses.dedup();
}

fn insert_xor_instrs(idx: usize, code: &mut Code, canary: u32) {
    code.body.insert(idx, Const(wasabi_wasm::Val::I32(canary as i32)));
    code.body.insert(idx + 1, Binary(I32Xor));
}

fn find_and_crypt_func_ptrs(module: &mut Module, canary: u32) -> Vec<u32> {
    let mut func_ptr_addresses = vec![];

    for (func_idx, func) in module.clone().functions() {
        if let Some(func_code_mut) = module.functions[func_idx.to_usize()].code_mut() {
            let mut func_instrs_rev_iter = func.instrs().iter().rev().peekmore();
            let mut call_indirect_instr_idx = func_code_mut.body.len();

            'l_next_func: loop {
                func_instrs_rev_iter.reset_cursor();
                loop {
                    match func_instrs_rev_iter.next() {
                        Some(CallIndirect(_, _)) => {
                            call_indirect_instr_idx -= 1;
                            break;
                        }
                        None => {
                            break 'l_next_func;
                        }
                        _ => {
                            call_indirect_instr_idx -= 1;
                        }
                    }
                }

                let func_ptr_addr;
                loop {
                    match func_instrs_rev_iter.peek() {
                        Some(Load(I32Load, mem_arg)) => {
                            func_ptr_addr = mem_arg.offset;
                            break;
                        }
                        None => {
                            println!("[Pointer Hardening] Could not find an 'i32.load' instruction before a 'call_indirect' instruction in function #{func_idx:?} !");
                            break 'l_next_func;
                        }
                        _ => {
                            func_instrs_rev_iter.advance_cursor();
                        }
                    }
                }

                // TODO: we need to come up with a way to handle when there are multiple i32.const
                // before the i32.load.
                loop {
                    func_instrs_rev_iter.advance_cursor();
                    match func_instrs_rev_iter.peek() {
                        Some(Const(I32(i32))) => {
                            func_ptr_addresses.push(*i32 as u32 + func_ptr_addr);
                            func_instrs_rev_iter.next();
                            insert_xor_instrs(call_indirect_instr_idx, func_code_mut, canary);
                            break;
                        }
                        None => {
                            println!("[Pointer Hardening] Could not find an 'i32.const' instruction before a 'i32.load' instruction in function #{func_idx:?} !");
                            break 'l_next_func;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    remove_dup_addresses(&mut func_ptr_addresses);
    func_ptr_addresses
}

fn encrypt_func_ptrs_in_data_sections(module: &mut Module, func_ptr_addresses: &Vec<u32>, canary: u32) {
    for func_ptr_addr in func_ptr_addresses {
        let mut found_func_ptr = false;

        'l_encrypted_func_ptr: for memory in module.memories.iter_mut() {
            for data_section in memory.data.iter_mut() {
                if let Const(Val::I32(i32)) = data_section.offset[0] {
                    if !data_section.bytes.is_empty() {
                        // Check if the function pointer is in this data section
                        let func_ptr_size = 4;

                        /*
                         * Round up the length of the data section to the next four byte boundary.
                         * This is done so that we can detect if a function pointer lies at the end of a data section,
                         * as any trailing null bytes are removed by wasabi.
                         */
                        let mut data_section_len = data_section.bytes.len();
                        let remainder = ((data_section_len + 3) & !3) - data_section_len;
                        data_section.bytes.append(&mut vec![0; remainder]);
                        data_section_len += remainder;

                        let data_section_start = i32 as u32;
                        let data_section_end = (data_section_start + data_section_len as u32) - func_ptr_size as u32;
                        // Restore the data section to its original length if we are not modifying it
                        if *func_ptr_addr < data_section_start || *func_ptr_addr > data_section_end {
                            data_section.bytes.truncate(data_section_len - remainder);
                            continue;
                        }

                        // Get the function pointer from the data section
                        let func_ptr_start: usize = (func_ptr_addr - data_section_start) as usize;
                        let func_ptr_end = func_ptr_start + func_ptr_size;
                        let func_ptr = u32::from_le_bytes(
                            data_section.bytes[func_ptr_start..func_ptr_end]
                                .try_into()
                                .unwrap(),
                        );
                        // Web Assembly uses little-endian byte ordering
                        let encrypted_func_ptr = (func_ptr ^ canary).to_le_bytes();
                        // Store the encrypted function pointer into the data section
                        data_section.bytes[func_ptr_start..func_ptr_end].copy_from_slice(&encrypted_func_ptr);

                        /*
                         * Restore the data section to its original length if the function pointer being modified is not
                         * at the end of the data section.
                         */
                        if *func_ptr_addr != data_section_end {
                            data_section.bytes.truncate(data_section_len - remainder);
                        }

                        found_func_ptr = true;
                        break 'l_encrypted_func_ptr;
                    }
                }
            }
        }
        if !found_func_ptr {
            panic!("[Pointer Hardening] Failed to encrypt the function pointer at the address {func_ptr_addr:#010X}, aborting !");
        }
    }
}
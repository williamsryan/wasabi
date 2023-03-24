use peekmore::PeekMore;

use std::time::*;

use wasabi_wasm::BinaryOp::I32Xor;
use wasabi_wasm::LoadOp::I32Load;
use wasabi_wasm::Module;
use wasabi_wasm::StoreOp::I32Store;
use wasabi_wasm::Val;
use wasabi_wasm::Val::I32;
use wasabi_wasm::{Code, Instr::*};

pub fn harden_module(module: &mut Module) {
    let mut func_ptr_addresses = get_func_ptr_addresses(module);
    let canary = generate_le_canary();

    // Use a dummy module in order to resolve the addresses of all of the function pointers without
    // clobbering the true module
    loop {
        let mut prev_func_ptr_addresses = func_ptr_addresses.clone();
        do_crypt_instrs(&mut module.clone(), &mut prev_func_ptr_addresses, canary);

        // Exit the loop once we have resolved the addresses of all of the function pointers
        if func_ptr_addresses.len() == prev_func_ptr_addresses.len() {
            break;
        }
        func_ptr_addresses = prev_func_ptr_addresses;
    }

    do_crypt_instrs(module, &mut func_ptr_addresses, canary);
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

fn get_func_ptr_addresses(module: &mut Module) -> Vec<u32> {
    let mut func_ptr_addresses = vec![];

    for (func_idx, func) in module.clone().functions() {
        let real_func_idx = func_idx.to_usize() + 1;
        let mut func_instrs_rev_iter = func.instrs().iter().rev().peekmore();

        'l_next_func: loop {
            func_instrs_rev_iter.reset_cursor();
            loop {
                match func_instrs_rev_iter.next() {
                    Some(CallIndirect(_, _)) => {
                        break;
                    }
                    None => {
                        break 'l_next_func;
                    }
                    _ => {}
                }
            }

            match func_instrs_rev_iter.peek() {
                Some(Load(I32Load, mem_arg)) => {
                    if let Some(Const(I32(i32))) = func_instrs_rev_iter.peek_next() {
                        func_ptr_addresses.push(*i32 as u32 + mem_arg.offset);
                        func_instrs_rev_iter.next();
                    } else {
                        println!("[Pointer Hardening] Unrecognised 'i32.load' pattern in function #{real_func_idx:?} !");
                    }
                }
                None => {
                    println!("[Pointer Hardening] Could not find an instruction before a 'call_indirect' instruction in function #{real_func_idx:?} !");
                }
                _ => {
                    println!("[Pointer Hardening] Unknown instruction pattern before a 'call_indirect' instruction in function #{real_func_idx:?} !");
                }
            }
        }
    }
    remove_dup_addresses(&mut func_ptr_addresses);
    func_ptr_addresses
}

fn insert_crypt_instrs(idx: usize, code: &mut Code, canary: u32) {
    code.body.insert(idx, Const(wasabi_wasm::Val::I32(canary as i32)));
    code.body.insert(idx + 1, Binary(I32Xor));
}

fn do_crypt_instrs(module: &mut Module, func_ptr_addresses: &mut Vec<u32>, canary: u32) {
    for (func_idx, func) in module.clone().functions() {
        if let Some(func_code_mut) = module.functions[func_idx.to_usize()].code_mut() {
            let mut func_instrs_rev_iter = func.instrs().iter().rev().peekmore();
            let mut curr_instr_idx = func_code_mut.body.len();

            loop {
                curr_instr_idx -= 1;
                func_instrs_rev_iter.reset_cursor();
                func_instrs_rev_iter.next();
                match func_instrs_rev_iter.peek() {
                    Some(Store(I32Store, mem_arg)) => {
                        let mut store_func_ptr_addr = mem_arg.offset;
                        if let Some(Load(I32Load, mem_arg)) = func_instrs_rev_iter.peek_next() {
                            let mut load_func_ptr_addr = mem_arg.offset;
                            if let Some(Const(I32(i32))) = func_instrs_rev_iter.peek_next() {
                                load_func_ptr_addr += *i32 as u32;
                            } else {
                                continue;
                            }
                            if let Some(Const(I32(i32))) = func_instrs_rev_iter.peek_next() {
                                store_func_ptr_addr += *i32 as u32;
                                if func_ptr_addresses.contains(&load_func_ptr_addr) || func_ptr_addresses.contains(&store_func_ptr_addr) {
                                    insert_crypt_instrs(curr_instr_idx - 1, func_code_mut, canary);
                                    func_ptr_addresses.append(&mut vec![load_func_ptr_addr, store_func_ptr_addr]);
                                }
                            }
                        }
                    }
                    Some(Load(I32Load, mem_arg)) => {
                        let load_func_ptr_addr;
                        if let Some(Const(I32(i32))) = func_instrs_rev_iter.peek_next() {
                            load_func_ptr_addr = *i32 as u32 + mem_arg.offset;
                        } else {
                            continue;
                        }
                        if let Some(Const(I32(i32))) = func_instrs_rev_iter.peek_next() {
                            let store_func_ptr_addr = *i32 as u32;
                            if func_ptr_addresses.contains(&load_func_ptr_addr) || func_ptr_addresses.contains(&store_func_ptr_addr) {
                                insert_crypt_instrs(curr_instr_idx, func_code_mut, canary);
                                func_ptr_addresses.append(&mut vec![load_func_ptr_addr, store_func_ptr_addr]);
                            }
                        } else if func_ptr_addresses.contains(&load_func_ptr_addr) {
                            insert_crypt_instrs(curr_instr_idx, func_code_mut, canary);
                        }
                    }
                    None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    remove_dup_addresses(func_ptr_addresses);
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
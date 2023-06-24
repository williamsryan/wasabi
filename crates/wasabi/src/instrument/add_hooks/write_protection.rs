use wasabi_wasm::BinaryOp::*;
use wasabi_wasm::Function;
use wasabi_wasm::FunctionType;
use wasabi_wasm::FunctionType::GoedelNumber;
use wasabi_wasm::Idx;
use wasabi_wasm::Instr;
use wasabi_wasm::Instr::*;
use wasabi_wasm::Label;
use wasabi_wasm::LocalOp;
use wasabi_wasm::StoreOp::*;
use wasabi_wasm::Val;
use wasabi_wasm::ValType::*;
use wasabi_wasm::{MemoryOp, Module};

struct ValidateWritePatch {
    original_instr: Instr,
    func_idx: Idx<Function>,
}

pub fn write_protect_range(module: &mut Module, start_address: u32, end_address: u32) {
    assert!(
        start_address < end_address,
        "start_address ({start_address:#010X}) < end_address ({end_address:#010X})"
    );

    // println!("start_address ({start_address:#010X}) < end_address ({end_address:#010X})");

    let mut validate_write_patches: Vec<ValidateWritePatch> = vec![];
    let mut patched_store_instrs = 0;
    for (func_idx, func) in module.clone().functions() {
        if let Some(func_code) = func.code() {
            for (instr_idx, instr) in func_code.body.clone().into_iter().enumerate() {
                if let Store(store_op, _) = instr {
                    let func_type = store_op.to_type();
                    let stack_size = func_type.inputs().len();
                    if stack_size != 2 {
                        println!("[Write Protection] Encountered a 'store' instruction with {stack_size} value{0} on the stack, skipping !", if stack_size == 1 { "" } else { "s" });
                        continue;
                    }
                    let store_addr_type = func_type.inputs()[0];
                    let store_val_type = func_type.inputs()[1];

                    if store_addr_type != I32 {
                        println!("[Write Protection] Encountered a 'store' instruction where the address is of type '{store_addr_type}', skipping !");
                        continue;
                    }
                    match store_op {
                        I32Store8 | I32Store16 | I32Store => {
                            if store_val_type != I32 {
                                println!("[Write Protection] Encountered a 'i32.store' instruction where the value being stored is of type '{store_val_type}', skipping !");
                                continue;
                            }
                        }
                        I64Store8 | I64Store16 | I64Store32 | I64Store => {
                            if store_val_type != I64 {
                                println!("[Write Protection] Encountered a 'i64.store' instruction where the value being stored is of type '{store_val_type}', skipping !");
                                continue;
                            }
                        }
                        F32Store => {
                            if store_val_type != F32 {
                                println!("[Write Protection] Encountered a 'f32.store' instruction where the value being stored is of type '{store_val_type}', skipping !");
                                continue;
                            }
                        }
                        F64Store => {
                            if store_val_type != F64 {
                                println!("[Write Protection] Encountered a 'f64.store' instruction where the value being stored is of type '{store_val_type}', skipping !");
                                continue;
                            }
                        }
                    };

                    // Check if we have already inserted a patch that corresponds to this instruction
                    let validate_write_patch = validate_write_patches
                        .iter()
                        .find(|validate_write_patch| validate_write_patch.original_instr == instr);

                    let validate_write_func_idx = match validate_write_patch {
                        Some(validate_write_patch) => validate_write_patch.func_idx,
                        None => {
                            let num_additional_bytes_modified = match store_op {
                                I32Store8 | I64Store8 => 0,
                                I32Store16 | I64Store16 => 1,
                                I32Store | F32Store | I64Store32 => 3,
                                I64Store | F64Store => 7,
                            };

                            let new_func_idx = module.add_function(
                                FunctionType::new(&[store_addr_type, store_val_type], &[]),
                                vec![
                                    I32, // Temporary variable
                                ],
                                // Check if the address being written to is in the range that we are protecting
                                vec![
                                    Block(GoedelNumber {
                                        inputs: 0,
                                        results: 0,
                                    }),
                                    Local(LocalOp::Get, Idx::from(0u32)),
                                    Const(Val::I32(end_address as i32)),
                                    Binary(I32GeU),
                                    BrIf(Label::from(0u32)),
                                    Const(Val::I32(start_address as i32)),
                                    Local(LocalOp::Get, Idx::from(0u32)),
                                    Binary(I32Sub),
                                    Local(LocalOp::Tee, Idx::from(2u32)),
                                    Const(Val::I32(0)),
                                    Local(LocalOp::Get, Idx::from(2u32)),
                                    Const(Val::I32(start_address as i32)),
                                    Binary(I32LeU),
                                    Select,
                                    Const(Val::I32(num_additional_bytes_modified)),
                                    Binary(I32GtU),
                                    BrIf(Label::from(0u32)),
                                    Unreachable,
                                    End,
                                    Local(LocalOp::Get, Idx::from(0u32)),
                                    Local(LocalOp::Get, Idx::from(1u32)),
                                    instr.clone(),
                                    End,
                                ],
                            );

                            validate_write_patches.push(ValidateWritePatch {
                                original_instr: instr,
                                func_idx: new_func_idx,
                            });

                            new_func_idx
                        }
                    };

                    if let Some(module_code) = module.functions[func_idx.to_usize()].code_mut() {
                        module_code.body[instr_idx] = Call(validate_write_func_idx);
                        patched_store_instrs += 1;
                    } else {
                        println!("[Write Protection] Failed to patch instruction #{0} in function #{1} !", instr_idx + 1, func_idx.to_usize());
                    }
                }
            }
        }
    }
    println!(
        "[Write Protection] Patched {patched_store_instrs} 'store' instruction{0} !",
        if patched_store_instrs == 1 { "" } else { "s" }
    );
}

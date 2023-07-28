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

fn get_called_func_idxs_recursive(
    module: &Module,
    func_idx: &Idx<Function>,
    func_idxs: &mut Vec<Idx<Function>>,
) {
    func_idxs.push(*func_idx);

    if let Some(code) = module.function(*func_idx).code() {
        for instr in &code.body {
            if let Call(func_idx) = instr {
                get_called_func_idxs_recursive(module, func_idx, func_idxs);
            }
        }
    } else {
        println!(
            "[Write Protection] Failed to parse function #{0} !",
            func_idx.to_usize()
        );
    }
}

pub fn write_protect_range(module: &mut Module, start_address: u32, end_address: u32) {
    assert!(
        start_address < end_address,
        "start_address ({start_address:#010X}) < end_address ({end_address:#010X})"
    );

    let mut whitelisted_func_idxs = vec![];
    // If the module contains a 'start' function
    if let Some(start_func_idx) = module.start {
        // Take note of all the functions that the 'start' function calls
        get_called_func_idxs_recursive(module, &start_func_idx, &mut whitelisted_func_idxs);
        // Ensure that no duplicate values exist in the vector
        whitelisted_func_idxs.sort();
        whitelisted_func_idxs.dedup();
    }

    let mut validate_write_patches: Vec<ValidateWritePatch> = vec![];
    let mut patched_store_instrs = 0;
    for (func_idx, func) in module.clone().functions() {
        // Do not protect any functions that are called by the 'start' function
        if whitelisted_func_idxs.contains(&func_idx) {
            continue;
        }

        if let Some(code) = func.code() {
            for (instr_idx, instr) in code.body.clone().into_iter().enumerate() {
                if let Store(store_op, _) = instr {
                    let func_type = store_op.to_type();
                    let store_addr_type = func_type.inputs()[0];
                    let store_val_type = func_type.inputs()[1];

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

                    if let Some(code) = module.functions[func_idx.to_usize()].code_mut() {
                        code.body[instr_idx] = Call(validate_write_func_idx);
                        patched_store_instrs += 1;
                    } else {
                        println!("[Write Protection] Failed to patch instruction #{0} in function #{1} !", instr_idx + 1, func_idx.to_usize());
                    }
                }
            }
        } else {
            println!(
                "[Write Protection] Failed to parse function #{0} !",
                func_idx.to_usize()
            );
        }
    }
    println!(
        "[Write Protection] Patched {patched_store_instrs} 'store' instruction{0} !",
        if patched_store_instrs == 1 { "" } else { "s" }
    );
}

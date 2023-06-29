use wasabi_wasm::BinaryOp::I32Eq;
use wasabi_wasm::Function;
use wasabi_wasm::FunctionType;
use wasabi_wasm::FunctionType::GoedelNumber;
use wasabi_wasm::Idx;
use wasabi_wasm::Instr::*;
use wasabi_wasm::Label;
use wasabi_wasm::LoadOp;
use wasabi_wasm::LocalOp;
use wasabi_wasm::Memarg;
use wasabi_wasm::Module;
use wasabi_wasm::StoreOp;
use wasabi_wasm::Val;
use wasabi_wasm::ValType;

use super::write_protection::write_protect_range;

struct CallIndirectInstrLoc {
    func_idx: Idx<Function>,
    instr_idx: usize,
}

const CALL_INDIRECT_READ_ONLY_TBL_ADDR: u32 = 0x00000010;

pub fn harden_module(module: &mut Module) {
    let call_indirect_instr_locs = patch_call_indirect_instrs(module);
    let num_patched_call_indirect_instrs = call_indirect_instr_locs.len();

    println!("[Pointer Hardening] Patching {num_patched_call_indirect_instrs} 'call_indirect' instruction{0} !",
    if num_patched_call_indirect_instrs == 1 { "" } else { "s" } );
    if num_patched_call_indirect_instrs == 0 {
        return;
    }
    let get_func_ptrs_funcs_idxs =
        add_get_func_ptrs_funcs_to_module(module, &call_indirect_instr_locs);

    init_start_func(module, get_func_ptrs_funcs_idxs);
    write_protect_range(
        module,
        CALL_INDIRECT_READ_ONLY_TBL_ADDR,
        CALL_INDIRECT_READ_ONLY_TBL_ADDR + (call_indirect_instr_locs.len() as u32 * 4),
    );
}

fn patch_call_indirect_instrs(module: &mut Module) -> Vec<CallIndirectInstrLoc> {
    let mut call_indirect_instr_locs: Vec<CallIndirectInstrLoc> = vec![];

    for (func_idx, func) in module.clone().functions_mut() {
        if func.param_count() != 0 {
            continue;
        }

        if let Some(func_code) = func.code_mut() {
            for (instr_idx, instr) in func_code.clone().body.iter().enumerate() {
                if let CallIndirect(func_type, _table_idx) = instr {
                    if !func_type.inputs().is_empty() {
                        break;
                    }

                    let call_instr = Call(module.add_function(
                        FunctionType::new(&[ValType::I32], &[ValType::I32]),
                        vec![
                            ValType::I32, // Parameter
                        ],
                        // Check if the function pointer has been modified
                        vec![
                            Block(GoedelNumber {
                                inputs: 0,
                                results: 0,
                            }),
                            Local(LocalOp::Get, Idx::from(0u32)),
                            Const(Val::I32(
                                CALL_INDIRECT_READ_ONLY_TBL_ADDR as i32
                                    + (call_indirect_instr_locs.len() as i32 * 4),
                            )),
                            Load(
                                LoadOp::I32Load,
                                Memarg {
                                    alignment_exp: 2,
                                    offset: 0,
                                },
                            ),
                            Binary(I32Eq),
                            BrIf(Label::from(0u32)),
                            Unreachable,
                            End,
                            Local(LocalOp::Get, Idx::from(0u32)),
                            instr.clone(),
                            End,
                        ],
                        /*
                        // Use the function pointer that was deduced
                        vec![
                            Const(Val::I32(
                                CALL_INDIRECT_READ_ONLY_TBL_ADDR as i32
                                    + (call_indirect_instr_locs.len() as i32 * 4),
                            )),
                            Load(
                                LoadOp::I32Load,
                                Memarg {
                                    alignment_exp: 2,
                                    offset: 0,
                                },
                            ),
                            instr.clone(),
                            End,
                        ],
                        */
                    ));

                    call_indirect_instr_locs.push(CallIndirectInstrLoc {
                        func_idx,
                        instr_idx,
                    });

                    if let Some(func_code) = module.function_mut(func_idx).code_mut() {
                        func_code.body[instr_idx] = call_instr;
                    } else {
                        println!("[Pointer Hardening] Failed to patch instruction #{0} in function #{1} !", instr_idx + 1, func_idx.to_usize());
                    }
                }
            }
        }
    }

    call_indirect_instr_locs
}

fn add_get_func_ptrs_funcs_to_module(
    module: &mut Module,
    call_indirect_instr_locs: &[CallIndirectInstrLoc],
) -> Vec<Idx<Function>> {
    let mut get_func_ptrs_funcs_idxs: Vec<Idx<Function>> = vec![];

    for call_indirect_instr_loc in call_indirect_instr_locs.iter() {
        let func = module.function_mut(call_indirect_instr_loc.func_idx);

        if let Some(func_code) = func.code() {
            let new_func = &mut func_code.body[0..call_indirect_instr_loc.instr_idx].to_vec();
            new_func.push(End);

            get_func_ptrs_funcs_idxs.push(module.add_function(
                FunctionType::new(&[], &[ValType::I32]),
                vec![],
                new_func.to_vec(),
            ));
        }
    }

    get_func_ptrs_funcs_idxs
}

fn init_start_func(module: &mut Module, get_func_ptrs_funcs_idxs: Vec<Idx<Function>>) {
    let mut start_func_body = vec![];

    // If the module already has a 'start' function defined
    if let Some(start_func_idx) = module.start {
        // Call the original 'start' function first
        start_func_body.push(Call(start_func_idx));
    }
    // Store the function pointers in read-only memory
    for (i, get_func_ptrs_funcs_idx) in get_func_ptrs_funcs_idxs.into_iter().enumerate() {
        start_func_body.push(Call(get_func_ptrs_funcs_idx));
        start_func_body.push(Local(LocalOp::Set, Idx::from(0u32)));
        start_func_body.push(Const(Val::I32(
            CALL_INDIRECT_READ_ONLY_TBL_ADDR as i32 + (i as i32 * 4),
        )));
        start_func_body.push(Local(LocalOp::Get, Idx::from(0u32)));
        start_func_body.push(Store(
            StoreOp::I32Store,
            Memarg {
                alignment_exp: 2,
                offset: 0,
            },
        ));
    }
    start_func_body.push(End);

    module.start = Some(module.add_function(
        FunctionType::new(&[], &[]),
        vec![ValType::I32], // Temporary
        start_func_body,
    ));
}

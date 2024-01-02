use super::write_protection::write_protect_range;

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

struct CallIndirectPatch {
    func_idx: Idx<Function>,
    instr_idx: usize,
    new_func_idx: Idx<Function>,
}

const CALL_INDIRECT_READ_ONLY_TBL_ADDR: u32 = 0x00001000; // Just trying a large value for now to test if it works.
const FUNC_PTR_SIZE: u32 = 0x00000004;

pub fn harden_module(module: &mut Module) {
    let call_indirect_patches = get_call_indirect_patches(module);
    let num_call_indirect_patches = call_indirect_patches.len();

    // Dummy test.
    // for seg in module.clone().memories() {
    //     println!("memory segment test: {:?}", seg);
    // }

    println!(
        "[Pointer Hardening] Patching {num_call_indirect_patches} 'call_indirect' instruction{0} !",
        if num_call_indirect_patches == 1 {
            ""
        } else {
            "s"
        }
    );
    if num_call_indirect_patches == 0 {
        return;
    }
    let get_func_ptrs_funcs_idxs = do_call_indirect_patches(module, &call_indirect_patches);

    init_start_func(module, &get_func_ptrs_funcs_idxs);
    // TODO: test this with and without the write-protection.
    // Determine overhead incurred for this individual pass.
    write_protect_range(
        module,
        CALL_INDIRECT_READ_ONLY_TBL_ADDR,
        CALL_INDIRECT_READ_ONLY_TBL_ADDR + (call_indirect_patches.len() as u32 * FUNC_PTR_SIZE),
    );
}

fn get_call_indirect_patches(module: &mut Module) -> Vec<CallIndirectPatch> {
    let mut call_indirect_patches: Vec<CallIndirectPatch> = vec![];

    // NOTE: does this end up now looking at functions 1->n, when it should be 1->(n-1)?
    for (func_idx, func) in module.clone().functions() {
        // Do not attempt to deduce function pointers that are within functions that accept arguments.
        if func.param_count() != 0 {
            continue;
        }

        if let Some(code) = func.code() {
            for (instr_idx, instr) in code.body.iter().enumerate() {
                if let CallIndirect(func_type, _table_idx) = instr {
                    let locals = &[
                        func_type.inputs(),
                        // Added
                        &[ValType::I32],
                    ]
                    .concat();
                    let func_ptr_local_idx = locals.len() - 1;

                    let mut body = vec![
                        Block(GoedelNumber {
                            inputs: 0,
                            results: 0,
                        }),
                        // Load the precomputed function pointer
                        Local(LocalOp::Get, Idx::from(func_ptr_local_idx)),
                        Const(Val::I32(
                            CALL_INDIRECT_READ_ONLY_TBL_ADDR as i32
                                + (call_indirect_patches.len() as i32 * FUNC_PTR_SIZE as i32),
                        )),
                        Load(
                            LoadOp::I32Load,
                            Memarg {
                                alignment_exp: 2,
                                offset: 0,
                            },
                        ),
                        // Check if the function pointer has changed
                        Binary(I32Eq),
                        // Branch if the function pointer has not changed
                        BrIf(Label::from(0u32)),
                        // If the function pointer has changed
                        // Panic
                        Unreachable,
                        End,
                    ];
                    // If the function pointer has not changed
                    // Load the arguments
                    for i in 0..locals.len() {
                        body.push(Local(LocalOp::Get, Idx::from(i)));
                    }
                    // Call the function pointer
                    body.push(instr.clone());
                    body.push(End);

                    call_indirect_patches.push(CallIndirectPatch {
                        func_idx,
                        instr_idx,
                        new_func_idx: module.add_function(
                            FunctionType::new(locals, func_type.results()),
                            vec![],
                            body,
                        ),
                    });
                }
            }
        } else {
            println!(
                "[Pointer Hardening] Failed to parse function #{0}! (.code() returned: {1:?})",
                func_idx.to_usize(), func.code()
            );
        }
    }

    call_indirect_patches
}

fn do_call_indirect_patches(
    module: &mut Module,
    call_indirect_patches: &[CallIndirectPatch],
) -> Vec<Idx<Function>> {
    let mut get_func_ptrs_funcs_idxs: Vec<Idx<Function>> = vec![];

    for (i, call_indirect_patch) in call_indirect_patches.iter().enumerate() {
        let func = module.function_mut(call_indirect_patch.func_idx);
        let mut locals: Vec<ValType> = func.locals().map(|(_, local)| local.type_).collect();
        // Added
        locals.push(ValType::I32);
        let func_ptr_local_idx = locals.len() - 1;

        if let Some(code) = func.code_mut() {
            // Instructions used to compute the function pointer
            let new_func = &mut code.body[0..call_indirect_patch.instr_idx].to_vec();
            // Save the function pointer
            new_func.push(Local(LocalOp::Set, Idx::from(func_ptr_local_idx)));
            // Load the address that the function pointer will be stored at
            new_func.push(Const(Val::I32(
                CALL_INDIRECT_READ_ONLY_TBL_ADDR as i32 + (i as i32 * FUNC_PTR_SIZE as i32),
            )));
            // Load the function pointer
            new_func.push(Local(LocalOp::Get, Idx::from(func_ptr_local_idx)));
            // Store the function pointer
            new_func.push(Store(
                StoreOp::I32Store,
                Memarg {
                    alignment_exp: 2,
                    offset: 0,
                },
            ));
            // Get rid of the excess values that are on the stack before returning from the function
            match code.body[call_indirect_patch.instr_idx] {
                CallIndirect(func_type, _tbl_idx) => {
                    for _ in 0..func_type.inputs().len() {
                        new_func.push(Drop);
                    }
                }
                _ => {
                    panic!("[Pointer Hardening] Instruction #{0} of function #{1} is not a 'call_indirect' instruction !",
                           call_indirect_patch.instr_idx + 1, call_indirect_patch.func_idx.to_usize());
                }
            }
            new_func.push(End);

            // Patch the original instruction
            code.body[call_indirect_patch.instr_idx] = Call(call_indirect_patch.new_func_idx);

            get_func_ptrs_funcs_idxs.push(module.add_function(
                FunctionType::new(&[], &[]),
                locals,
                new_func.to_vec(),
            ));
        } else {
            panic!(
                "[Pointer Hardening] Failed to parse function #{0} !",
                call_indirect_patch.func_idx.to_usize()
            );
        }
    }

    get_func_ptrs_funcs_idxs
}

fn init_start_func(module: &mut Module, get_func_ptrs_funcs_idxs: &Vec<Idx<Function>>) {
    let mut start_func_body = vec![];

    // If the module already has a 'start' function defined
    if let Some(start_func_idx) = module.start {
        // Call the original 'start' function first
        start_func_body.push(Call(start_func_idx));
    }
    for get_func_ptrs_funcs_idx in get_func_ptrs_funcs_idxs {
        start_func_body.push(Call(*get_func_ptrs_funcs_idx));
    }
    start_func_body.push(End);

    module.start = Some(module.add_function(FunctionType::new(&[], &[]), vec![], start_func_body));
}

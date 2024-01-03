use wasabi_wasm::BinaryOp::*;
use wasabi_wasm::Function;
use wasabi_wasm::FunctionType;
use wasabi_wasm::FunctionType::GoedelNumber;
use wasabi_wasm::Idx;
use wasabi_wasm::Instr;
use wasabi_wasm::Instr::*;
use wasabi_wasm::Label;
use wasabi_wasm::LocalOp;
use wasabi_wasm::StoreOp;
use wasabi_wasm::Val;
use wasabi_wasm::ValType;
use wasabi_wasm::ValType::*;
use wasabi_wasm::{MemoryOp, Module};

pub fn monitor_test(module: &mut Module) {
    let print_func_idx = add_print_function(module);

    for (func_idx, func) in module.functions_mut() {
        let mut new_instrs = Vec::new();

        if let Some(func_code) = func.code() {
            for (_, instr) in func_code.body.clone().into_iter().enumerate() {
                if let Store(store_op, _) = instr {
                    match store_op {
                        StoreOp::I32Store
                        | StoreOp::I64Store
                        | StoreOp::F32Store
                        | StoreOp::F64Store => {
                            new_instrs.push(Call(print_func_idx)); // Print the value on stack.
                            new_instrs.push(Local(LocalOp::Get, Idx::from(0u32)));
                            // Continue normal execution.
                        }
                        _ => {}
                    }
                }

                // Add original instructions to the new instruction list.
                new_instrs.push(instr.clone());
            }
        }

        // Replace the original instructions with the new instruction list.
        // *func.body_mut() = new_instrs;
    }
}

fn add_print_function(module: &mut Module) -> Idx<Function> {
    // println!("[Instruction Monitor] Adding a print function to the module.");
    // Define the type of the print function.
    let print_func_type = FunctionType::new(&vec![ValType::I32], &[]);

    // Define the body of the print function
    // This is a placeholder, replace it with the actual instructions
    let print_func_body = vec![
        Local(LocalOp::Get, Idx::from(0u32)),
        Call(Idx::from(0u32)), // Call the host function
        End,
    ];

    // Add the function to the module
    let print_func_idx = module.add_function(print_func_type, vec![I32], print_func_body);

    // Return the index of the print function.
    print_func_idx
}

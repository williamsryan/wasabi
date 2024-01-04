use wasabi_wasm::Function;
use wasabi_wasm::FunctionType;
use wasabi_wasm::Idx;
use wasabi_wasm::Instr::*;
use wasabi_wasm::LocalOp;
use wasabi_wasm::Module;
use wasabi_wasm::StoreOp;
use wasabi_wasm::Val;
use wasabi_wasm::ValType;
use wasabi_wasm::ValType::*;

pub fn monitor_test(module: &mut Module) {
    let logging_func_idx = add_logging_function(module);

    for (func_idx, func) in module.functions_mut() {
        if let Some(instrs) = func.instrs_mut() {
            let mut new_instrs = Vec::new();

            for (instr_idx, instr) in instrs.iter().cloned().enumerate() {
                if let Store(store_op, _) = instr {
                    match store_op {
                        StoreOp::I32Store
                        | StoreOp::I64Store
                        | StoreOp::F32Store
                        | StoreOp::F64Store => {
                            // Push the function index, instruction index, and value to be stored onto the stack.
                            new_instrs.push(Const(Val::I32(func_idx.to_u32() as i32)));
                            new_instrs.push(Const(Val::I32(instr_idx as i32)));
                            new_instrs.push(Local(LocalOp::Get, Idx::from(0u32)));
                            // Call the logging function.
                            new_instrs.push(Call(logging_func_idx));
                        }
                        _ => {}
                    }
                }
                // Add original instructions to the new instruction list.
                new_instrs.push(instr);
            }
            // Replace the original instructions with the new ones.
            *instrs = new_instrs;
        }
    }
}

fn add_logging_function(module: &mut Module) -> Idx<Function> {
    // println!("[Instruction Monitor] Adding a print function to the module.");
    // Define the type of the print function.
    let log_func_type = FunctionType::new(
        &vec![ValType::I32, ValType::I32, ValType::I32],
        &vec![ValType::I32],
    );

    // Define the body of the logging function.
    let log_func_body = vec![
        // Log the function index
        Local(LocalOp::Get, Idx::from(0u32)), // Get the function index
        Call(Idx::from(0u32)),                // Call the host function
        // Log the instruction index
        Local(LocalOp::Get, Idx::from(1u32)), // Get the instruction index
        Call(Idx::from(0u32)),                // Call the host function
        // Log the value to be stored
        Local(LocalOp::Get, Idx::from(2u32)), // Get the value to be stored
        Call(Idx::from(0u32)),                // Call the host function
        // Local(LocalOp::Get, Idx::from(2u32)),
        End,
    ];

    // Add the function to the module
    let log_func_idx = module.add_function(log_func_type, vec![I32, I32, I32], log_func_body);

    // Return the index of the logging function.
    log_func_idx
}

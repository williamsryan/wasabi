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
use wasabi_wasm::ValType;
use wasabi_wasm::ValType::*;
use wasabi_wasm::{MemoryOp, Module};

pub fn monitor_test(module: &mut Module) {
    for (func_idx, func) in module.clone().functions() {
        // println!("func_idx: {:?}", func_idx);
        // println!("func: {:?}", func);

        if let Some(func_code) = func.code() {
            for (instr_idx, instr) in func_code.body.clone().into_iter().enumerate() {
                // println!("instr_idx: {:?}", instr_idx);
                // println!("instr: {:?}", instr);

                if let Store(store_op, _) = instr {
                    let func_type = store_op.to_type();
                    let stack_size = func_type.inputs().len();

                    let store_addr_type = func_type.inputs()[0];
                    let store_val_type = func_type.inputs()[1];

                    // Debugging stuff.
                    // println!("store_addr_type: {:?}", store_addr_type);
                    // println!("store_val_type: {:?}", store_val_type);
                    // println!("store_op: {:?}", store_op);
                    // println!("stack_size: {:?}", stack_size);
                    // println!("func_type: {:?}", func_type);
                    // println!("instr: {:?}", instr);

                    // Insert a 'tee_local' instruction to duplicate the value being stored.
                    let tee_instr = Local(LocalOp::Tee, Idx::from(2u32));
                    // func_code.body.insert(instr_idx, tee_instr);

                    // Insert a call to a host function that prints the value being stored.
                    let print_func_idx = add_print_function(module);
                    let call_instr = Instr::Call(print_func_idx);
                    // func_code.body.insert(instr_idx + 1, call_instr);

                    if store_addr_type != I32 {
                        println!("[Instruction Monitor] Encountered a 'store' instruction where the address is of type '{store_addr_type}', skipping !");
                        continue;
                    }

                    match store_op {
                        I32Store8 | I32Store16 | I32Store => {
                            if store_val_type != I32 {
                                println!("[Instruction Monitor] Encountered a 'i32.store' instruction where the value being stored is of type '{store_val_type}', skipping !");
                                continue;
                            }
                        }
                        I64Store8 | I64Store16 | I64Store32 | I64Store => {
                            if store_val_type != I64 {
                                println!("[Instruction Monitor] Encountered a 'i64.store' instruction where the value being stored is of type '{store_val_type}', skipping !");
                                continue;
                            }
                        }
                        F32Store => {
                            if store_val_type != F32 {
                                println!("[Instruction Monitor] Encountered a 'f32.store' instruction where the value being stored is of type '{store_val_type}', skipping !");
                                continue;
                            }
                        }
                        F64Store => {
                            if store_val_type != F64 {
                                println!("[Instruction Monitor] Encountered a 'f64.store' instruction where the value being stored is of type '{store_val_type}', skipping !");
                                continue;
                            }
                        }
                    };
                }
            }
        }
    }
}


fn add_print_function(module: &mut Module) -> Idx<Function> {
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
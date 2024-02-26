use wasmer::{imports, Function, FunctionType, Instance, Module, Store, Type, Value};
// use wasmer_compiler_cranelift::Cranelift;
// use wasmer_engine_jit::JIT;
use std::path::Path;

// fn host_print(i: i32) {
//     println!("{}", i);
// }

pub fn create_runtime(wasm_bin: &Path) -> Result<Instance, Box<dyn std::error::Error>> {
    println!("[+] Creating runtime from module: {:?}", wasm_bin.display());
    let mut store = Store::default();
    let module = Module::from_file(&store, &wasm_bin)?;

    let host_print_sig = FunctionType::new(vec![Type::I32], vec![]);
    let host_print_func = Function::new(&mut store, &host_print_sig, |args| {
        let result = args[0].unwrap_i32();
        println!("{}", result);

        // Ok(vec![Value::I32(result)])
        Ok(vec![])
    });

    println!("[+] Creating imports");

    let import_obj = imports! {
        "env" => {
            "print" => host_print_func,
        },
    };

    println!("[+] Instantiating module");

    let instance = Instance::new(&mut store, &module, &import_obj)?;

    Ok(instance)
}

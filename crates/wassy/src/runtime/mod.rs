use wasmer::{imports, Function, Instance, Module, Store};
// use wasmer_compiler_cranelift::Cranelift;
// use wasmer_engine_jit::JIT;

fn host_print(i: i32) {
    println!("{}", i);
}

pub fn create_runtime() -> Result<Instance, Box<dyn std::error::Error>> {
    let module_wat = r#"
    (module
    (type $t0 (func (param i32) (result i32)))
    (func $add_one (export "add_one") (type $t0) (param $p0 i32) (result i32)
        get_local $p0
        i32.const 1
        i32.add))
    "#;
    let mut store = Store::default();
    let module = Module::new(&store, &module_wat)?;

    let import_obj = imports! {
        "env" => {
            "host_print" => Function::new_typed(&mut store, host_print),
        },
    };

    let instance = Instance::new(&mut store, &module, &import_obj).unwrap();

    Ok(instance)
}

use wasabi_wasm::Data;
use wasabi_wasm::ImportOrPresent::Present;
use wasabi_wasm::LoadOp::I32Load;
use wasabi_wasm::Memory;
use wasabi_wasm::Module;
use wasabi_wasm::Val;
use wasabi_wasm::Val::I32;
use wasabi_wasm::{Code, Instr::*};

pub fn monitor_test(module: &mut Module) {
    for (func_idx, func) in module.clone().functions() {
        println!("func_idx: {:?}", func_idx);
        println!("func: {:?}", func);
    }
}

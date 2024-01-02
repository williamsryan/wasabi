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

pub fn dummy_log() {
    println!("dummy log");
}

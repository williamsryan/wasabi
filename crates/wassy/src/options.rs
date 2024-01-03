use std::path::PathBuf;

use enumset::EnumSet;
use enumset::EnumSetType;
use serde::Deserialize;
use serde::Serialize;

use clap::Parser;

/// [TBD Project Name]: compiler passes for hardening Wasm binaries
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Options {
    /// WebAssembly binary to instrument
    #[arg(value_name = "input.wasm")]
    pub input_file: PathBuf,

    /// Generate JavaScript code for inclusion in Node.js, not the browser
    #[arg(short = 'n', long = "node")]
    pub node_js: bool,

    /// Output directory (created if it does not exist)
    #[arg(short = 'o', long = "output-dir", default_value = "./out/")]
    pub output_dir: PathBuf,

    /// Instrumentations to apply
    #[arg(long = "hooks", num_args(0..))]
    pub hooks: Vec<Hook>,
}

// Derive parsing, pretty-printing, and convenience like getting all variants of the enum.
#[derive(Debug, Serialize, Deserialize, EnumSetType)]
#[serde(rename_all = "snake_case")]
/// High-level hook names, modulo minor changes:
/// - no trailing underscores (originally to avoid clashes with JavaScript keywords)
pub enum Hook {
    Start,

    Nop,
    Unreachable,

    Br,
    BrIf,
    BrTable,

    If,
    Begin,
    End,

    // together for call_pre and call_post
    Call,
    PointerHardening,
    Return,

    Drop,
    Select,

    Const,
    Unary,
    Binary,

    Load,
    Store,
    WriteProtection,
    // Just a test for logging the memory access.
    StoreUsage,

    MemorySize,
    MemoryGrow,

    Local,
    Global,
}

// Use serde_plain for parsing strings to enum variants.
impl std::str::FromStr for Hook {
    type Err = serde_plain::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_plain::from_str(s)
    }
}

// Offers convenient HookSet::all() method.
pub type HookSet = EnumSet<Hook>;

use std::fs;
use std::io;

use main_error::MainError;
use wasabi_wasm::Module;

use clap::Parser;

use wassy::instrument::add_hooks;
use wassy::options::HookSet;
use wassy::options::Options;

use wassy::runtime::create_runtime;

fn main() -> Result<(), MainError> {
    // TODO: use clap as our CLI since we're moving away from Wasabi.
    let args = Options::parse();

    let enabled_hooks = if args.hooks.is_empty() {
        // If --hooks is not given, everything shall be instrumented.
        HookSet::all()
    } else {
        let mut enabled_hooks = HookSet::new();
        for hook in args.hooks {
            // dbg!("TEST: {}", hook);
            enabled_hooks.insert(hook);
        }
        enabled_hooks
    };
    // for hook in args.no_hooks {
    //     enabled_hooks.remove(hook);
    // }

    let input_filename = args
        .input_file
        .file_name()
        .ok_or_else(|| io_err("invalid input file, has no filename"))?;
    let output_file_wasm = args.output_dir.join(input_filename);
    // let output_file_wasabi_js = output_file_wasm.with_extension("wasabi.js");

    // instrument Wasm and generate JavaScript
    let (mut module, _offsets, _warnings) = Module::from_file(args.input_file)?;
    if module.metadata.used_extensions().next().is_some() {
        return Err(io_err(
            "input file uses Wasm extensions, which are not supported yet by Wasabi",
        )
        .into());
    }
    // let (_js, hook_count) = add_hooks(&mut module, enabled_hooks, args.node_js).unwrap();
    let hook_count = add_hooks(&mut module, enabled_hooks).unwrap();
    println!("inserted {hook_count} low-level hooks");

    // write output files
    fs::create_dir_all(&args.output_dir)?;
    module.to_file(output_file_wasm)?;

    // TODO: use runtime from wasmer to provide host functions.


    Ok(())
}

// TODO remove after proper error handling
fn io_err(str: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, str.to_string())
}

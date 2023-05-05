// Hook-style instrumentation, analysis happens in callbacks, i.e., added function imports.
pub mod add_hooks;
pub use self::instrument::add_hooks;

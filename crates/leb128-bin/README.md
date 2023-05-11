# `leb128` Commandline Utility

Useful for quick conversion between decimal numbers and LEB128 (Little Endian Base 128) format.
E.g., for debugging parsing numbers in WebAssembly binaries.

LEB 128 (a variable-length code compression) is used in Wasm binary encoding for _all_ integer literals (unsigned or signed).


$$uN ::= n:byte \Rightarrow n      (\mathrel{if} n < 2^7 \wedge n < 2^N) \\
| n:byte m:u(N-7)   \Rightarrow 2^7\cdot m + (n-2^7) (\mathrel{if} n \geq 2^7 \wedge N > 7) $$

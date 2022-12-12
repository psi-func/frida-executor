/* 
    frida-executor - frida agent instrumentation

    Written by Maksim Shalagin <shalaginmx998@yandex.ru>

    Copyright 2022 Maksim Shalagin. All rights reserved.
*/

const TARGET_MODULE = "test_empty";
const TARGET_FUNCTION = DebugSymbol.getFunctionByName("target_func");
const RET_TYPE = "void"
const ARGS_TYPES = ["pointer", "int"] ;

let func_handle = new NativeFunction(TARGET_FUNCTION, RET_TYPE, ARGS_TYPES, { traps: 'all' });

// Define to exclude all other than target_module
export let target_module  = TARGET_MODULE;
// harness function
export let fuzzer_test_one_input = function(payload) {
    let payload_mem = payload.buffer.unwrap();
    
    func_handle(payload_mem, payload.length);

}

console.log(" >> Agent loaded!")


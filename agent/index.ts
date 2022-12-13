/* 
    frida-executor - frida agent instrumentation

    Written by Maksim Shalagin <shalaginmx998@yandex.ru>

    Copyright 2022 Maksim Shalagin. All rights reserved.
*/

import "./executor.js";

const TARGET_MODULE = "test-linux";
const TARGET_FUNCTION = DebugSymbol.getFunctionByName("target_func");
const RET_TYPE = "int";
const pointer_type: NativeFunctionArgumentType = "pointer" as const;
const int_type: NativeFunctionArgumentType = "int" as const;

let func_handle = new NativeFunction(TARGET_FUNCTION, RET_TYPE, [pointer_type, int_type], { traps: 'all' });

// Define to exclude all other than target_module
export let target_module  = TARGET_MODULE;
// harness function
export let fuzzer_test_one_input = function(payload: Uint8Array) {
    let payload_mem = (payload.buffer as ArrayBuffer).unwrap() ;
    
    func_handle(payload_mem, payload.length);

}

console.log(" >> Agent loaded!")

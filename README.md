# Simple frida executor

Serves to get edge coverage via python frida core API

instrumentation backend implemented in Typescript frida API

## How to use me

setup frida agent in `agent/index.ts`:

```ts
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

```

Provide target module in executable program, target function to start coverage with and type of that function

Compile frida agent script with npm:

```sh
npm install
npm run build # now `agent.js` in root directory 
```

Run with python frida API

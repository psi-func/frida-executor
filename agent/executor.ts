/* 
    frida-executor - frida agent instrumentation

    Written by Maksim Shalagin <shalaginmx998@yandex.ru>

    Copyright 2022 Maksim Shalagin. All rights reserved.
*/

import { TRACE_BITS } from "./bitmap.js";
import { MAP_SIZE, MAX_FILE, TIMEOUT } from "./config.js";
import { fuzzer_test_one_input, target_module } from "./index.js";
import { start_tracing } from "./instrumentor.js";
import { hex_to_arrbuf } from "./utils.js";


const zeroed_bits : number[] = new Array(MAP_SIZE);

const run_coverage = (buf: ArrayBuffer, callback: any) => {
    // cleanup before execute
    TRACE_BITS.writeByteArray(zeroed_bits);
    
    const ts_0 = (new Date()).getTime();

    try {
        callback(buf);
    }
    catch (err: any) {
        // error occuried
        // crash observer
        if (err.type !== undefined) {
            send({
                "event": "crash",
                "err": err,
            }, buf);
        }
        else if (err.$handle != undefined){
            send({
                "event": "exception",
                "err": err,
            })
        }
        throw err;
    }

    const ts_1 = (new Date().getTime());

    const exec_ms = ts_1 - ts_0;

    if (exec_ms > TIMEOUT) {
        // timeout observer
        send({
            "event": "crash",
            "err": {"type": "timeout"},
        }, buf);
        throw "timeout";
    }

    // send map + exec time as event
    send({
        "event": "ec",
        "exec_ms": exec_ms,
    }, TRACE_BITS.readByteArray(MAP_SIZE));

    return null;
}

export const executor_loop = () => {
    let payload : Uint8Array | null = null;

    const runner = (arr_buf : ArrayBuffer) => {

        if (arr_buf.byteLength > MAX_FILE)
            payload = new Uint8Array(arr_buf.slice(0, MAX_FILE));
        else 
            payload = new Uint8Array(arr_buf);

        fuzzer_test_one_input(payload);
    };

    // set exception handler if crashed
    Process.setExceptionHandler((exception: ExceptionDetails) => {
        // send message to client as json
        send({
            "event": "crash",
            "err": exception,
        }, payload?.buffer as ArrayBuffer);

        // terminate process
        return false;
    });

    start_tracing(Process.getCurrentThreadId(), target_module);
    
    console.log(" >> Setup complete...");

    // executor cycle
    while (true) {
        // wait for input
        send({
            "event": "ready",
        });

        let buf : ArrayBuffer | null = null;

        let op = recv("input", (msg) => {
            if (msg.buf == null) {
                buf = null;
                return;
            }
            buf = hex_to_arrbuf(msg.buf);
        });

        op.wait();
        // run harness
        if (buf !== null ) run_coverage(buf, runner);
    }

};



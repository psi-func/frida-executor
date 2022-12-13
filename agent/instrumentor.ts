/* 
    frida-executor - frida agent instrumentation

    Written by Maksim Shalagin <shalaginmx998@yandex.ru>

    Copyright 2022 Maksim Shalagin. All rights reserved.
*/

import { TRACE_BITS } from "./bitmap.js";
import { MAP_SIZE } from "./config.js";

// trust threshold must be 0
Stalker.trustThreshold = 0;

const ignore_libs = ["libc", "libSystem", "frida"];

let start_addr = ptr(0);
let end_addr = ptr("-1");

export let prev_loc_map = new Map<ThreadId, NativePointer>;

export const start_tracing = (thread_id: ThreadId, target_module: string | Module | null) => {

    let maps = function () {
        let maps = Process.enumerateModules();
        let i = 0;

        return maps;
    }();
    

    if (target_module !== null) {
        maps.forEach((m) => {
            let msg = ["Found module:", m.name, m.base, "size:", m.size].join(' ');

            if (m.name == target_module || m == target_module) {
                start_addr = m.base;
                end_addr = m.base.add(m.size);
                msg += ' included (+)';
            }
            else {
                Stalker.exclude(m);
                msg += ' excluded (-)';
            }
            console.log(msg);
        });
    } else {
        maps.forEach((m) => {
            let msg = ["Found module:", m.name, m.base, "size:", m.size].join(' ');

            if (ignore_libs.some((ignored_libname) => { m.name.startsWith(ignored_libname) })) {
                Stalker.exclude(m);
                msg += ' excluded (-)';
            }
            else {
                msg += ' included (+)';
            }
            console.log(msg);
        });
    }

    let prev_loc_ptr = prev_loc_map.get(thread_id) ?? Memory.alloc(32);
    prev_loc_map.set(thread_id, prev_loc_ptr);

    let transform = undefined;

    if (Process.arch == "x64") {
        // Fast inline instrumentation for x86_64
        const transform_x64 = (iterator: StalkerX86Iterator) => {
            let i = iterator.next();
        
            let cur_loc = i?.address ?? ptr(0);
        
            if (cur_loc.compare(start_addr) > 0 &&
            cur_loc?.compare(end_addr) < 0) {
        
                cur_loc = cur_loc?.shr(4).xor(cur_loc.shl(8));
                cur_loc = cur_loc.and(MAP_SIZE - 1);
        
                iterator.putPushfx();
                iterator.putPushReg("rdx");
                iterator.putPushReg("rcx");
                iterator.putPushReg("rbx");
        
                // rdx = cur_loc
                iterator.putMovRegAddress("rdx", cur_loc);
                // rbx = &prev_loc
                iterator.putMovRegAddress("rbx", prev_loc_ptr);
                // rcx = *rbx
                iterator.putMovRegRegPtr("rcx", "rbx");
                // rcx ^= rdx
                iterator.putXorRegReg("rcx", "rdx");
                // rdx = cur_loc >> 1
                iterator.putMovRegAddress("rdx", cur_loc.shr(1));
                // *rbx = rdx
                iterator.putMovRegPtrReg("rbx", "rdx");
                // rbx = bitmap.trace_bits
                iterator.putMovRegAddress("rbx", TRACE_BITS);
                // rbx += rcx
                iterator.putAddRegReg("rbx", "rcx");
                // (*rbx)++
                iterator.putU8(0xfe); // inc byte ptr [rbx]
                iterator.putU8(0x03);
            
                iterator.putPopReg("rbx");
                iterator.putPopReg("rcx");
                iterator.putPopReg("rdx");
                iterator.putPopfx();
        
            }

            do iterator.keep()
            while ((i = iterator.next()) !== null);
        }

        transform = transform_x64;
    }

    Stalker.follow(thread_id, {
        events: {
            call: false,
            ret: false,
            exec: false,
            block: false,
            compile: true,
        },
        transform: transform,
    });

}


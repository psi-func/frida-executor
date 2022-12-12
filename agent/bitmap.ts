/* 
    frida-executor - frida agent instrumentation

    Written by Maksim Shalagin <shalaginmx998@yandex.ru>

    Copyright 2022 Maksim Shalagin. All rights reserved.
*/


import { MAP_SIZE } from "./config";

export let TRACE_BITS = Memory.alloc(MAP_SIZE);
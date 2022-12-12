# example of usage frida_agent.js

import frida
import base64
import os
import sys
import time
import signal
import queue

TARGET = "test_empty"
SCRIPT = "agent.js"

input_queue = queue.Queue(10)

with open(TARGET, 'rb') as f:
    b = f.read()
    input_queue.put(b)

def readable_time(t):
    t /= 1000 # ms
    h = t // 60 // 60
    m = t // 60 - h * 60
    s = t - m * 60 - h * 60 * 60
    return "%dh-%dm-%ds" % (h, m, s)

def get_cur_time(): # ms
    return int(round(time.time() * 1000))

def report_error(message):
    print (" ============= EXECUTOR ERROR! =============")
    if "lineNumber" in message and message["lineNumber"] is not None:
        print ("  line %d: %s" % (message["lineNumber"], message["description"]))
    else:
        print ("  %s" % message["description"])
    if "stack" in message:
        print ("  JS stacktrace:\n")
        print (message["stack"])
    print ("")

def on_ready(message, data):
    global input_queue
      
    buf = input_queue.get(block=True)
    
    script.post({
        "type": "input",
        "buf" : buf.hex()
    })
    print("")
    
def on_ec(message, data):
    
    with open("ec.test", 'wb') as f:
        f.write(data)

# executor setup
with open(SCRIPT, 'r') as f:
    code = f.read()

pid = frida.spawn(TARGET, stdio="pipe")
session = frida.attach(pid)

script = session.create_script(code, runtime="v8")

def on_message(message, data):
    print(message)
    if message["type"] == "error":
        report_error(message)
        print (" >> Killing", pid)
        os.kill(pid, signal.SIGKILL)
        print (" >> Press Control-C to exit...") 
        script.unload()
        session.detach()
    msg = message["payload"]
    if msg['event'] == 'ready':
        on_ready(msg, data)

script.on('message', on_message)

script.load()

# graceful shutdown
def signal_handler(sig, frame):
    global pid
    print (" >> Exiting...")
    print (" >> Killing", pid)
    os.kill(pid, signal.SIGKILL)
    try:
        script.unload()
        session.detach()
    except: 
        pass
    os._exit (0)
signal.signal(signal.SIGINT, signal_handler)


# wait
sys.stdin.read()
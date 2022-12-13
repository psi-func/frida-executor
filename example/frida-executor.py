# example of usage frida_agent.js

import frida
import base64
import os
import sys
import time
import signal

TARGET = "test/test-linux"
SCRIPT = "agent.js"

print(os.getcwd())

output_folder = "frida_out"
os.makedirs(output_folder, exist_ok=True)

def readable_time(t):
    t /= 1000 # ms
    h = t // 60 // 60
    m = t // 60 - h * 60
    s = t - m * 60 - h * 60 * 60
    return "%dh-%dm-%ds" % (h, m, s)

def get_cur_time(): # ms
    return int(round(time.time() * 1000))

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
    elif msg['event'] == 'crash':
        on_crash(msg, data)
    elif msg['event'] == 'exception':
        on_exception(msg, data)
    elif msg['event'] == 'ec':
        on_ec(msg, data)

def on_ready(message, data):
    print("")
    
def on_ec(message, data):
    
    with open("ec.test", 'wb') as f:
        f.write(data)

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

def on_crash(message, data):
    global script, session, pid
    print ("\n"*2 + "  ============= CRASH FOUND! =============")
    print ("    type:", message["err"]["type"])
    if "memory" in message["err"]:
        print ("    %s at:" % message["err"]["memory"]["operation"], message["err"]["memory"]["address"])
    print ("")
    t = int(time.time())
    name = os.path.join(output_folder, "crash_%s_%d" % (message["err"]["type"], t))
    
    print (" >> Saving at %s" % repr(name))
    with open(name, "wb") as f:
        f.write(data)
    
    print (" >> Killing", pid)
    os.kill(pid, signal.SIGKILL)
    
    print (" >> Press Control-C to exit...")
    script.unload()
    session.detach()

def on_exception(message, data):
    global script, session, pid
    print ("\n"*2 + "  =========== EXCEPTION FOUND! ===========")
    print ("    message:", message["err"])
    print ("")
    t = int(time.time())
    name = os.path.join(output_folder, "exception_%d" % (t))
    
    print (" >> Saving at %s" % repr(name))
    with open(name, "wb") as f:
        f.write(data)
    
    print (" >> Killing", pid)
    os.kill(pid, signal.SIGKILL)
    print (" >> Press Control-C to exit...")
    script.unload()
    session.detach()

script.on('message', on_message)
script.load()

# graceful shutdown
def signal_handler(sig, frame):
    global pid
    print (" >> Exiting...")
    print (" >> Killing", pid)
    try:
        script.unload()
        session.detach()
        os.kill(pid, signal.SIGKILL)
    except: 
        pass
    os._exit(0)
signal.signal(signal.SIGINT, signal_handler)


try:
    script.exports.callExecutorStartup()
except (frida.core.RPCException, frida.InvalidOperationError) as e:
    try:
        print(e)
    except:
        pass
    exit(1)

try:
    script.exports.callExecutorOnce(bytes([0x01, 0x44]).hex())
    script.exports.callExecutorOnce(bytes([0xfe, 0x44, 0, 0, 0xf0]).hex())
    script.exports.callExecutorOnce(bytes([0x01, 0x44]).hex())
except :
    pass

# wait
sys.stdin.read()
from maat import *
import lief
import struct

INPUTVAL=-1

# init
path = "./guessnum"
eng = MaatEngine(ARCH.X64, OS.LINUX)
eng.settings.log_insts = True

elf = lief.parse(path)

symbs = {x.name: x.value for x in elf.symbols if x.value != 0 and x.name != ""}

eng.load(path, BIN.ELF64)

# setup call to target with arg

eng.cpu.rip = symbs["target"]

rsp = eng.cpu.rsp.as_uint()
rsp -= 8
eng.cpu.rsp = rsp

# put a return addr to stop at
retaddr = symbs["frame_dummy"]
eng.hooks.add(EVENT.EXEC, WHEN.BEFORE, filter=retaddr)
eng.mem.write(eng.cpu.rsp, retaddr, 8)

# variable input
varname = "input"
eng.vars.set(varname, INPUTVAL)
eng.cpu.rdi = Var(64, varname)

# set up hooks
def path_hook(eng):
    print(f"Path event @ {eng.info.addr:x}")
    b = eng.info.branch
    
    # invert this condition and output a new input
    s = Solver()
    for c in eng.path.constraints():
        s.add(c)

    # add constraint that would go the other way
    c = b.cond
    if b.taken:
        c = c.invert()
    s.add(c)

    if not s.check():
        print("Ran into unreachable path")
    else:
        m = s.get_model()
        v = m.get(varname)
        intval = struct.unpack("<i", struct.pack("<I", v))[0] # trick to get a signed int from the output
        print(f"Try input as: 0x{v:x} ({intval})")

    return ACTION.CONTINUE

eng.hooks.add(EVENT.PATH, WHEN.BEFORE, callbacks=[path_hook])

# run
stop = eng.run()

if stop != STOP.HOOK:
    print(f"Unexpected stop {stop}")

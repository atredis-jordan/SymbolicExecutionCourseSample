from re import I
from maat import *
import subprocess
import lief
import sys

def path_hook(eng):
    b = eng.info.branch

    # solve for an input that would take us down the other way
    s = Solver()
    for c in eng.path.constraints():
        s.add(c)

    c = b.cond
    if b.taken:
        c = c.invert()

    s.add(c)

    if s.check():
        m = s.get_model()
        print(m.get("input_int"))
    else:
        print("Dead code!")


def init():
    path = "./guessnum"

    eng = MaatEngine(ARCH.X64, OS.NONE)
    eng.settings.symptr_write = False # make crash if concrete part would do bad access
    eng.settings.symptr_read = False
    eng.settings.log_insts = True

    eng.load(path, BIN.ELF64)

    elf = lief.parse(path)

    # find all the needed addrs
    symbs = {x.name: x.value for x in elf.symbols if x.value != 0 and x.name != ""}

    # set up call to main (no args)
    eng.cpu.rip = symbs["target"]

    arg = int(sys.argv[1])
    name = "input_int"
    eng.vars.set(name, arg)
    eng.cpu.rdi = Var(64, name)

    # set up a return value on the stack
    rsp = eng.cpu.rsp.as_uint()
    end_addr = symbs["_fini"]
    eng.mem.write(rsp, end_addr, 8)

    # add a hook for the return addr
    eng.hooks.add(EVENT.EXEC, WHEN.BEFORE, filter=end_addr)

    eng.hooks.add(EVENT.PATH, WHEN.BEFORE, callbacks=[path_hook])

    return eng

def main():
    eng = init()

    stop = eng.run()
    if stop != STOP.HOOK:
        print("Got unexpected stop {stop}")
        exit(-1)

    print("Done")

if __name__ == '__main__':
    main()

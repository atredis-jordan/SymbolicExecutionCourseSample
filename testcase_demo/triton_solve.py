from triton import *
import struct
import lief

INPUTVAL=-1

# Init
path = "./guessnum"

# load the file into Triton
ctx = TritonContext(ARCH.X86_64)

elf = lief.parse(path)

loadable = [x for x in elf.segments if x.type == lief.ELF.SEGMENT_TYPES.LOAD]

for s in loadable:
    va = s.virtual_address
    b = bytes(s.content)
    ctx.setConcreteMemoryAreaValue(va, b)

# set up execution of the target
symbs = {x.name: x.value for x in elf.symbols if x.value != 0 and x.name != ""}

rip = symbs["target"]
ctx.setConcreteRegisterValue(ctx.registers.rip, rip)

# just a random addr to know when we return
retaddr = symbs["frame_dummy"]

rsp = 0x7ffffff08
ctx.setConcreteRegisterValue(ctx.registers.rsp, rsp)

ctx.setConcreteMemoryValue(MemoryAccess(rsp, 8), retaddr)

# symbolize the input argument
ctx.setConcreteRegisterValue(ctx.registers.rdi, INPUTVAL & 0xffffffff)
ctx.symbolizeRegister(ctx.registers.rdi, "input_var")

# execute the trace
while rip != retaddr:
    opcodes = ctx.getConcreteMemoryAreaValue(rip, 15)

    inst = Instruction(rip, opcodes)

    if EXCEPTION.NO_FAULT != ctx.processing(inst):
        raise Exception(f"Unknown instruction at 0x{rip:x}: {inst}")

    print(inst)

    rip = ctx.getConcreteRegisterValue(ctx.registers.rip)

# solve for diverting inputs
astctx = ctx.getAstContext()

path = astctx.equal(astctx.bvtrue(), astctx.bvtrue())

for c in ctx.getPathConstraints():
    for b in c.getBranchConstraints():
        if b['isTaken']:
            continue
        # generate an input that would have taken us this way
        # note: that this is a great place for target specific
        # optimizations like keeping a address tree or something
        # by Triton not having snapshots, we will be invoking the
        # solver for branches we have already solved for

        m, status, _ = ctx.getModel(astctx.land([path, b['constraint']]), True)
        if status != SOLVER_STATE.SAT:
            print("Unsatisfiable path found")
        else:
            inval = m[ctx.getSymbolicVariable("input_var").getId()].getValue()
            intval = struct.unpack("<i", struct.pack("<I", inval))[0]
            print(f"Try input = 0x{inval:x} ({intval})")

    # add to our existing path constraints as we go deeper in the path
    path = astctx.land([path, c.getTakenPredicate()])

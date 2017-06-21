from pydbg import *
from pydbg.defines import *

import struct
import random

# user defined callback function

def printf_randomizer(dbg):

    # read in the value of the counter at ESP + 0x8 as a DWORD
    parameter_addr = dbg.context.Esp + 0x8
    counter = dbg.read_process_memory(parameter_addr, 4)

    # when we use read_process_memory, it returns a packed binary
    # string, it must be unpacked before further use
    counter = struct.unpack("L", counter)[0]
    print "Counter : %d" % int(counter)

    # generate a binary number and pack it into binary format
    # so that it is written correctly back into the process
    random_counter = random.randint(1,100)
    random_counter = struct.pack("L", random_counter)[0]

    # swap in random number and resume the process
    dbg.write_process_memory(parameter_addr, random_counter)

    return DBG_CONTINUE

# instantiate the pydbg class
dbg = pydbg()

# now enter the PID of the printf_loop.py process
pid = raw_input("Enter the printf_loop.py PID: ")

# attach the debugger to process
dbg.attach(int(pid))

# set the breakpoint with the printf_randomizer function
# defined as callback

printf_address =dbg.func_resolve("msvcrt", "printf")
dbg.bp_set(printf_address, description = "printf_address", handler = printf_randomizer)

# resume the process
dbg.run()

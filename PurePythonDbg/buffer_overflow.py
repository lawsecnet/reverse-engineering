from ctypes import *

msvcrt = cdll.msvcrt

# give debugger time to attach
raw_input("Press any key after attaching debugger")

# Create the 5-byte destination buffer
buffer = c_char_p("AAAAA")

# the overflow string
overflow = "A" * 100

# Overflow!
msvcrt.strcpy(buffer, overflow)

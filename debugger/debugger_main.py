from ctypes import *
from debugger_define import *

kernel32 = windll.kernel32

class debugger():

    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False
        self.h_thread = None
        self.context  = None
        self.breakpoints = {}
        self.first_breakpoint = True
        self.hardware_breakpoints = {}

        # determines and stores dedault page size for the system
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

        self.guarded_pages = []
        self.memory_breakpoints = {}

    def load(self, path_to_file):
        # dwCreation flag determines how to create process
        creation_flags = DEBUG_PROCESS

        # initationg the structs
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION

        # starting process in separate window
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        # initiazlizing cb variable in the STARTUPINFO struct
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessA(path_to_file, None, None, None, None,
        creation_flags, None, None, byref(startupinfo), byref(process_information)):

            print "Process launch successfull !!!"
            print "> PID: %d" % process_information.dwProcessId

        else:
            print "[-] Error: 0x%08x." % kernel32.GetLastError()

        self.h_process = self.open_process(process_information.dwProcessId)

    def open_process(self, pid):

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, pid, False)

    def attach(self, pid):

        self.h_process = self.open_process(pid)

        # attempt to attach to the process or exit the call
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
            self.run()

        else:
            print "[-] Unable to attach to the process"

    def run(self):

        # poll the debugee for debugging events

        while self.debugger_active == True:
            self.get_debug_event()

    def get_debug_event(self):

        if self.exception == EXCEPTION_ACCESS_VIOLATION:
            print "Access violation detected"
        elif self.exception == EXCEPTION_BREAKPOINT:
            continue_status = self.exception_handler_breakpoint()
        elif self.exception == EXCEPTION_GUARD_PAGE:
            print "Guard page access detected"
        elif self.exception == EXCEPTION_SINGLE_STEP:
            self.exception_handler_single_step()

        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEVENT(bref(debug_event), INFINITE):

            # obtain thread and context information
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(self.h_thread)

                print "Event Code: %d Thread ID: %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId)

            # if the event is an exception, examine further

            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:

                # exception Code
                exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception.address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

            if exception == EXCEPTION_ACCESS_VIOLATION:
                print "Access violation detected"

                #in case of breakpoint, call internal handler

            elif exception == EXCEPTION_BREAKPOINT:
                continue_status = self.exception_handler_breakpoint()

            elif ec == EXCEPTION_GUARD_PAGE:
                print "Guard Page Access detected"

            elif ec == EXCEPTION_SINGLE_STEP:
                print "Single stepping"

            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

    def detach(self):

        if kernel32.DebugActiveProcessStop(self.pid)
            print "[*] Debugging finished. Exiting."
            return True
        else:
            print "Error occured"
            return False


    def open_thread (self, thread_id):

        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if h_thread is not None:
            return h_thread

        else:
            print "[8] Could not obtain a valid thread handle"
            return False

        def enumerate_threads(self):

            thread_entry = THREADENTRY32()

            thread_list = []
                snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

            if snapshot is not None:
                # setting size of struct
                thread_entry.dwSize = sizeof(thread_entry)
                    success = kernel32.Thread32First(snapshot, byref(thread_entry))

                kernel32.CloseHandle(snapshot)
                return thread_list
            else:
                return False

        def get_thread_context (self, thread_id):

            context = CONTEXT()
            context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

            # Obtain a handle to the thread_id
            h_thread = self.open_thread(thread_id)
            if kernel32.GetThreadContext(h_thread, byref(context)):
                kernel32.CloseHandle(h_thread)
                return context
            else:
                return False

    def exception_handler_breakpoint():

            print "[*] Inside the breakpoint handler"
                print "Exception Address: 0x%08x" % self.exception_address

            return DBG_CONTINUE

    def read_process_memory(self, address, length):

        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)

        if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):

            return False

        else:

            data += read_buf.raw
            return data

    def write_process_memory(self, address, data):

        count = c_ulong(0)
        length = len(data)

        c_data = c_char_p(data[count.value:])

        if not kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):

            return False

        else:
            return True

    def bp_set(self, address):

        if not self.breakpoints.has_key(address):
            try:

                # store the original BYTE
                original_byte = self.read_process_memory(address, 1)

                # write the INT3 opcode
                self.write_process_memory(address, "\xCC")

                # register the breakpoint in our internal list
                self.breakpoints[address] = (address, original_byte)

            except:

                return False

        return True

    def func_resolve(self, dll, function):

        handle = kernel32.GetModuleHandle
        address= kernel32.GetProcAddress(handle, function)

        kernel32.CloseHandle(handle)

        return address

    def bp_set_hw(self, address, length, condition):

        # check for valid length value
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1

        # check for valid confition
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False

        # check for available slots
        if not self.hardware_breakpoints.has_key(0):
            available = 0
        elif not self.harware_breakpoints.has_key(1):
            available = 1
        elif not self.harware_breakpoints.has_key(2):
            available = 2
        elif not self.harware_breakpoints.has_key(3):
            available = 3
        else:
            return False

        # we want to set the debug register in every thread
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id = thread_id)

            # enable the appropriate flag in the DR7
            # register to set the breakpoints
            context.Dr7 |= 1 << (available * 2)

        # save the address of thebreakpoint in the free register found
        if available == 0:
            context.Dr0 = address
        elif available == 1:
            context.Dr1 = address
        elif available == 2:
            context.Dr2 = address
        elif available == 3:
            context.Dr3 = address

        # set the breakpoint condition
        context.Dr7 |= condition << ((available * 4) + 16)

        # set the length
        context.Dr7 |= << ((available * 4) + 18)

        # set thread context with the break set
        h_thread = self.open_thread(thread_id)
        kernel32.SetThreadContext(h_thread, byref(context))

        # update the internal hardware breakpoint array at the used slot index
            self.harware_breakpoints[available] = (address, length, condition)

            return True

    def exception_handler_single_step(self):

        # determine if this single step event occured in reaction to
        # to a hardware breakpoint and grab the hit breakpoint
        # according to Intel documentation, we should be able to check for
        # BS flag in Dr6, however it appears that Windows isn't
        # properly propagating the flag down.

        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot = 1
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            slot = 2
        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            slot = 3

        else:
            # that wasn't an INT1 generated by hw breakpoint

            continue_status = DBG_EXCEPTION_NOT_HANDLED

        # remove breakpoint from the list

        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE

        print "[-] Hardware breakpoint removed"
        return continue_status

    def bp_del_hw(self, slot):

        # disable the breakpoint for all active threads
        for thread_id in self.enumerate_threads():

            context = self.get_thread_context(thread_id = thread_id)

            # reset flags to remove breakpoint
            context.Dr7 &= ~(1 << (slot *2))

            # zero out the address
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr4 = 0x00000000

            # remove the condition flag
            context.Dr7 &= ~(3 << (slot * 4) + 16)

            # remove the length flag
            context.Dr7 &= ~(3 << (slot * 4) + 18)

            # reset the thread's context with the breakpoint removed
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        # remove breakpoint from internal list
        del self.hardware_breakpoints[slot]

        return True

    def bp_set_mem(self, address, size):

        mbi = MEMORY_BASIC_INFORMATION()

        # if VirtualQueryEx() call doesnt reurin full sized memory basic information
        # return False
        if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            return False

        current_page = mbi.BaseAddress

        # set permissions on all pages that are affected by our breakpoint
        while current_page <= address + size:

            # add the page to the list, which will differentiate guarded pages
            # from those setup by the OS or debugee process
            self.guarded_pages.append(current_page)

            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.h_process, current_page, size, mbi.Protect | PAGE_GUARD, byref(old_protection)):
                return False

            # increase range by the size of teh default system memory page size
            current_page += self.page_size

        # add the memory breakpoint to global list
        self.memory_breakpoints[address] = (address, size, mbi)

        return True

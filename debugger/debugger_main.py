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
        self.exception = None
        self.exception_address = None

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

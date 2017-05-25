import debugger_main

pid = raw_input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))

list = debugger.enumerate_threads()

# grab value of each of the register for each thread

for thread in list:

    thread_context = debugger.get_thread_context(thread)

    # output content of the registers

    print "[*] Dumping registers for thread ID: 0x%08x" % thread
    print "[**] EIP: 0x%08x" % thread_context.Eip
    print "[**] EsP: 0x%08x" % thread_context.Esp
    print "[**] EbP: 0x%08x" % thread_context.Ebp
    print "[**] EAX: 0x%08x" % thread_context.Eap
    print "[**] EBX: 0x%08x" % thread_context.Ebp
    print "[**] ECX: 0x%08x" % thread_context.Ecp
    print "[**] EDX: 0x%08x" % thread_context.Edp
    print "[*] END DUMP"

debugger.detach()

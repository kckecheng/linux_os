=================================
Linux System Call Introduction
=================================

This document tries to explain the basic knowledge about linux system call.

**Notes**: all information in this document is based on x86_64.

User Space and Kernel Space
------------------------------

User space and kernel space refer to virtual address space splitting.

Virtual Address Space
~~~~~~~~~~~~~~~~~~~~~~~~

The physical memory in a computer system is always limited, processes need to share the expensive resource efficiently to improve system performance. In the meanwhile, different hardware architectures implement different memory details, including addressing, reservation, etc. These complexities make using physical memory directly not suitable, Linux developed virtual memory as a solution.

The virtual memory abstraces memory access details for different architectures with a consolidated view, and delivers the capability of keeping only needed information in the physical memory to improve memory usage efficiency. In the meanwhile, additional features required by processes, such as memory sharing, access control, etc. are achived more easily and straightforward with virtual memory.

With virtual memory, every process uses virtual addresses within its own virtual address space. While a process is running, its program code, data, dynamically provisioned memory, stacks, etc. are addressing within its virtual address space. Since the addressing can be achived by using a single integer, a virtual address space is also called as a virtual linear address space interchagbly.

**Notes**: The virtual address space addressing varies based on hardware architectures: for x86_32, it is 4GB(32 bits addressing); for x86_64, it may be 256TB(PML4, 48 bits addressing) or even 64PB(PML5, 56 bits addressing) depends on how many bis are used for memory addressing. The detailed implementaion of virtual memory and virtual address space will be covered with the memory management document.

Logical Address
~~~~~~~~~~~~~~~~~

To improve the efficiency of translating virtual addresses to physical addresses, x86 architectured CPU ships with a memory management unit(MMU for short). A MMU consists of a segmentation unit and a paging unit. The paging unit is responsible for translating virtual addresses to physical addresses, while the segmentation unit adds one more feature named segmentation(the ability dividing a virtual adrress space into memory segments) to virtual memory management.

A memory segment defines a memory size and a starting address as its base in the virtual address space. All virtual addresses from base to (base + size) can be addressed by giving a segment base and an offset to the base, this is called logical addressing, and the address used is like (segment base):(segment offset) which is called logical address.

The relationship of logical address, virtual address and physical address can be summarized as below:

**Logical Address ---> MMU Segmentation Unit ---> Virtual Address ---> MMU Paging Unit ---> Physical Address**

**Notes**:

- The segmentation unit of x86 architectured CPU was implemented back to the time when CPU was not able to address the full physical memory space(The details will be introduced in the memory management document). Nowadasys, x86_64 CPU is able to address hundreds of TB even PB memory, segmentation is not needed at all - but it is still used(have to be used since the segmentation unit in MMU cannot be disabled) for some limited features;
- Some tools such as objdump can be used to display section information from ELF binaries;

User Space and Kernel Space
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When an application is executed, it is always better to keep similar objects(instructions, data, stacks, etc.) adjacent to each other than spread them ramdomly within a virtual address space. This is easy to be understood, e.g., when an instruction of the application is being executd, the next instruction(for most cases, instructions are executed one by one) can be fetched directly from the adjacent virtual address into CPU cache to bost the execution performance.

Allowing for the benefits of groupping similar objectes together, a virtual address space is splitted into separated address ranges for holding different objects: program code, program data, shared libraries, program stacks, kernel code, kernel data, etc. The splitting layout is predefined(can be tuned during compiling) and different architectures have different implementations. For x86_64, referr to https://docs.kernel.org/x86/x86_64/mm.html for the details.

Such splited address ranges have to implement differenet access control for the sake of system stability: an application of course can access its own code and data within its address space, and it can also invoke functions and refer to exported variables provided by shared libraries directly, but it should never access kernel code and data directly which may impact the system stability. Based on such requirements of different access control, splited address ranges within a virtual address space are logically grouped into 2 regions:

- User space: for holding user application related objects including related shared libraries;
- Kernel space: for holding kernel related objects including kernel code and data;

When logical address is also taken into consideration, we can have another picutre by using segments to describe user space and kernel space:

- User space: consists of user code segment, user data segment, user heap segment, shared libraries segment, stack segment, etc.;
- Kernel space: consists of kernel code segment, kernel data segment, etc.;

Privilege Level
~~~~~~~~~~~~~~~~

We have introduced the concept of user space and kernel space is based on the requirement of differnet access control under the consideration of system stability. In the background, this actually needs the support from hardware. With x86 architectured CPU, 4 protection rings are defined to support different instruction execution privileges, they are ring 0 which has the highest privilege to ring 3 which has the lowest privilege. While the logical splitting of user space and kernel space makes Linux only leverage 2 of the rings - ring 0 for kernel mode where all instructions can be executed, and ring 3 for user mode where privileged instructions cannot be executed. Linux defines a term named privilege level accordingly to describe the mapping mechanism between user/kernel space to CPU protection rings, and it is easy to conclude that privilege level has only 2 values - 0 when code is executing in kernel sapce, 3 when code is executing in user space.

In the meanwhile, when an application is excuting within its virtual address space(no matter user space or kernel space), instructions from the same segment should have the same privilege(since a segment is a group of similar objects with the same access control) - This make a segment base become a good place to define the privilege level for the whole segment. With x86 architectured CPU, a special CPU register is used for this purpose, this is the code selector register(or cs for short). The privilege level defined with cs is named requested Privilege Level(or RPL for short) and its layout can be gotten by checking https://wiki.osdev.org/Segment_Selector. By checking the RPL, we can understand if we are running instructions within the user space or kernel space - let's do it:

::

  gdb -q vmlinux
  Reading symbols from vmlinux...
  (gdb) target remote :1234
  Remote debugging using :1234
  amd_e400_idle () at arch/x86/kernel/process.c:780
  780                     return;
  (gdb) print /t $cs
  $7 = 10000
  (gdb) c
  Continuing.
  ^C
  Program received signal SIGINT, Interrupt.
  0x00007fbd2ac9a95a in ?? ()
  (gdb) print /t $cs
  $8 = 110011
  (gdb)

Explanations:

- based on the layout of cs, the last 2 bits are used for RPL, hence we can print out the value of cs in binary format and check the RPL value;
- $7 = 10000: the last 2 bits are 00, which indicates that RPL = 0, we are in the kernel space;
- $8 = 110011: the last 2 bits are 11, which indicates that RPL = 3, we are in the user space;

**Notes**: execept for RPL, there is also DPL, CPL. These will be introduced within the memory management document.

System Call
-------------

Definition
~~~~~~~~~~~

User space and kernel space have different access control based on our previous introduction. When an application is running, its memory access is fully granted within user space, however, consuming privileged resources in kernel space is not possible since higher privilege level is required - but consuming such resources is not avoidable. There must be a mechanism giving applications the ability to swtich to kernel space - this is the work of system call.

Whenever an application needs to access/consume privileged resouces/services, it needs to invoke corresponding system calls. After each system call, a switch from user space to kernel space will be executed and kernel code will kick in consuming/running resources/services on behalf of the associated application. At the end of a system call, another switch from kernel space to user space will be executed and a return value of the system call will be provided, then the application can continue its execution within user space again. Such a switch from user/kernel space to kernel/user space is called a context switch, we will cover this in the process scheduling document.

All system calls apply strict check on parameters when invoked from user space to guarantee no offensive operations are involved, hence bugs of user space application won't impact kernel space(no harm to the system stability).

Implementation
~~~~~~~~~~~~~~~~

For end users, system calls look like normal APIs. For example, when we want to get the contents of a file, function "ssize_t read(int fd, void \*buf, size_t count)" will be called from our applications. Most users take "read" here as a system call and think it as a kernel API - this is not correct or at least not accurate.

In fact, when an application needs to invoke a system call, it needs to set values on several specific CPU registers, then call a specific assembly instruction named syscall which triggers a context switch from user space to kernel space. After switching to kernel space, a system call dispater will do some preparations and invoke the actual system call implemented in kernel code.  There are several hundreds of system calles defined with linux, all of them are invoked by the same system call dispather with the help of syscall who inits the user space to kernel space context switch.

The system call dispather implemented as assembly language within kernel decides which actual system call to invoke based on a integer value set on a specific CPU register(rax for x86_64), and pass values collected from other registers as parameters to the actual system call which are implemented in C language. Each system call is mapped to a integer value within kernel, and system calls supported limited num. of parameters(at most 6) due to the num. of available CPU registers. The integer num. used to map the actual system call within kernel is called **system call number**. Linux kernel also maintains a mapping between system call paramters and CPU registers, together with system call numbers, a table named **system call table** as below can be gotten:

::

  rax | actual system call | rdi                | rsi               | rdx                | r10                 | r9               | r8                |
  0   | sys_read           | unsigned int fd    | char *buf         | size_t count       |                     |                  |                   |
  1   | sys_write          | unsigned int fd    | char *buf         | size_t count       |                     |                  |                   |
  ...
  9   | sys_mmap           | unsigned long addr | unsigned long len | unsigned long prot | unsigned long flags | unsigned long fd | unsigned long off |
  ...

Once a system call in kernel space has been completed, another assembly instruction named sysret will be called to switch back from kernel space to user space, then the application resume its execution in user space with the value gottern from the previously invoked system call(from CPU registers).

Since system calls will be used frequently, and it is not efficient to trigger system calls in user space with assembly instructions like above(set values on CPU registers then invoke syscall), libraries are used instead. The most famous library on Linux is glibc which wraps syscall details and provids a straightforward and sophisticated programming API to user space applications. Now we understand what we previous called as "system call" are actually glibc provided APIs in user space which perform those complicated assembly instructions on behalf of us.

vsyscall and vDSO
~~~~~~~~~~~~~~~~~~

Most system calls are implemented with the mechanism introduced above. However, system calls are expensive since it involes context switches which will interrupt the current running user space application. To mitigate the overheads, two mechanisms named vsyscall and vDSO are designed to make certain system calls work directly in user space without the need of context swithes.

**vsyscall**

It is the short name for virtual system call. Its initial implementation is quite straightforward: it maps the implementation of certain system calls and required variables to a user space memory page(as read only for security, hence mapped system calls should be those which have no needs to modify variables). After such mappings, mapped system calls can be used directly in user space. Since only one memory page is mapped, only four system calls are supported. Furthermore, the mapping is static - all processes access mapped system calls from the system virtual addresses, which brings potential security issues. Because such limitations, vsyscalls are not recommended, and emulated vsyscall are designed to keep backward compatibility. For more information on vsyscall, please consult google search.

**vDSO**

To overcome the limitations of vsyscall, vDSO, short for virtual dynamic shared object, are introduced. Since it is dynamic allocation based, it supports more than four system calls, and the mapping addresses are different for each process which solves the security concerns of vsyscall. For end users, vDSO is exposed with the help of glibc which wrapps the details - for a system has vDSO enabled, it will be used of course; for a system does not have vDSO support, a traditional system call will be used. For more details of vDSO, please consult google search.

Trace and Verify
~~~~~~~~~~~~~~~~~

We have introduced system calls in theory, let's trace a system call(traditional system calls but not vsyscall/vDSO) directly from both user space and kernel to get an deeper understanding.

The system call we are going to trace is dup, to trace it, let's create a simple c file named main.c with below contents:

::

  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <stdio.h>

  int main() {
    const char *fpath = "/etc/passwd";
    int fd1, fd2;

    fd1 = open(fpath, O_RDONLY);
    if (fd1 == -1) {
      printf("fail to open file: %s\n", fpath);
      return errno;
    }

    fd2 = dup(fd1);
    if (fd2 == -1) {
      printf("fail to dup file: %s\n", fpath);
      return errno;
    }

    close(fd1);
    close(fd2);
    return 0;
  }

Let's compile the program as below:

::

  gcc -g main.c -o dup_trace

**User Space Tracing**

User space tracing can be performed with the help of gdb, let's try to trace dup:

::

  gdb -q dup_trace
  Reading symbols from dup_trace...
  (gdb) b dup
  Breakpoint 1 at 0x10b0
  (gdb) start
  Temporary breakpoint 2 at 0x11c9: file main.c, line 8.
  Starting program: /home/kcbi/sandbox/gdbdemo/dup_trace

  Temporary breakpoint 2, main () at main.c:8
  8       int main() {
  (gdb) c
  Continuing.

  Breakpoint 1, dup () at ../sysdeps/unix/syscall-template.S:78
  78      ../sysdeps/unix/syscall-template.S: No such file or directory.
  (gdb)

The result tells us dup actually is implemented within ../sysdeps/unix/syscall-template.S at line 78. This is not a line in our source code, where is it? Actually, as we previously said, what we use as a system call actually is the API provided by glibc libary which wraps the actual system call defined in kernel. Let's add the source code path for searching in glibc and start the trace again:

::

  (gdb) directory ~/glibc-2.31/sysdeps/
  Source directories searched: /home/kcbi/glibc-2.31/sysdeps:$cdir:$cwd
  (gdb) start
  The program being debugged has been started already.
  Start it from the beginning? (y or n) y
  Temporary breakpoint 3 at 0x5555555551c9: file main.c, line 8.
  Starting program: /home/kcbi/sandbox/gdbdemo/dup_trace

  Temporary breakpoint 3, main () at main.c:8
  8       int main() {
  (gdb) c
  Continuing.

  Breakpoint 1, dup () at ../sysdeps/unix/syscall-template.S:78
  78      T_PSEUDO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)

Here we can see "T_PSEUDO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)" from glibc is invoked. Let's step into it:

::

  (gdb) step
  dup () at ../sysdeps/unix/syscall-template.S:79
  79              ret

Nothing valuable is here, the next line to run is just a ret instruction, hence the work actually is done with the previous line "78      T_PSEUDO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)", let's disassemble the line:

::

  (gdb) start
  The program being debugged has been started already.
  Start it from the beginning? (y or n) y
  Temporary breakpoint 4 at 0x5555555551c9: file main.c, line 8.
  Starting program: /home/kcbi/sandbox/gdbdemo/dup_trace

  Temporary breakpoint 4, main () at main.c:8
  8       int main() {
  (gdb) c
  Continuing.

  Breakpoint 1, dup () at ../sysdeps/unix/syscall-template.S:78
  78      T_PSEUDO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
  (gdb) disassemble
  Dump of assembler code for function dup:
  => 0x00007ffff7ed7890 <+0>:     endbr64
     0x00007ffff7ed7894 <+4>:     mov    $0x20,%eax
     0x00007ffff7ed7899 <+9>:     syscall
     0x00007ffff7ed789b <+11>:    cmp    $0xfffffffffffff001,%rax
     0x00007ffff7ed78a1 <+17>:    jae    0x7ffff7ed78a4 <dup+20>
     0x00007ffff7ed78a3 <+19>:    retq
     0x00007ffff7ed78a4 <+20>:    mov    0xdd5c5(%rip),%rcx        # 0x7ffff7fb4e70
     0x00007ffff7ed78ab <+27>:    neg    %eax
     0x00007ffff7ed78ad <+29>:    mov    %eax,%fs:(%rcx)
     0x00007ffff7ed78b0 <+32>:    or     $0xffffffffffffffff,%rax
     0x00007ffff7ed78b4 <+36>:    retq
  End of assembler dump.

Based on the output, it is clear to see some CPU registers will be set and syscall will be invoked. Based on previous introduction, we know system call number and parameters will be used during system calls:

- The system call number for dup is 32 based on arch/x86/include/generated/uapi/asm/unistd_64.h;
- The function signature for dup is "int dup(int oldfd)", based on the system call table(man syscall) for x86_64 as below, the only parameter oldfd will be set on dri;

  ::

    Arch/ABI      arg1  arg2  arg3  arg4  arg5  arg6  arg7  Notes
    x86-64        rdi   rsi   rdx   r10   r8    r9    -

Let's verify the system call number(32) and registers(rdi) are correct during the execution:

::

  (gdb) p fd1
  No symbol "fd1" in current context.
  (gdb) up
  #1  0x000055555555522a in main () at main.c:18
  18        fd2 = dup(fd1);
  (gdb) p fd1
  $15 = 3
  (gdb) down
  #0  dup () at ../sysdeps/unix/syscall-template.S:78
  78      T_PSEUDO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
  (gdb) p 0x20
  $16 = 32
  (gdb) p $rdi
  $17 = 3

The system call number is 32 and it indeed will be set on the eax register (0x00007ffff7ed7894 <+4>:     mov    $0x20,%eax). In the meanwhile, the paramter passed to dup is oldfd which is 3, it is set on the rdi register as expected. The user space tracing ends here, other stories happen within kernel.

**Kernel Space Tracing**

There are several ways to perform trace within kernel space, such as crash, kgdb, gdb + qemu. We are going to use gdb + qemu + buildroot here, the details on how to set up such an env will be covered in another document.

Let's start our remote gdb:

::

  gdb -q vmlinux
  (gdb) target remote :1234
  Remote debugging using :1234
  amd_e400_idle () at arch/x86/kernel/process.c:780
  780                     return;

The next step is setting a breakpoint when dup is invoked from user space. In kernel space, the associated system call is__x64_sys_dup for x86_64(refer to arch/x86/entry/syscalls/syscall_64.tbl). Let's check what happens when dup is called:

::

  (gdb) b __x64_sys_dup
  Breakpoint 1 at 0xffffffff81163a00: file fs/file.c, line 1286.
  (gdb) c
  Continuing.

  Breakpoint 1, __x64_sys_dup (regs=0xffffc900001d7f58) at fs/file.c:1286
  1286    SYSCALL_DEFINE1(dup, unsigned int, fildes)
  (gdb) list 1286
  1281                    return retval;
  1282            }
  1283            return ksys_dup3(oldfd, newfd, 0);
  1284    }
  1285
  1286    SYSCALL_DEFINE1(dup, unsigned int, fildes)
  1287    {
  1288            int ret = -EBADF;
  1289            struct file *file = fget_raw(fildes);
  1290
  (gdb)
  1291            if (file) {
  1292                    ret = get_unused_fd_flags(0);
  1293                    if (ret >= 0)
  1294                            fd_install(ret, file);
  1295                    else
  1296                            fput(file);
  1297            }
  1298            return ret;
  1299    }
  1300

After setting the breakpoint on __x64_sys_dup, "continue" is executed from gdb. Once user applicaiton "dup_trace" is run, the breakpoint gets triggered. Based on the result, it is clear to see the function "SYSCALL_DEFINE1(dup, unsigned int, fildes)" defined within file fs/file.c is the kernel space system call implementation for dup. Now, let' check who is the system call dispather:

::

	(gdb) bt
	#0  __x64_sys_dup (regs=0xffffc90000147f58) at fs/file.c:1289
	#1  0xffffffff8162dc63 in do_syscall_x64 (nr=<optimized out>, regs=0xffffc90000147f58) at arch/x86/entry/common.c:50
	#2  do_syscall_64 (regs=0xffffc90000147f58, nr=<optimized out>) at arch/x86/entry/common.c:80
	#3  0xffffffff8180007c in entry_SYSCALL_64 () at arch/x86/entry/entry_64.S:113
	#4  0x0000000000000000 in ?? ()

From the output, the dispatcher entry_SYSCALL_64 defined within arch/x86/entry/entry_64.S can be located. Let's see what it actually does:

::

  (gdb) frame 3                                                                                                                                                                                                     #3  0xffffffff8180007c in entry_SYSCALL_64 () at arch/x86/entry/entry_64.S:113
  113             call    do_syscall_64           /* returns with IRQs disabled */
  (gdb) disassemble
  Dump of assembler code for function entry_SYSCALL_64:
     0xffffffff81800000 <+0>:     swapgs
     0xffffffff81800003 <+3>:     mov    %rsp,%gs:0x6014
     0xffffffff8180000c <+12>:    jmp    0xffffffff81800020 <entry_SYSCALL_64+32>
     0xffffffff8180000e <+14>:    mov    %cr3,%rsp
     0xffffffff81800011 <+17>:    nopl   0x0(%rax,%rax,1)
     0xffffffff81800016 <+22>:    and    $0xffffffffffffe7ff,%rsp
     0xffffffff8180001d <+29>:    mov    %rsp,%cr3
     0xffffffff81800020 <+32>:    mov    %gs:0x1ac90,%rsp
     0xffffffff81800029 <+41>:    pushq  $0x2b
     0xffffffff8180002b <+43>:    pushq  %gs:0x6014
     0xffffffff81800033 <+51>:    push   %r11
     0xffffffff81800035 <+53>:    pushq  $0x33
     0xffffffff81800037 <+55>:    push   %rcx
     0xffffffff81800038 <+56>:    push   %rax
     0xffffffff81800039 <+57>:    push   %rdi
     ......
     0xffffffff8180006e <+110>:   xor    %r15d,%r15d
     0xffffffff81800071 <+113>:   mov    %rsp,%rdi
     0xffffffff81800074 <+116>:   movslq %eax,%rsi
     0xffffffff81800077 <+119>:   callq  0xffffffff81607f20 <do_syscall_64>
     ......

Generally speaking, the dispather performs a lot of operations on CPU registers(to collect system call num. and parameters set in user space before syscall), and then call do_syscall_64 defined within arch/x86/entry/common.c with two parameters: regs, and nr. The **nr** parameter is the system call number, and regs contains all other parameters needed for the actual system call. Based on nr, __x64_sys_dup will be finally selected and invoked, let's understand how this happens:

::

  (gdb) frame 1
  #1  0xffffffff8162dc63 in do_syscall_x64 (nr=<optimized out>, regs=0xffffc90000147f58) at arch/x86/entry/common.c:50
  50                      regs->ax = sys_call_table[unr](regs);
  (gdb) list
  45               */
  46              unsigned int unr = nr;
  47
  48              if (likely(unr < NR_syscalls)) {
  49                      unr = array_index_nospec(unr, NR_syscalls);
  50                      regs->ax = sys_call_table[unr](regs);
  51                      return true;
  52              }
  53              return false;
  54      }
  (gdb) p *sys_call_table
  $1 = (const sys_call_ptr_t) 0xffffffff81150c80 <__x64_sys_read>

From the output, it is clear to see the actual system call in kernel space, A.K.A __x64_sys_dup, is selected by checking sys_call_table[unr] and invoked directrly with regs as parameters. Let's see what is defined within sys_call_table:

::

  (gdb) info variables sys_call_table
  All variables matching regular expression "sys_call_table":

  File arch/x86/entry/syscall_64.c:
  16:     const sys_call_ptr_t sys_call_table[451];
  (gdb) list arch/x86/entry/syscall_64.c:16
  11      #include <asm/syscalls_64.h>
  12      #undef __SYSCALL
  13
  14      #define __SYSCALL(nr, sym) __x64_##sym,
  15
  16      asmlinkage const sys_call_ptr_t sys_call_table[] = {
  17      #include <asm/syscalls_64.h>
  18      };

Based on the result, it is clear sys_call_table is initialized with asm/syscalls_64.h, let's check that file(cd to the linux kernel source root directory at first):

::

	# find . -name syscalls_64.h
	./arch/x86/include/generated/asm/syscalls_64.h
	./arch/x86/um/shared/sysdep/syscalls_64.h
	# head ./arch/x86/include/generated/asm/syscalls_64.h
	__SYSCALL(0, sys_read)
	__SYSCALL(1, sys_write)
	__SYSCALL(2, sys_open)
	__SYSCALL(3, sys_close)
	__SYSCALL(4, sys_newstat)
	__SYSCALL(5, sys_newfstat)
	__SYSCALL(6, sys_newlstat)
	__SYSCALL(7, sys_poll)
	__SYSCALL(8, sys_lseek)
	__SYSCALL(9, sys_mmap)

Let's continue our tracing to see what happens once the system call in kernel space is done:

::

	(gdb) bt
	#0  __x64_sys_dup (regs=0xffffc90000147f58) at fs/file.c:1289
	#1  0xffffffff8162dc63 in do_syscall_x64 (nr=<optimized out>, regs=0xffffc90000147f58) at arch/x86/entry/common.c:50
	#2  do_syscall_64 (regs=0xffffc90000147f58, nr=<optimized out>) at arch/x86/entry/common.c:80
	#3  0xffffffff8180007c in entry_SYSCALL_64 () at arch/x86/entry/entry_64.S:113
	#4  0x0000000000000000 in ?? ()
	(gdb) n
	1286    SYSCALL_DEFINE1(dup, unsigned int, fildes)
	(gdb) n
	do_syscall_64 (regs=0xffffc90000147f58, nr=<optimized out>) at arch/x86/entry/common.c:86
	86              syscall_exit_to_user_mode(regs);
	(gdb) b syscall_exit_to_user_mode
	Breakpoint 2 at 0xffffffff81631f00: file ./arch/x86/include/asm/current.h, line 15.
	(gdb) c
	Continuing.

	Breakpoint 2, syscall_exit_to_user_mode (regs=regs@entry=0xffffc90000147f58) at ./arch/x86/include/asm/current.h:15
	15              return this_cpu_read_stable(current_task);

Once the system call is done, syscall_exit_to_user_mode defined within function do_syscall_64 will be used to return to user space. Of course there will be quite some details behind this function, but it is not our interest. We can conclude our system call tracing in kernel space:

1. Once a system call is triggered from user space after the syscall instruction, a context switch from user space to kernel space will be executed;
2. The system call dispather defined within arch/x86/entry/entry_64.S will collect system call num. and parameters from CPU registers and invoke do_syscall_x64 defined within arch/x86/entry/common.c;
3. The do_syscall_x64 will check system call table(initialized with arch/x86/include/generated/asm/syscalls_64.h) using the system call num. to get the actual system call and invoke it with parameters;
4. Once the actual system call is done, a context switch from kernel space to user space will be triggered;

Summary
~~~~~~~~~

As a summary, the whole process of a system call is as below:

1. An application want to consume services in kernel space;
2. Associated system call API defined within glibc is invoked;
3. The glibc wrapper for the acutal system call will set CPU registers with corresponding system call number and paramters;
4. Instruction syscall is invoked from glibc, a context switch from user space to kernel space is performed;
5. The system call dispatcher within linux kernel will kick in to play;
6. Current application status including user stacks, return address, etc. will be saved on kernel stack;
7. CPU registers for the actual system call get saved on kernel stack;
8. The system call number and paramters are collected from CPU registers;
9. The actual system call is invoked by the system call dispather;
10. Application status are restored from kernel stacks;
11. Instruction sysret is executed to switch back to user space;
12. The application resumes its normal execution in user space.

**NOTES**:

- sysenter will be mentioned as the instruction triggers system calls within a lot of existing documents, it is for old CPU models, nowadays x86_64 uses syscall;
- sysret/iret will be mentioned as the instruction to return back from system within a lot of existing documents, it is for old CPU models, nowadays x86_64 uses sysret;
- Information for system call numbers is defined within linux source code file arch/x86/include/generated/uapi/asm/unistd_64.h;
- Different architectures use difference instructions to switch from user space to kernel space, run command **man syscall** to find the detailed instruction used to perform the swtich;
- Registers used for system call number and parameters on different architectures are different, run command **man syscall** to find the details;
- The raw x86_64 system call table can be found with linux source code file arch/x86/entry/syscalls/syscall_64.tbl;

Tools
-------

gdb + qemu is a good way to trace into linux kernel, however, it is not feasible for production systems. We are going to introudce several tools which can be leveraged for system call analysis for production systems in this section.

ftrace
~~~~~~~~~

Ftrace is an internal tracer designed to help out developers and designers of systems to find what is going on inside the kernel. It can be used for debugging or analyzing latencies and performance issues that take place in kernel space.

We will only demonstrate the basics of ftrace with several examples related with system call analysis instead of covering the tool thoroughly. Please refer to https://www.kernel.org/doc/Documentation/trace/ftrace.txt for more information.

**function trace**

One of the most useful feature of ftrace is its capability of tracing functions defined in kernel space. System calls are implemented in kernel, so we can trace them with ftrace. Let's trace the system call **dup** as before.

::

  cd /sys/kernel/debug/tracing
  cat available_tracers # find out what kind of trace can be used, we are going to use function tracer
  cat current_tracer # find out the current enabled tracer
  echo function > current_tracer # enable function trace
  echo 1 > options/latency-format # enable latency format output
  cat available_filter_functions | grep sys_dup # here we can find if __x64_sys_dup is supported as the filter
  echo __x64_sys_dup > set_ftrace_filter # trace only  __x64_sys_dup
  echo > trace # clear previously tracing result
  cat trace # start function tracing on __x64_sys_dup
  # if there is no outout, ssh localhost which will trigger __x64_sys_dup
  cat trace
  #                  _------=> CPU#
  #                 / _-----=> irqs-off
  #                | / _----=> need-resched
  #                || / _---=> hardirq/softirq
  #                ||| / _--=> preempt-depth
  #                |||| /     delay
  #  cmd     pid   ||||| time  |   caller
  #     \   /      |||||  \    |   /
      sshd-4381    2.... 142164512us#: __x64_sys_dup <-do_syscall_64
      sshd-4381    2.... 142166125us : __x64_sys_dup <-do_syscall_64

The result is really self explained. Let's trace a specified process this time:

::

  echo > set_ftrace_filter # trace all functions instead of a specific function
  echo 16786 > set_event_pid # only trace the specified process
  echo > trace
  cat trace
  #                  _------=> CPU#
  #                 / _-----=> irqs-off
  #                | / _----=> need-resched
  #                || / _---=> hardirq/softirq
  #                ||| / _--=> preempt-depth
  #                |||| /     delay
  #  cmd     pid   ||||| time  |   caller
  #     \   /      |||||  \    |   /
    <idle>-0       0d... 11013035us : update_ts_time_stats <-tick_irq_enter
    <idle>-0       0d... 11013035us : nr_iowait_cpu <-update_ts_time_stats
    <idle>-0       0d... 11013036us : tick_do_update_jiffies64 <-tick_irq_enter
    <idle>-0       0d... 11013036us : touch_softlockup_watchdog_sched <-irq_enter
    <idle>-0       0d... 11013036us : _local_bh_enable <-irq_enter
    <idle>-0       0d... 11013036us : irqtime_account_irq <-irq_enter
    <idle>-0       0d.h. 11013036us : sched_ttwu_pending <-scheduler_ipi
  echo 0 > tracing_on # turn off trace
  echo nop > current_tracer # clear tracer

Again the result is self explained.

Please explore ftrace function trace by yourself:)

**function graph trace**



bpf
~~~~~~

TBD

perf
~~~~~~

TBD

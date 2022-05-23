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

**Notes**: The segmentation unit of x86 architectured CPU was implemented back to the time when CPU was not able to address the full physical memory space(The details will be introduced in the memory management document). Nowadasys, x86_64 CPU is able to address hundreds of TB even PB memory, segmentation is not needed at all - but it is still used(have to be used since the segmentation unit in MMU cannot be disabled) for some limited features.

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
~~~~~~~~~~~~

System call is the interface between user space and kernel space. When an application is running, its memory access(virtual memory) are limited within its user space. Whenever privileged resouces/services are needed, system calls need to be invoked to switch to the kernel space(kernel code will be executed on behalf of the process after switching).

System calls apply strict check on any request from user space to guarantee no offensive operations are involved, hence bugs of user space application won't impact the system stability.


Implementation
~~~~~~~~~~~~~~~~

System call number: arch/x86/include/generated/uapi/asm/unistd_64.h

Tracing
----------

ftrace
~~~~~~~~~

bpf
~~~~~~

perf
~~~~~~



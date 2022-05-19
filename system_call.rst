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

To improve the efficiency of translating virtual addresses to physical addresses, x86 architectured CPU ships with a memory management unit(MMU for short). A MMU consists of a segmentation unit and a paging unit. The paging unit is responsible for translating virtual addresses to physical addresses, while the segmentaion unit adds one more feature named segment to virtual memory management.

A segment defines a memory size and a starting address as its base in the virtual address space, in other words, all virtual addresses from base to base + size can be addressed by giving a segment base and an offset to the base. This is called logical address.

The relationship of logical address, virtual address and physical address can be summarized as below:

**Logical Address ---> MMU Segmentation Unit ---> Virtual Address ---> MMU Paging Unit ---> Physical Address**

User Space and Kernel Space
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When an application is executed, it is always better to keep similar objects(instructions, data, stacks, etc.) adjacent to each other than spread them ramdomly within a virtual address space. This is easy to understand, e.g., when an instruction of the application is being executd, the next instruction(for most cases, instructions are executed one by one) can be fetched directly from the adjacent virtual address into CPU cache to bost the execution performance.

Allowing for the benefits of groupping similar objectes together, a virtual address space is splitted into separated address ranges for holding different objects: program code, program data, shared libraries, program stacks, kernel code, kernel data, etc. The splitting layout is predefined(can be tuned during compiling) and different architectures have different implementations. For x86_64, referr to https://docs.kernel.org/x86/x86_64/mm.html for the details.

Such splited address ranges have to implement differenet access control for the sake of system stability: an application of course can access its own code and data within its address space, and it can also invoke functions and refer to exported variables provided by shared libraries directly, but it should never access kernel code and data directly which may impact the system stability. Based on such requirements of different access control, splited address ranges within a virtual address space are logically grouped into 2 regions:

- User space: for holding user application related objects including related shared libraries;
- Kernel space: for holding kernel related objects including kernel code and data;

When logical address is also taken into consideration, we can have a more clearer picutre based on segment over user space and kernel space:

- User space: consists of user code segment, user data segment, user heap segment, shared libraries segment, stack segment, etc.;
- Kernel space: consists of kernel code segment, kernel data segment, etc.;

Privilege Level
~~~~~~~~~~~~~~~~

When an appliation is excuting within its virtual address space, it can refer to any address by giving an segment base and a offset. Hence the access control for user space and kernel space can be configured on segment - the access control is named privilege level, which is associated with a concept named protection ringhs.

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



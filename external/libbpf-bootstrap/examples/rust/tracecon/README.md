# tracecon

An eBPF sample application, written in C & Rust using
[libbpf-rs](https://github.com/libbpf/libbpf-rs). It will output all
TCPv4 connections that have been established on the host as ips and
hostnames by probing `tcp_v4_connect` in kernel and glibc's `getaddrinfo`
in userland. On a successful host lookup the first result will be stored in
a hashmap, which can be used as a lookup table to retrieve a hostname for
ip_v4 connections.

## Requirements

### Kernel

The project is built on technology like `CO-RE` and `BTF`, which is only
available in more recent kernels (5.0-ish). Ubuntu 20.10 has configured and
packaged all the required dependencies.

### Compilers

The project has been tested with LLVM v11 and Rust v1.52.1.

### Generate `vmlinux.h`

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

You can verify whether your kernel was built with BTF enabled:

```bash
cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF
```

## Build

### Vagrant

eBPF is a low-level technology on the Linux kernel. Docker is not a good fit
to build eBPF code on MacOS or Windows environments. On those platforms
Docker ships its own kernel (e.g. linuxkit) and BTF might not be enabled.

There is a `Vagrantfile` to provision a Ubuntu 20.10 VM including the
necessary dependencies to build the project. To install Vagrant with a
VirtualBox backend and provision the VM on a MacOS host machine run:

```
brew cask install virtualbox
brew cask install vagrant
vagrant up
```

Log in to the machine. The current host workdir is mounted to `/vagrant`:

```
vagrant ssh
sudo su -
cd /vagrant
```

### Cargo

```bash
cargo build
```

## Run

Start the program to instrument the eBPF probe and listen to events:

```bash
cargo run --release
```

In another shell perform some http calls:

```bash
curl -s www.jsonplaceholder.com > /dev/null
# Do not use a dns lookup
curl -s -H "Host: www.jsonplaceholder.com" 172.67.201.157 > /dev/null
```

The other shell should show the respective events:

```bash
host event: www.jsonplaceholder.com
ip event: 172.67.201.157
```

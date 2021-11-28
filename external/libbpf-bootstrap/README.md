# Demo BPF applications

## Minimal

`minimal` is just that – a minimal practical BPF application example. It
doesn't use or require BPF CO-RE, so should run on quite old kernels. It
installs a tracepoint handler which is triggered once every second. It uses
`bpf_printk()` BPF helper to communicate with the world. To see it's output,
read `/sys/kernel/debug/tracing/trace_pipe` file as a root:

```shell
$ cd examples/c
$ make minimal
$ sudo ./minimal
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: BPF triggered from PID 3840345.
           <...>-3840345 [010] d... 3220702.101265: bpf_trace_printk: BPF triggered from PID 3840345.
```

`minimal` is great as a bare-bones experimental playground to quickly try out
new ideas or BPF features.

## Bootstrap

`bootstrap` is an example of a simple (but realistic) BPF application. It
tracks process starts (`exec()` family of syscalls, to be precise) and exits
and emits data about filename, PID and parent PID, as well as exit status and
duration of the process life. With `-d <min-duration-ms>` you can specify
minimum duration of the process to log. In such mode process start
(technically, `exec()`) events are not output (see example output below).

`bootstrap` was created in the similar spirit as
[libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools) from
BCC package, but is designed to be more stand-alone and with simpler Makefile
to simplify adoption to user's particular needs. It demonstrates the use of
typical BPF features:
  - cooperating BPF programs (tracepoint handlers for process `exec` and `exit`
    events, in this particular case);
  - BPF map for maintaining the state;
  - BPF ring buffer for sending data to user-space;
  - global variables for application behavior parameterization.
  - it utilizes BPF CO-RE and vmlinux.h to read extra process information from
    kernel's `struct task_struct`.

`bootstrap` is intended to be the starting point for your own BPF application,
with things like BPF CO-RE and vmlinux.h, consuming BPF ring buffer data,
command line arguments parsing, graceful Ctrl-C handling, etc. all taken care
of for you, which are crucial but mundane tasks that are no fun, but necessary
to be able to do anything useful. Just copy/paste and do simple renaming to get
yourself started.

Here's an example output in minimum process duration mode:

```shell
$ sudo ./bootstrap -d 50
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
19:18:32 EXIT  timeout          3817109 402466  [0] (126ms)
19:18:32 EXIT  sudo             3817117 3817111 [0] (259ms)
19:18:32 EXIT  timeout          3817110 402466  [0] (264ms)
19:18:33 EXIT  python3.7        3817083 1       [0] (1026ms)
19:18:38 EXIT  python3          3817429 3817424 [1] (60ms)
19:18:38 EXIT  sh               3817424 3817420 [0] (79ms)
19:18:38 EXIT  timeout          3817420 402466  [0] (80ms)
19:18:43 EXIT  timeout          3817610 402466  [0] (70ms)
19:18:43 EXIT  grep             3817619 3817617 [1] (271ms)
19:18:43 EXIT  timeout          3817609 402466  [0] (321ms)
19:18:44 EXIT  iostat           3817585 3817531 [0] (3006ms)
19:18:44 EXIT  tee              3817587 3817531 [0] (3005ms)
...
```

## Uprobe

`uprobe` is an example of dealing with user-space entry and exit (return) probes,
`uprobe` and `uretprobe` in libbpf lingo. It attached `uprobe` and `uretprobe`
BPF programs to its own function (`uprobe_trigger()`) and logs input arguments
and return result, respectively, using `bpf_printk()` macro. The user-space
function is triggered once every second:

```shell
$ sudo ./uprobe
libbpf: loading object 'uprobe_bpf' from buffer
...
Successfully started!
...........
```

You can see `uprobe` demo output in `/sys/kernel/debug/tracing/trace_pipe`:
```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-461101 [018] d... 505432.345032: bpf_trace_printk: UPROBE ENTRY: a = 0, b = 1
           <...>-461101 [018] d... 505432.345042: bpf_trace_printk: UPROBE EXIT: return = 1
           <...>-461101 [018] d... 505433.345186: bpf_trace_printk: UPROBE ENTRY: a = 1, b = 2
           <...>-461101 [018] d... 505433.345202: bpf_trace_printk: UPROBE EXIT: return = 3
           <...>-461101 [018] d... 505434.345342: bpf_trace_printk: UPROBE ENTRY: a = 2, b = 3
           <...>-461101 [018] d... 505434.345367: bpf_trace_printk: UPROBE EXIT: return = 5
```

# Fentry

`fentry` is an example that uses fentry and fexit BPF programs for tracing. It
attaches `fentry` and `fexit` traces to `do_unlinkat()` which is called when a
file is deleted and logs the return value, PID, and filename to the
trace pipe.

Important differences, compared to kprobes, are improved performance and
usability. In this example, better usability is shown with the ability to
directly dereference pointer arguments, like in normal C, instead of using
various read helpers. The big distinction between **fexit** and **kretprobe**
programs is that fexit one has access to both input arguments and returned
result, while kretprobe can only access the result.

fentry and fexit programs are available starting from 5.5 kernels.

```shell
$ sudo ./fentry
libbpf: loading object 'fentry_bpf' from buffer
...
Successfully started!
..........
```

The `fentry` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file, ret = 0
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file2
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file2, ret = 0
```

# Kprobe

`kprobe` is an example of dealing with kernel-space entry and exit (return)
probes, `kprobe` and `kretprobe` in libbpf lingo. It attaches `kprobe` and
`kretprobe` BPF programs to the `do_unlinkat()` function and logs the PID,
filename, and return result, respectively, using `bpf_printk()` macro.

```shell
$ sudo ./kprobe
libbpf: loading object 'kprobe_bpf' from buffer
...
Successfully started!
...........
```

The `kprobe` demo output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9346    [005] d..3  4710.951696: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test1
              rm-9346    [005] d..4  4710.951819: bpf_trace_printk: KPROBE EXIT: ret = 0
              rm-9346    [005] d..3  4710.951852: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test2
              rm-9346    [005] d..4  4710.951895: bpf_trace_printk: KPROBE EXIT: ret = 0
```

# XDP

`xdp` is an example written in Rust (using libbpf-rs). It attaches to
the ingress path of networking device and logs the size of each packet,
returning `XDP_PASS` to allow the packet to be passed up to the kernel’s
networking stack.

```shell
$ sudo ./target/release/xdp 1
..........
```

The `xdp` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-823887  [000] d.s1 602386.079100: bpf_trace_printk: packet size: 75
           <...>-823887  [000] d.s1 602386.079141: bpf_trace_printk: packet size: 66
           <...>-2813507 [000] d.s1 602386.696702: bpf_trace_printk: packet size: 77
           <...>-2813507 [000] d.s1 602386.696735: bpf_trace_printk: packet size: 66
```

# Building

libbpf-bootstrap supports multiple build systems that do the same thing.
This serves as a cross reference for folks coming from different backgrounds.

## C Examples

Makefile build:

```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd examples/c
$ make
$ sudo ./bootstrap
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
00:21:22 EXIT  python3.8        4032353 4032352 [0] (123ms)
00:21:22 EXEC  mkdir            4032379 4032337 /usr/bin/mkdir
00:21:22 EXIT  mkdir            4032379 4032337 [0] (1ms)
00:21:22 EXEC  basename         4032382 4032381 /usr/bin/basename
00:21:22 EXIT  basename         4032382 4032381 [0] (0ms)
00:21:22 EXEC  sh               4032381 4032380 /bin/sh
00:21:22 EXEC  dirname          4032384 4032381 /usr/bin/dirname
00:21:22 EXIT  dirname          4032384 4032381 [0] (1ms)
00:21:22 EXEC  readlink         4032387 4032386 /usr/bin/readlink
^C
```

CMake build:

```shell
$ git submodule update --init --recursive       # check out libbpf
$ mkdir build && cd build
$ cmake ../examples/c
$ make
$ sudo ./bootstrap
<...>
```

XMake build (Linux):

```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd examples/c
$ xmake
$ xmake run bootstrap
```

XMake build (Android):

```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd examples/c
$ xmake f -p android
$ xmake
```

Install [Xmake](https://github.com/xmake-io/xmake)

```shell
$ bash <(wget https://xmake.io/shget.text -O -)
$ source ~/.xmake/profile
```

## Rust Examples

Install `libbpf-cargo`:
```shell
$ cargo install libbpf-cargo
```

Build using `cargo`:
```shell
$ cd examples/rust
$ cargo build --release
$ sudo ./target/release/xdp 1
<...>
```

# Troubleshooting

Libbpf debug logs are quire helpful to pinpoint the exact source of problems,
so it's usually a good idea to look at them before starting to debug or
posting question online.

`./minimal` is always running with libbpf debug logs turned on.

For `./bootstrap`, run it in verbose mode (`-v`) to see libbpf debug logs:

```shell
$ sudo ./bootstrap -v
libbpf: loading object 'bootstrap_bpf' from buffer
libbpf: elf: section(2) tp/sched/sched_process_exec, size 384, link 0, flags 6, type=1
libbpf: sec 'tp/sched/sched_process_exec': found program 'handle_exec' at insn offset 0 (0 bytes), code size 48 insns (384 bytes)
libbpf: elf: section(3) tp/sched/sched_process_exit, size 432, link 0, flags 6, type=1
libbpf: sec 'tp/sched/sched_process_exit': found program 'handle_exit' at insn offset 0 (0 bytes), code size 54 insns (432 bytes)
libbpf: elf: section(4) license, size 13, link 0, flags 3, type=1
libbpf: license of bootstrap_bpf is Dual BSD/GPL
...
```

use anyhow::{anyhow, bail, Result};
use core::time::Duration;
use libbpf_rs::PerfBufferBuilder;
use object::Object;
use object::ObjectSymbol;
use plain::Plain;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use structopt::StructOpt;

#[path = "bpf/.output/tracecon.skel.rs"]
mod tracecon;
use tracecon::*;

type Event = tracecon_bss_types::event;
unsafe impl Plain for Event {}

#[derive(Debug, StructOpt)]
struct Command {
    /// verbose output
    #[structopt(long, short)]
    verbose: bool,
    /// glibc path
    #[structopt(long, short, default_value = "/lib/x86_64-linux-gnu/libc.so.6")]
    glibc: String,
    #[structopt(long, short)]
    /// pid to observe
    pid: Option<i32>,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn get_symbol_address(so_path: &str, fn_name: &str) -> Result<usize> {
    let path = Path::new(so_path);
    let buffer = fs::read(path)?;
    let file = object::File::parse(buffer.as_slice())?;

    let mut symbols = file.dynamic_symbols();
    let symbol = symbols
        .find(|symbol| {
            if let Ok(name) = symbol.name() {
                return name == fn_name;
            }
            false
        })
        .ok_or(anyhow!("symbol not found"))?;

    Ok(symbol.address() as usize)
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = Event::default();
    plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");

    match event.tag {
        0 => println!("ip event: {}", Ipv4Addr::from(event.ip)),
        1 => println!("host event: {}", String::from_utf8_lossy(&event.hostname)),
        _ => {}
    }
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    let mut skel_builder = TraceconSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;
    if let Some(pid) = opts.pid {
        open_skel.rodata().target_pid = pid;
    }
    let mut skel = open_skel.load()?;
    let address = get_symbol_address(&opts.glibc, "getaddrinfo")?;

    let _uprobe =
        skel.progs_mut()
            .getaddrinfo_enter()
            .attach_uprobe(false, -1, &opts.glibc, address)?;

    let _uretprobe =
        skel.progs_mut()
            .getaddrinfo_exit()
            .attach_uprobe(true, -1, &opts.glibc, address)?;

    let _kprobe = skel
        .progs_mut()
        .tcp_v4_connect_enter()
        .attach_kprobe(false, "tcp_v4_connect")?;

    let _kretprobe = skel
        .progs_mut()
        .tcp_v4_connect_exit()
        .attach_kprobe(true, "tcp_v4_connect")?;

    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .build()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        perf.poll(Duration::from_millis(100))?;
    }

    Ok(())
}

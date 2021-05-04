# xdprtr

[![Release](https://img.shields.io/github/v/release/natesales/xdprtr?style=for-the-badge)](https://github.com/natesales/xdprtr/releases)
[![License](https://img.shields.io/github/license/natesales/xdprtr?style=for-the-badge)](https://github.com/natesales/xdprtr/blob/main/LICENSE)

XDP programmable forwarding plane

### Usage

The `xdprtrctl` command is provided to control xdprtr.

```
Usage: xdprtrctl [options]

DOCUMENTATION:
 xdprtrctl
 - Control xdprtr programmable forwarding plane

Required options:
 -d, --dev <ifname>         Operate on device <ifname>

Other options:
 -h, --help                 Show help
 -S, --skb-mode             Install XDP program in SKB (AKA generic) mode
 -N, --native-mode          Install XDP program in native mode
 -A, --auto-mode            Auto-detect SKB or native mode
 -F, --force                Force install, replacing existing program on interface
 -U, --unload               Unload XDP program instead of loading
 -M, --reuse-maps           Reuse pinned maps
     --filename <file>      Load program from <file>
     --progsec <section>    Load program in <section> of the ELF file
```

There are also `xdprtrload` and `xdprtrunload` utils that take interfaces as arguments to quickly load/unload xdprtr.

The `xdprtr.o` eBPF ELF file contains four XDP programs, defined in sections and can be supplied to `xdprtrctl` with the `--progsec` flag.

#### eBPF ELF Sections
- `xdp_rtr` - Router
- `xdp_rtr_debug` - Router with kernel tracing and stat map logging enabled
- `xdp_pass` - Pass all traffic to kernel network stack
- `xdp_drop` - Drop all traffic

### Statistics

The `xdpstat` utility serves to read XDP statistics from a BPF map. With the `xdp_rtr_debug` loaded, `xdpstat -d <iface>` can be used to poll stats in real time.

```
Usage: xdpstat [options]

DOCUMENTATION:
 XDPRTR XDP stats program - get statistics from running XDP program

Required options:
 -d, --dev <ifname>         Operate on device <ifname>

Other options:
 -h, --help                 Show help
 -q, --quiet                Quiet mode (no output)
```

### Installation

xdprtr can be installed from my [code repositories](https://github.com/natesales/repos) or as a GitHub [release](https://github.com/natesales/xdprtr/releases).

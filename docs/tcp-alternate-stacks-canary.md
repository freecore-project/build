# FreeCORE 15.1 alternate TCP stack canary

This change ships the RACK and BBR TCP stacks and their shared high-precision
timer as **dormant kernel modules**. It does **not** change the stack any
FreeCORE service uses, enable anything at boot, add a WebUI or middleware
surface, or make an administrator-selected alternate stack a supported
configuration.

RACK is the supported opt-in. **BBR ships for experimentation only and is not
supported**, and is validated no further than "it is present, it loads, and it
can be selected". the internal development record shipped HPTS and RACK;
the internal development record added BBR and revised the exclusion the first issue had
recorded. Public tracking: codeberg freecore/freecore#25.

## Build gate

`kernel_modules` in `profiles/freenas/config.pyd` is a `MODULES_OVERRIDE`
list, so only the subdirectories named there are built. It has never named
`sys/modules/tcp`, so no FreeCORE or TrueNAS CORE 13.3 image has carried an
alternate TCP stack at all: a 13.3-RELEASE-p4 baseline reports only `freebsd`
in `net.inet.tcp.functions_available`. This is an added capability, not a
restored one.

The list now also selects `tcp/hpts`, `tcp/rack` and `tcp/bbr`, producing
`tcphpts.ko`, `tcp_rack.ko` and `tcp_bbr.ko`. The HPTS entry is not optional:
`tcp_rack` and `tcp_bbr` both declare `MODULE_DEPEND(<stack>, tcphpts)`, and
`kernel/TRUENAS.amd64` does not set `options TCPHPTS`, so HPTS can only exist
as a module. Stock FreeBSD `GENERIC` omits that option and still ships
`tcphpts.ko`, so this is the upstream arrangement rather than a local one.

The parent `tcp` directory is **not** used in place of the three explicit
entries, because it would pull `tcpmd5` in as well.

`tcp/bbr` is shipped but **not supported**, and the distinction is deliberate.
FreeBSD's BBR is BBRv1: its last stack-specific upstream commit landed
2025-01-09, closing a static-analysis audit pass, and every change since is a
tree-wide sweep that happened to cross it — including the October 2025 HPTS
API rework, which mechanically rewrote roughly 125 lines of its pacing-timer
code in a stack nobody exercises at scale. BBRv1 also competes aggressively
with loss-based flows on shallow-buffered paths, and Linux or GCP results
describing later revisions of the algorithm do not transfer to it.

None of that is a reason to withhold the file, because an unloaded module
changes no behavior, and because the alternative is administrators building
the modules by hand and `kldload`ing them against an ABI nothing tests. Those
are reasons not to *recommend* BBR, and they are why it ships at a lower tier
than RACK rather than not at all.

Nothing loads these modules. No `kld_list`, `loader.conf` or `rc.conf`
fragment is added, and `net.inet.tcp.functions_default` is untouched, so an
image containing them behaves exactly like one without until an administrator
acts.

## Activation

Host, explicit: `kldload tcp_rack` — the linker pulls `tcphpts` in by
dependency. `sysctl net.inet.tcp.functions_available` then lists `rack`
alongside `freebsd`, with the `D` column still on `freebsd`. `kldload tcp_bbr`
behaves the same way and may be loaded alongside `tcp_rack`; both stacks then
appear in the list and neither becomes the default.

**Leave the host default alone.** NFS, iSCSI/CTL and SMB have only ever been
validated on the default stack; changing `net.inet.tcp.functions_default` on
the host changes TCP for every appliance service at once.

Per-jail selection requires a **VNET** jail. `net.inet.tcp.functions_default`
is `CTLFLAG_VNET` without `CTLFLAG_PRISON`, and the sysctl layer grants the
write only when the prison owns its own network stack, so a shared-IP jail is
refused outright. Inside a VNET jail:

```sh
sysctl net.inet.tcp.functions_default=rack
```

The setting applies to TCP connections created afterwards; existing ones keep
the stack they were born with. The host and every other jail are unaffected.

Persistence is the administrator's choice and is **not yet verified on this
image**: the intended paths are a `loader`-type tunable `tcp_rack_load=YES`
for the module, and `/etc/sysctl.conf` inside the jail for the selection.
Confirm both across a reboot before documenting them as working.

## Limitations

- **BBR is shipped but unsupported and unvalidated for behavior.** We confirm
  it is present, loads, and can be selected. We do not validate its
  throughput, its fairness or its retransmission behaviour, and we make no
  performance claim for it against RACK. It is BBRv1; do not enable it on a
  shared uplink on the strength of published BBR results, which describe later
  revisions of the algorithm.
- The kernel does not set `options RATELIMIT`, so pacing is software-only.
  There is no NIC hardware pacing, and none is implied.
- Loading `tcphpts` is not free: its module load allocates a per-CPU HPTS
  entry and registers a software interrupt and callout on every CPU. Modern
  HPTS sleeps when idle, but leave the module unloaded unless it is in use.
- **`tcphpts` does not unload once loaded.** `kldunload tcp_rack` (or
  `tcp_bbr`) succeeds, but
  the timer module then refuses with `Device busy`: upstream returns `EBUSY`
  from its `MOD_QUIESCE` handler on purpose — "allow only forced unload of
  HPTS", because a stack module's function pointers cannot be retired with the
  same guarantees `userret()` gives. `kldunload -f tcphpts` is the only way back
  short of a reboot, and forcing it is not worth doing on a live system. Treat
  loading HPTS as a decision that lasts until the next boot.
- An alternate stack carries its own advisory stream — `SA-26:43.tcp`, a
  use-after-free in the RACK stack option handler, is in the current 15.1
  patch series. Fixes arrive with the base sync; the exposure exists only on
  systems that load the module. That particular advisory is RACK-only:
  `rack_set_sockopt()` cached its `struct tcp_rack *` across the inpcb-lock
  drop for `sooptcopyin()`, while `bbr_set_sockopt()` has always read
  `t_fb_ptr` only after reacquiring the lock and re-checking `tp->t_fb`. Do
  not generalise it into a claim that BBR is the riskier module to load.
- An administrator-selected alternate stack sits outside default support.

## Exact-image acceptance (still required)

1. Payload, in the exact canary image: `tcphpts.ko`, `tcp_rack.ko` and
   `tcp_bbr.ko` all present in `/boot/kernel`. Record the build identity.
2. Default configuration: cold boot and reboot reach READY;
   `net.inet.tcp.functions_available` lists only `freebsd`; `kldstat` shows
   none of the three modules. Nothing is loaded by default, so the release test result
   must be unchanged from the preceding build — any delta is a finding, not
   an expected cost.
3. `kldload tcp_rack` on the host: `kldstat` shows `tcp_rack` **and**
   `tcphpts` pulled in by dependency; `rack` becomes available; the `D` column
   stays on `freebsd`. Repeat for `kldload tcp_bbr`, and confirm both stacks
   loaded together list cleanly with the default still `freebsd`.
4. In a VNET jail: the selection above succeeds, traffic from that jail still
   works, and the host and other jails still report `freebsd` as their
   default. Confirm the same for `bbr`.
5. In a shared-IP jail: the same write is refused. A jail that appears to
   accept it is a finding.
6. `kldunload tcp_rack` and `kldunload tcp_bbr` each succeed and the system
   returns to the default stack. `tcphpts` stays resident by upstream design
   (see Limitations); that is expected, not a defect. Reboot leaves the system on the default stack with
   nothing loaded, and NFS, iSCSI/CTL and SMB behaviour is unchanged throughout.

Not in acceptance, deliberately: BBR throughput, fairness, retransmission
behaviour, or any performance comparison against RACK. We ship the module and
prove it loads and can be selected. What it does with traffic is the
administrator's to measure, and the documentation says so.

The source and profile checks are not runtime proof. Keep the internal development record and the
public issue open until their own evidence exists. the internal development record is closed on its
own evidence against `FreeCORE-15.1-MASTER-202609061234`, which predates the
BBR entry — do not read its acceptance as covering `tcp_bbr.ko`.

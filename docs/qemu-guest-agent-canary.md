# FreeCORE 15.1 QEMU Guest Agent canary

This change ships a dormant QEMU Guest Agent for FreeCORE running **as a
guest** under QEMU/KVM, including Proxmox VE. It does **not** establish bhyve
guest-agent support, another hypervisor, agent-assisted ZFS quiescing,
application-consistent backups, guest trim, or time synchronisation.
the internal development record; public tracking codeberg freecore/freecore#24.

## Build gate

The image selects `emulators/qemu@guestagent` (package `qemu-guest-agent`,
QEMU 10.2.0): only `/usr/local/bin/qemu-ga`, the rc script `qemu-guest-agent`
(`name=qemu_guest_agent`, default `qemu_guest_agent_enable=NO`), keymaps and a
trace-event list. No emulator, tools, firmware or desktop stack. Nothing else
in the image selects `emulators/qemu`, so the flavor's conflict list is moot,
and its only ports dependency is the GLib already present.

`device virtio_console` is compiled into `kernel/TRUENAS.amd64`. The image
previously shipped neither the driver nor its module (`kernel_modules` is a
`MODULES_OVERRIDE` list), so no channel device could appear. The driver names
the host-provided port `/dev/vtcon/org.qemu.guest_agent.0`, qemu-ga's built-in
default, and attaches only when a hypervisor presents a virtio-console device;
bhyve, VMware, Xen and bare metal see no change.

Check the native package build for **no skipped/ignored/missing
`emulators/qemu@guestagent`**. Before `conf-base`, the qemu-guest-agent image
customizer verifies the agent binary and its complete transitive DT_NEEDED
closure inside the image (ports libraries limited to GLib and GLib's own
dependencies), the presence of every allow-listed RPC name in the built agent,
the rc script and its default-disabled state, the absence of any image rc.conf
fragment enabling the service, the absence of `qemu-*` tools and `share/qemu`
firmware, and the kernel's embedded configuration (`INCLUDE_CONFIG_FILE`) for
`virtio_console`. Missing or unexpected payload fails the image build.

The customizer installs only `/usr/local/etc/qemu/qemu-ga.conf`, qemu-ga's
default configuration path; `conf-base` captures it for diskless boot, so it
is restored every boot and rides the update packages:

```ini
[general]
daemon=true
allow-rpcs=guest-ping,guest-info,guest-sync,guest-sync-delimited,guest-get-host-name,guest-get-osinfo,guest-network-get-interfaces,guest-shutdown,guest-fsfreeze-status,guest-fsfreeze-freeze,guest-fsfreeze-freeze-list,guest-fsfreeze-thaw
```

An allow-list flips qemu-ga's fallback from "everything" to "deny unless
listed". Blocked RPCs show `enabled: false` in `guest-info` and are rejected
with `Command <name> has been disabled`. Excluded on purpose: `guest-exec*`,
`guest-file-*`, `guest-set-user-password`, `guest-set-time`, `guest-fstrim`,
`guest-ssh-*`, `guest-suspend-*`. The two sync commands synchronise the
protocol stream, not disks. The `guest-fsfreeze-*` family is allowed
(the internal development record): hypervisor backups call it by default, and on FreeCORE
it suspends nothing (see Limitations), so refusing it only made backup tools
log errors. `daemon=true`
keeps the agent detached even if an administrator's flags override drops the
rc script's default `-d`. It changes no middleware service row, WebUI page,
listener, jail grant (`KEYWORD: nojail`; jail devfs rulesets do not expose
`/dev/vtcon`), or open-vm-tools/xe-guest-utilities configuration.

## Activation and host setup

Guest: the agent is the **QEMU Guest Agent** service (System › Services,
the internal development record); its *Start Automatically* setting owns `qemu_guest_agent_enable`,
and the migration that introduced the service removed any RC tunable of that
name. On the first boot with the guest-agent channel present, the service
enables itself once and remembers the decision (the internal development record); an
administrator's later choice is kept. Per-RPC changes go through the `rc.conf`
tunable `qemu_guest_agent_flags` (System › Tunables, type `rc.conf`), e.g.
`-d -a guest-get-time` widens and `-d -b guest-shutdown` narrows; command-line
lists are concatenated with the file's list and a blocked entry always wins.
Diagnostics: `-d -v -l /var/log/qemu-ga.log`, `qemu-ga -D` (effective
configuration), `qemu-ga --allow-rpcs=help` (every RPC the built agent knows).

Without a channel (enabled on bhyve, VMware, Xen or bare metal) qemu-ga logs
`failed to initialize guest agent channel` once, exits before daemonising, and
the rc framework reports the failed start. No process lingers and no retry
loop runs; upstream `retry-path` stays off.

Proxmox VE: VM › Options › QEMU Guest Agent, or
`qm set <vmid> --agent enabled=1`. Proxmox attaches `virtio-serial` plus
`virtserialport,name=org.qemu.guest_agent.0` backed by
`/var/run/qemu-server/<vmid>.qga`, uses `guest-shutdown` (powerdown mode) for
Shutdown and Reboot with a 60 s default timeout (`qm shutdown <vmid> --timeout
180` if services stop slowly), and calls `guest-fsfreeze-status`,
`guest-fsfreeze-freeze` and `guest-fsfreeze-thaw` around snapshot-mode backups,
clones, snapshots without RAM and replications unless `freeze-fs=0`. On FreeCORE
the freeze returns 0 without suspending anything, so the default works and the
backup log stays clean. Keep `fstrim_cloned_disks=0`: the FreeBSD agent has no
`guest-fstrim`.

Plain QEMU or libvirt:
`-chardev socket,path=/tmp/qga.sock,server=on,wait=off,id=qga0 -device virtio-serial -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0`
(libvirt: `<channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>`).
Talk to it with `socat - UNIX-CONNECT:/tmp/qga.sock`, one JSON object per
line, e.g. `{"execute":"guest-ping"}`. `guest-get-osinfo` reports the FreeBSD
base identity from `/etc/os-release`, not the FreeCORE version in
`/etc/version`.

Shutdown semantics, verified in source: FreeBSD has no `/sbin/poweroff`, so
`guest-shutdown` in powerdown mode (Proxmox's only mode) runs
`/sbin/shutdown -p +0`, which signals init(8) and runs `/etc/rc.shutdown`
including the `ix-shutdown` hooks: the same path as the middleware's own
shutdown and the ACPI power button. Modes `reboot` and `halt` run
`/sbin/reboot` and `/sbin/halt` directly, which stop init, terminate every
process and call reboot(2) **without** `rc.shutdown`; libvirt's
`virsh reboot --mode agent` takes this path. A ports-side patch making BSD use
`shutdown -r/-h +0` is the follow-up in freecore/ports; until then prefer
power-down plus start.

## Limitations

FreeBSD qemu-ga suspends **UFS** filesystems only (`qga/commands-bsd.c`,
`UFSSUSPEND`); ZFS is skipped, and a FreeCORE system mounts nothing else that
it could suspend. `guest-fsfreeze-freeze` therefore opens `/dev/ufssuspend`,
suspends nothing and returns 0; the agent does not stay frozen; `thaw` closes
the device and returns 0. There is no agent-assisted ZFS quiescing or
application-consistent backup: a hypervisor snapshot of a running FreeCORE is
crash-consistent, with or without the freeze. A second freeze without a thaw
in between is refused with `filesystems have already frozen`; the refused call
closes the device itself, so the next freeze succeeds (observed on 15.1-RC5). `guest-fstrim`,
`guest-set-time`, `guest-exec`, guest file access and password changes are
disabled; NTP remains the time source. FreeCORE as a bhyve guest is unchanged.

## Exact-image acceptance (still required)

1. Record ISO name and SHA-256, `_BE/repo-manifest` heads,
   `qemu-guest-agent-10.2.0_1` in the package build log, an empty
   `objs/logs/custom-qemu-guest-agent`, and on the installed image
   `pkg info -d qemu-guest-agent`, `config -x /boot/kernel/kernel | grep
   virtio_console`, `readelf -d /usr/local/bin/qemu-ga | grep NEEDED`,
   `ls /usr/local/bin/qemu-*` (only `qemu-ga`), `cat /usr/local/etc/qemu/qemu-ga.conf`.
2. Default configuration, any hypervisor: cold boot and reboot reach READY
   with no new failed jobs; `service qemu-guest-agent status` reports not
   running; no `qemu-ga` process. open-vm-tools and xe-guest-utilities
   behaviour unchanged by source/config diff and, where a VMware or Xen host is
   available, at runtime. Unavailable hypervisors are documented coverage
   limits, not grounds for inventing results.
3. QEMU/KVM or Proxmox VM (record hypervisor, version and the host device
   line): `/dev/vtcon/org.qemu.guest_agent.0` exists before activation, with no
   `kldload`.
4. With the channel present, **reboot**: the service has enabled itself and
   the agent is running after boot (the internal development record).
5. From the host: `guest-sync-delimited`, `guest-ping`, `guest-info` (exactly
   the twelve allowed RPCs report `enabled: true`), `guest-get-host-name`,
   `guest-get-osinfo`, `guest-network-get-interfaces`; compare with
   `hostname`, `uname` and `ifconfig` in the guest. Proxmox: the IP column of
   the summary panel.
6. Blocked RPCs are rejected without effect: `guest-exec`, `guest-file-open`,
   `guest-set-time` and `guest-fstrim` return `has been disabled`. Do not run
   privileged mutating probes against user data. The freeze family answers:
   `guest-fsfreeze-status` → `thawed`, `guest-fsfreeze-freeze` → `0`, status →
   `thawed`, `guest-fsfreeze-thaw` → `0`.
7. `guest-shutdown` from the host produces a real power-off through
   `rc.shutdown` (console sequence, middleware shutdown event), then a start
   and a successful `guest-ping` afterwards. Proxmox: Shutdown and Reboot with
   the agent enabled, noting the 60 s default. `guest-shutdown` is
   asynchronous; the observed power state is the evidence, not the accepted
   RPC.
8. Turn the service off and reboot: agent stopped, no errors, and it stays
   off (the one-time decision is remembered).
   Enable on a channel-less VM (bhyve canary): exactly one failed-start line,
   no process, READY unaffected.
9. Proxmox backup: snapshot-mode `vzdump` with the default `freeze-fs=1` on a
   running FreeCORE VM; record the log lines (freeze and thaw issued, no agent
   warning or error) and the restore result. This is not a ZFS-consistency
   claim. Without a Proxmox host,
   record a coverage limit rather than inferring a result.
10. The public reply names the first build that actually contains the
    validated feature. Internal implementation, image inclusion and runtime
    acceptance remain separate facts.

Source tests and the image gate are not runtime proof. Keep the internal development record and the
public issue open until their own evidence is available.

QEMU 10.2.0 channel and RPC policy: https://github.com/qemu/qemu/blob/v10.2.0/qga/main.c
QEMU 10.2.0 FreeBSD filesystem handling: https://github.com/qemu/qemu/blob/v10.2.0/qga/commands-bsd.c
QEMU 10.2.0 guest-shutdown command selection: https://github.com/qemu/qemu/blob/v10.2.0/qga/commands-posix.c
Proxmox guest agent options (`freeze-fs`, `fstrim_cloned_disks`): https://pve.proxmox.com/pve-docs/chapter-qm.html#qm_qga_enable

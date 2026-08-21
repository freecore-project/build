# FreeCORE 15.1 headless NVIDIA canary

This change ships a native kernel/SMI/NVML foundation. It does **not** establish
CUDA, NVENC/transcoding, graphics rendering, or shared-jail GPU support.
Maintenance is outside this change.

## Build gate

The image selects `x11/nvidia-driver-headless`, which depends on the exactly
matched `x11/nvidia-kmod-headless`. Both use R580.178.04, separate from the
unselected desktop driver's pin. The kernel slave retains upstream FreeBSD
KPI patches and disables Linux compatibility. Its GSP-default-off patch is
inherited; do not change firmware policy as an incidental test workaround.

`jail.pyd` mounts the image's `OS_ROOT` read-only at `/usr/src` in the ports
build jail. Verify that exact source identity and rebuild the NVIDIA kernel
package whenever those kernel sources change, even if OSVERSION is unchanged.
Preserve both build slots' caches; this is not a reason for a global clean.

Check the native package build for **no skipped/ignored/missing NVIDIA origin**.
Before `conf-base`, the NVIDIA image customizer verifies vendor binary hashes,
all four kernel-module files, the complete base-library DT_NEEDED set, the NVML
dlopen symlink and the license. Missing or mismatched payload fails the image
build. It rejects the desktop `libmap.d/nvidia.conf` override.

The customizer installs only a service-specific `devmatch` blocklist fragment,
preserving existing blocklist entries. `conf-base` then captures that fragment
for diskless boot. It neither disables devmatch globally nor changes kld_list,
loader defaults, services, devfs or jail configuration. The inherited loader
blacklist already includes NVIDIA modules.

## Exact-image acceptance (still required)

1. Record ISO, source manifest, kernel identity and both NVIDIA package versions.
   Compute the **complete** built-module dependency graph with `kldxref`, not a
   filtered subset. Native `nvidia` requires `mem` and `io`, provided by amd64
   DEFAULTS; modeset depends on `nvidia`. Verify these on the artifact itself.
2. GPU-less VM, default configuration: cold boot and reboot reach READY, no new
   failed jobs, no NVIDIA driver loaded, no automatic service or device grant.
   Verify the installed `/conf/base/etc/rc.conf.d/devmatch/freecore-nvidia` and
   runtime policy; existing NIC demand-loading and services remain available.
3. Supported RTX host, default configuration: confirm PCI inventory but **no
   NVIDIA module autoload**, including when opening the GPU dashboard.
4. On the disposable canary, explicitly run `kldload nvidia`, inspect full
   `kldstat`/dmesg and `/dev/nvidia*`, then run `nvidia-smi -q -x`. Compare PCI
   identity, driver version, memory, temperature and available utilization
   counters with `gpu.stats` and the visible GPU card. Unavailable fields are
   not zeroes. Hybrid/Optimus attachment is a hardware-specific acceptance gate.
5. Test the existing System > Tunables RC `kld_list` opt-in, preserving its
   current list and appending `nvidia`. Reboot and repeat. Do not use a LOADER
   `nvidia_load` entry alone or enable modeset/DRM for this headless scope.
6. Remove only that opt-in and reboot: driver stays unloaded and the appliance
   remains healthy. Do not unload any driver while a workload holds its device.
   Do not reclaim a device assigned to a passthrough VM.

Source tests and file/hash checks are not native compilation, module-load,
dashboard or workload proof. Keep the internal development record, the internal development record and the applicable GPU
observation/card acceptance open until their own evidence is available.

Vendor archive/hash: https://download.nvidia.com/XFree86/FreeBSD-x86_64/580.178.04/
Upstream pin: https://cgit.freebsd.org/ports/commit/?id=5b5cb97ca80e3255c15c6bf7bcb300ad707216f4

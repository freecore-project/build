# FreeCORE 15.1 Netgraph userland removal

The appliance excludes Netgraph userland to match its existing lack of
Netgraph kernel support. This corrects the module-addition approach in
`0c132ab`: the intended cleanup is to remove unused components.

Tracking: the internal development record and
[freecore/freecore#56](https://codeberg.org/freecore/freecore/issues/56).
Thanks to tigole for reporting the mismatch and questioning the added modules.

## Change and inherited baseline

TrueNAS CORE removed its Netgraph modules in 2020 (`3e49d91`, NAS-105629)
after its iocage experiment ended, but retained `ngctl`, `nghook`, `flowctl`
and `libnetgraph`. FreeCORE inherited that mismatch; this is a cleanup of
the inherited image, not a FreeBSD 15 regression.

The build profile now sets `WITHOUT_NETGRAPH=yes` and removes the `netgraph`
and `rc4` entries added by `0c132ab`. Its other kernel modules and kernel
configuration are unchanged. No Netgraph capability is added to the product.

## Source dependency checks

Checked against the 15.1 FreeBSD source tip `2fab330fd443`:

- `usr.sbin/Makefile` gates `ngctl`, `nghook` and `flowctl` on `MK_NETGRAPH`.
- `lib/Makefile` gates `libnetgraph`, and `libexec/Makefile` gates `pppoed`,
  on the same option.
- `share/mk/src.opts.mk` defaults `MK_NETGRAPH_SUPPORT` to `MK_NETGRAPH`.
  Consequently `netstat` and `bhyve` omit their optional Netgraph code and
  library dependency. Both programs remain in the appliance. No explicit
  `WITH_NETGRAPH_SUPPORT` override is added.
- PPP, base SNMP and Bluetooth are already disabled in this profile. There
  is no need to retain `libnetgraph` for those consumers.
- `build/tools/build-os.py:create_make_conf_build()` carries the build
  options into all four configurations: build, package-build jail, installed
  appliance and installer. This also applies to SDK builds.
- `build/tools/install-world.py` recreates the world staging directory before
  installing. A normal build/install therefore does not retain old Netgraph
  files merely because build objects are reused. Do not use `SKIP_OS` or
  `SKIP_INSTALL_WORLD` when preparing the first image with this change.

These are source checks, not a completed FreeBSD build or image acceptance.

## Acceptance on the next separately authorized image

Record the build identity and confirm that its build commit includes this
correction. Keep the tracking issue open until the published image is verified.

1. Inspect the staged payload and a fresh installation: no `ngctl`, `nghook`,
   `flowctl`, `pppoed`, or `libnetgraph.so*`; no `netgraph.ko`, `ng_*.ko`, or
   `rc4.ko` in either the normal or debug kernel directory. Inspect the
   installer payload as well.
2. Check the runtime ELF dependency closure: no shipped executable or shared
   library requires `libnetgraph.so.4`. In particular, `netstat` and `bhyve`
   must start without a missing-library error.
3. Verify an upgrade from a preceding image removes the old userland and
   library; if upgrading from an image containing `0c132ab`, verify the added
   modules are also removed. Source configuration alone does not prove
   upgrade cleanup.
4. Verify boot, ordinary network reporting, the normal VM network backend,
   jail networking, and the existing SMB/NFS/iSCSI acceptance remain healthy.

There is no Netgraph module-loading or application-support acceptance.
The 15.0 maintenance line remains outside this correction's scope.

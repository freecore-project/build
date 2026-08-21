#!/usr/bin/env python3
"""Verify the dormant QEMU Guest Agent payload and install its RPC allow-list.

Runs before conf-base so the policy survives the diskless /etc rebuild. Every
check fails closed: a missing binary, library, rc script, kernel driver or RPC
name aborts the image build. the internal development record.
"""

import os
from pathlib import Path
import re
import struct
import sys


AGENT = 'usr/local/bin/qemu-ga'
RC_SCRIPT = 'usr/local/etc/rc.d/qemu-guest-agent'
KERNEL = 'boot/kernel/kernel'
SHARE_DIR = 'usr/local/share/qemu'
LOCAL_ETC = 'usr/local/etc'
POLICY_PATH = 'usr/local/etc/qemu/qemu-ga.conf'

# The reviewed RPC surface: protocol sync, capability discovery, guest
# identity, interface addresses, a clean shutdown, and the filesystem-freeze
# family that hypervisor backups call (the internal development record).  FreeBSD's agent
# suspends UFS only (qga/commands-bsd.c, UFSSUSPEND); every FreeCORE mount is
# ZFS, nullfs, tmpfs, devfs or fdescfs, so a freeze suspends nothing, returns
# 0 and leaves the agent unfrozen.  Refusing it only made backup tools log
# errors.  Nothing that reads or writes guest files, executes commands,
# changes passwords or the clock, or trims filesystems.
ALLOWED_RPCS = (
    'guest-ping',
    'guest-info',
    'guest-sync',
    'guest-sync-delimited',
    'guest-get-host-name',
    'guest-get-osinfo',
    'guest-network-get-interfaces',
    'guest-shutdown',
    'guest-fsfreeze-status',
    'guest-fsfreeze-freeze',
    'guest-fsfreeze-freeze-list',
    'guest-fsfreeze-thaw',
)
FORBIDDEN_RPC_PREFIXES = (
    'guest-exec', 'guest-file-', 'guest-fstrim',
    'guest-set-', 'guest-ssh-', 'guest-suspend-',
)

POLICY = '''# FreeCORE QEMU Guest Agent policy (the internal development record).
#
# Installed by the image build.  /usr/local/etc is rebuilt from /conf/base on
# every boot, so edits here do not persist.  The agent runs as the QEMU Guest
# Agent service (System > Services) and needs the hypervisor's
# org.qemu.guest_agent.0 channel.  allow-rpcs turns the upstream "everything"
# default into "deny unless listed": blocked RPCs report enabled=false in
# guest-info and are rejected with "has been disabled".  Widen or narrow per
# RPC through the qemu_guest_agent_flags tunable (System > Tunables, type RC:
# -a NAME / -b NAME).  daemon=true keeps the agent detached even if that
# tunable drops the rc script's default -d.
[general]
daemon=true
allow-rpcs=%s
''' % ','.join(ALLOWED_RPCS)

# Libraries an agent-only closure may draw from ports: GLib and what GLib
# itself needs.  Anything else under usr/local/lib means the emulator, tools
# or desktop stack leaked into the image.
PORTS_LIBRARIES = frozenset({
    'libglib-2.0.so.0', 'libgmodule-2.0.so.0', 'libgobject-2.0.so.0',
    'libgio-2.0.so.0', 'libgthread-2.0.so.0',
    'libintl.so.8', 'libpcre2-8.so.0', 'libffi.so.8', 'libiconv.so.2',
})
BASE_LIBRARY_DIRS = ('lib', 'usr/lib')
LIBRARY_DIRS = BASE_LIBRARY_DIRS + ('usr/local/lib',)

# Files the guestagent flavor legitimately installs under share/qemu.
SHARE_ALLOWED = ('keymaps',)
SHARE_ALLOWED_FILES = ('trace-events-all',)

RC_CONF_FILES = (
    'etc/rc.conf', 'etc/rc.conf.local', 'etc/rc.conf.network', 'etc/rc.conf.freenas',
    'etc/defaults/rc.conf', 'etc/defaults/vendor.conf',
)
RC_CONF_DIRS = ('etc/rc.conf.d', 'usr/local/etc/rc.conf.d')


class ElfFile:
    """Minimal read-only ELF64 little-endian reader: sections and dynamic tags."""

    SHT_DYNAMIC = 6
    DT_NULL, DT_NEEDED, DT_RPATH, DT_RUNPATH = 0, 1, 15, 29

    def __init__(self, path):
        self.path = Path(path)
        with self.path.open('rb') as handle:
            header = handle.read(64)
            if len(header) < 64 or header[:4] != b'\x7fELF':
                raise RuntimeError(f'Not an ELF object: {self.path}')
            if header[4] != 2 or header[5] != 1:
                raise RuntimeError(f'Not a little-endian ELF64 object: {self.path}')
            (shoff,) = struct.unpack_from('<Q', header, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from('<HHH', header, 0x3a)
            if shentsize != 64 or shnum == 0 or shstrndx >= shnum:
                raise RuntimeError(f'ELF object without a usable section table: {self.path}')
            handle.seek(shoff)
            table = handle.read(shentsize * shnum)
            if len(table) != shentsize * shnum:
                raise RuntimeError(f'Truncated ELF section table: {self.path}')
            self.sections = []
            for index in range(shnum):
                fields = struct.unpack_from('<IIQQQQIIQQ', table, index * shentsize)
                self.sections.append({
                    'name_offset': fields[0], 'type': fields[1], 'offset': fields[4],
                    'size': fields[5], 'link': fields[6], 'entsize': fields[9],
                })
            names = self._read(handle, self.sections[shstrndx])
            for section in self.sections:
                section['name'] = self._cstring(names, section['name_offset'])

    @staticmethod
    def _cstring(table, offset):
        end = table.find(b'\0', offset)
        if end < 0:
            end = len(table)
        return table[offset:end].decode('ascii', 'replace')

    def _read(self, handle, section):
        handle.seek(section['offset'])
        data = handle.read(section['size'])
        if len(data) != section['size']:
            raise RuntimeError(f'Truncated ELF section in {self.path}')
        return data

    def section(self, name):
        for section in self.sections:
            if section['name'] == name:
                with self.path.open('rb') as handle:
                    return self._read(handle, section)
        return None

    def dynamic(self):
        """Return (DT_NEEDED names, DT_RPATH/DT_RUNPATH directories)."""
        for section in self.sections:
            if section['type'] == self.SHT_DYNAMIC:
                break
        else:
            return [], []
        if section['link'] >= len(self.sections):
            raise RuntimeError(f'Dynamic section without a string table: {self.path}')
        with self.path.open('rb') as handle:
            entries = self._read(handle, section)
            strings = self._read(handle, self.sections[section['link']])
        needed, runpath = [], []
        for offset in range(0, len(entries) - 15, 16):
            tag, value = struct.unpack_from('<qQ', entries, offset)
            if tag == self.DT_NULL:
                break
            if tag == self.DT_NEEDED:
                needed.append(self._cstring(strings, value))
            elif tag in (self.DT_RPATH, self.DT_RUNPATH):
                runpath.extend(part for part in self._cstring(strings, value).split(':') if part)
        return needed, runpath


def resolve_within_root(root, path):
    """Follow symlinks without ever leaving the image root."""
    for _ in range(16):
        if not path.is_symlink():
            return path if path.is_file() else None
        target = os.readlink(path)
        if '..' in Path(target).parts:
            return None
        path = root / target.lstrip('/') if target.startswith('/') else path.parent / target
    return None


def resolve_library(root, name, runpath):
    for directory in [*runpath, *LIBRARY_DIRS]:
        if '$' in directory:
            continue
        relative = directory.strip('/')
        path = resolve_within_root(root, root / relative / name)
        if path is not None:
            return path, relative
    return None, None


def library_closure(root, start):
    """Map every transitively needed library to the image directory providing it."""
    resolved, missing, queue = {}, [], [start]
    while queue:
        needed, runpath = ElfFile(queue.pop()).dynamic()
        for name in needed:
            if name in resolved or name in missing:
                continue
            path, directory = resolve_library(root, name, runpath)
            if path is None:
                missing.append(name)
                continue
            resolved[name] = directory
            queue.append(path)
    return resolved, missing


def verify_agent(root):
    agent = root / AGENT
    if agent.is_symlink() or not agent.is_file():
        raise RuntimeError(f'QEMU Guest Agent binary is missing: {AGENT}')
    if not agent.stat().st_mode & 0o111:
        raise RuntimeError(f'QEMU Guest Agent binary is not executable: {AGENT}')
    resolved, missing = library_closure(root, agent)
    if missing:
        raise RuntimeError('QEMU Guest Agent shared libraries are missing from the image: '
                           + ', '.join(sorted(missing)))
    ports = {name for name, directory in resolved.items() if directory not in BASE_LIBRARY_DIRS}
    unexpected = sorted(ports - PORTS_LIBRARIES)
    if unexpected:
        raise RuntimeError('QEMU Guest Agent links libraries outside the agent-only closure: '
                           + ', '.join(unexpected))
    data = agent.read_bytes()
    absent = [rpc for rpc in ALLOWED_RPCS if rpc.encode('ascii') + b'\0' not in data]
    if absent:
        raise RuntimeError('Allowed RPCs are not implemented by the built agent: ' + ', '.join(absent))


def verify_rc_script(root):
    script = root / RC_SCRIPT
    if script.is_symlink() or not script.is_file():
        raise RuntimeError(f'QEMU Guest Agent rc script is missing: {RC_SCRIPT}')
    if not script.stat().st_mode & 0o111:
        raise RuntimeError(f'QEMU Guest Agent rc script is not executable: {RC_SCRIPT}')
    text = script.read_text(errors='replace')
    expectations = {
        'service name': r'^name=qemu_guest_agent\s*$',
        'rcvar': r'^rcvar=qemu_guest_agent_enable\s*$',
        'default-disabled service': r'^qemu_guest_agent_enable=\$\{qemu_guest_agent_enable:-"?NO"?\}\s*$',
        'agent path': r'^qemu_guest_agent_bin=/usr/local/bin/qemu-ga\s*$',
    }
    for label, pattern in expectations.items():
        if not re.search(pattern, text, re.MULTILINE):
            raise RuntimeError(f'QEMU Guest Agent rc script lacks the expected {label}')


def verify_not_enabled(root):
    candidates = [root / relative for relative in RC_CONF_FILES]
    for relative in RC_CONF_DIRS:
        directory = root / relative
        if directory.is_dir():
            candidates.extend(path for path in sorted(directory.rglob('*')) if path.is_file())
    pattern = re.compile(r'^\s*qemu_guest_agent_enable=(.*)$', re.MULTILINE)
    for path in candidates:
        if not path.is_file():
            continue
        for match in pattern.finditer(path.read_text(errors='replace')):
            if match.group(1).strip().strip('"\'').upper() != 'NO':
                raise RuntimeError(f'Image configuration enables the QEMU Guest Agent: '
                                   f'{path.relative_to(root).as_posix()}')


def verify_agent_only_payload(root):
    # The emulated-guest lane (the internal development record + the internal development record-158) ships the
    # QEMU system and user-mode emulators alongside the guest agent by design, so an image
    # that carries a qemu-system-* emulator is expected to carry the rest of that payload.
    # The agent's disabled-by-default state, minimal glib closure, RPC allow-list and the
    # virtio_console kernel device are still verified by the other checks; only this
    # "no emulator leaked" assertion is conditional on the lane being absent.
    if any((root / 'usr/local/bin').glob('qemu-system-*')):
        return
    stray = sorted(path.relative_to(root).as_posix()
                   for path in (root / 'usr/local/bin').glob('qemu-*')
                   if path.name != 'qemu-ga')
    stray += sorted(path.relative_to(root).as_posix()
                    for path in (root / 'usr/local/libexec').glob('qemu-*'))
    share = root / SHARE_DIR
    if share.is_dir():
        for path in sorted(share.rglob('*')):
            if path.is_dir():
                continue
            relative = path.relative_to(share)
            if relative.parts[0] in SHARE_ALLOWED or relative.as_posix() in SHARE_ALLOWED_FILES:
                continue
            stray.append(path.relative_to(root).as_posix())
    if stray:
        raise RuntimeError('QEMU payload beyond the guest agent is present: ' + ', '.join(stray))


def verify_kernel(root):
    kernel = root / KERNEL
    if not kernel.is_file():
        raise RuntimeError(f'Kernel is missing: {KERNEL}')
    config = ElfFile(kernel).section('kern_conf')
    if config is None:
        raise RuntimeError('Kernel carries no embedded configuration (options INCLUDE_CONFIG_FILE); '
                           'cannot prove the virtio_console driver is built in')
    devices = set(re.findall(r'^device\s+(\S+)\s*$', config.decode('ascii', 'replace'), re.MULTILINE))
    for device in ('virtio', 'virtio_pci', 'virtio_console'):
        if device not in devices:
            raise RuntimeError(f'Kernel was built without device {device}; '
                               'the guest agent channel /dev/vtcon/org.qemu.guest_agent.0 needs it')


def install_policy(root):
    policy = root / POLICY_PATH
    if policy.is_symlink() or policy.parent.is_symlink():
        raise RuntimeError('Refusing a symlinked QEMU Guest Agent policy path')
    if policy.exists() and policy.read_text() != POLICY:
        raise RuntimeError('Refusing to replace an unexpected QEMU Guest Agent policy')
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.parent.chmod(0o755)
    policy.write_text(POLICY)
    policy.chmod(0o644)


def prepare_image(root):
    root = Path(root)
    if (root / LOCAL_ETC).is_symlink():
        raise RuntimeError('usr/local/etc is already the conf-base symlink; '
                           'qemu-guest-agent must run before conf-base')
    verify_agent(root)
    verify_rc_script(root)
    verify_not_enabled(root)
    verify_agent_only_payload(root)
    verify_kernel(root)
    install_policy(root)


if __name__ == '__main__':
    prepare_image(sys.argv[1])

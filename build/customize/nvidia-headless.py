#!/usr/bin/env python3
"""Verify the native NVIDIA subset and keep hardware demand-loading opt-in."""

import hashlib
from pathlib import Path
import sys


# Unmodified binaries from the reviewed FreeBSD R580.178.04 distfile. A new
# driver pin must update both ports and this image gate deliberately.
BINARY_HASHES = {
    'usr/local/bin/nvidia-smi':
        '4f055484a5c8eb4d0d498c56d4a8c2726e4210b282bc2f4d16bb161b02ffac78',
    'usr/local/lib/libnvidia-ml.so.1':
        '5d7254920a17ea0f0978389bdfae2fc4ec3969b545968dd457f9d828e79c8910',
}
MODULES = ('nvidia', 'nvidia-modeset', 'nvidia_gsp_ga10x_fw', 'nvidia_gsp_tu10x_fw')
# DT_NEEDED union of both vendor ELFs plus FreeBSD 15's libsys dependency.
# NVML itself is dlopen'ed by SMI.
BASE_LIBRARIES = (
    'lib/libthr.so.3', 'lib/libm.so.5', 'lib/libc.so.7', 'lib/librt.so.1', 'lib/libsys.so.7',
)
POLICY_PATH = 'etc/rc.conf.d/devmatch/freecore-nvidia'
POLICY = '''# FreeCORE: NVIDIA remains opt-in, including devmatch/devd events.
# Explicit kldload and the administrator's RC kld_list are unaffected.
devmatch_blocklist="${devmatch_blocklist:-${devmatch_blacklist:-}} nvidia nvidia-modeset nvidia-drm"
'''


def prepare_image(root):
    root = Path(root)
    for relative, expected in BINARY_HASHES.items():
        path = root / relative
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f'NVIDIA binary version/content mismatch: {relative}')
    for relative in [*(f'boot/modules/{name}.ko' for name in MODULES), *BASE_LIBRARIES]:
        with (root / relative).open('rb') as dependency:
            if dependency.read(4) != b'\x7fELF':
                raise RuntimeError(f'Missing/invalid NVIDIA dependency: {relative}')
    nvml_link = root / 'usr/local/lib/libnvidia-ml.so'
    if not nvml_link.is_symlink() or nvml_link.readlink() != Path('libnvidia-ml.so.1'):
        raise RuntimeError('Missing/incorrect NVML dlopen symlink')
    license_file = root / 'usr/local/share/nvidia-headless/license.txt'
    if not license_file.is_file() or license_file.stat().st_size == 0:
        raise RuntimeError('NVIDIA redistribution license is missing')
    if (root / 'usr/local/etc/libmap.d/nvidia.conf').exists():
        raise RuntimeError('Desktop NVIDIA libmap override is not part of the headless image')

    policy = root / POLICY_PATH
    if policy.is_symlink() or policy.parent.is_symlink():
        raise RuntimeError('Refusing a symlinked NVIDIA loading policy')
    if policy.exists() and policy.read_text() != POLICY:
        raise RuntimeError('Refusing to replace an unexpected NVIDIA loading policy')
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text(POLICY)
    policy.chmod(0o644)


if __name__ == '__main__':
    prepare_image(sys.argv[1])

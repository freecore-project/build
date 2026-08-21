#!/usr/bin/env python3
#+
# Copyright 2015 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import sys
import os
from utils import sh, e, env, objdir, info, error, import_function
from kernel_identity import expected_ident, ident_matches, baked_version


installworldlog = objdir('logs/dest-installworld')
distributionlog = objdir('logs/dest-distribution')
installkernellog = objdir('logs/dest-installkernel')
installkerneldebuglog = objdir('logs/dest-installkerneldebug')
installworld = import_function('build-os', 'installworld')
installkernel = import_function('build-os', 'installkernel')


def assert_kernel_identity(kernel):
    # the internal development record: never stage a kernel that names another os commit.
    if env('SKIP_KERNEL_IDENTITY_GUARD'):
        info('Skipping kernel identity check as instructed by setting SKIP_KERNEL_IDENTITY_GUARD')
        return
    expect = expected_ident(e('${OS_ROOT}'))
    if expect is None:
        info('Kernel identity check: no git identity for {0}, not checked', e('${OS_ROOT}'))
        return
    with open(kernel, 'rb') as f:
        text = f.read().decode('latin-1')
    if not ident_matches(text, expect):
        error('{0} identifies as "{1}", expected {2}', kernel, baked_version(text), expect)
    info('Kernel identity {0}: {1}', kernel, expect)


if __name__ == '__main__':
    if e('${SKIP_INSTALL_WORLD}'):
        info('Skipping world installation, as instructed by setting SKIP_INSTALL_WORLD')
        sys.exit(0)

    if os.path.isdir(e('${WORLD_DESTDIR}')):
        sh('chflags -fR 0 ${WORLD_DESTDIR}')
        sh('rm -rf ${WORLD_DESTDIR}')

    sh('mkdir -p ${WORLD_DESTDIR}')
    installworld(e('${WORLD_DESTDIR}'), installworldlog, distributionlog, conf="run")
    installkernel(e('${KERNCONF}'), e('${WORLD_DESTDIR}'), installkernellog, conf="run")
    installkernel(
        e('${KERNCONF}-DEBUG'),
        e('${WORLD_DESTDIR}'),
        installkerneldebuglog,
        kodir="/boot/kernel-debug",
        conf="run"
    )
    assert_kernel_identity(e('${WORLD_DESTDIR}/boot/kernel/kernel'))
    assert_kernel_identity(e('${WORLD_DESTDIR}/boot/kernel-debug/kernel'))

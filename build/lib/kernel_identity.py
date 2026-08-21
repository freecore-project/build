"""Kernel identity guard (the internal development record, follows the internal development record).

buildkernel runs with NO_KERNELCLEAN=YES against a preserved obj tree, so an
os move that touches no kernel-proper object (module sources, userland)
relinks nothing and sys/conf/newvers.sh never restamps vers.c: the old
identity is staged. These helpers compute the git token newvers.sh would
emit for the os checkout and compare it with a baked vers.c or kernel.
"""

import os
import re
import subprocess


GIT_DIRS = ('/usr/bin', '/usr/local/bin')
SCCS = re.compile(r'@\(#\)([^"\n\\\x00]*)')


def findvcs(os_root, name):
    """Return the directory holding `name`, walking up from os_root like newvers.sh."""
    path = os.path.realpath(os_root)
    while path != '/':
        if os.path.exists(os.path.join(path, name)):
            return path
        path = os.path.dirname(path)
    return None


def find_git(dirs=GIT_DIRS):
    for d in dirs:
        candidate = os.path.join(d, 'git')
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def expected_ident(os_root, git=None):
    """Git token newvers.sh emits for os_root, e.g.
    `freecore/15.0-maintenance-n75-f51d144a6266`, or None if it emits none.

    Mirrors newvers.sh: short=12 hash, `n<first-parent count>-` unless the
    repository is shallow, `<branch>-` unless HEAD is detached, `-dirty` if
    the work tree is modified.
    """
    top = findvcs(os_root, '.git')
    if top is None:
        return None
    if git is None:
        git = find_git()
    if git is None:
        return None
    cmd = [git, '-c', 'help.autocorrect=0', '--git-dir=' + os.path.join(top, '.git')]

    def run(*args):
        p = subprocess.run(cmd + list(args), stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, universal_newlines=True)
        return p.returncode, p.stdout.strip()

    rc, ident = run('rev-parse', '--verify', '--short=12', 'HEAD')
    if rc != 0 or not ident:
        return None
    if run('rev-parse', '--is-shallow-repository')[1] == 'false':
        rc, count = run('rev-list', '--first-parent', '--count', 'HEAD')
        if rc == 0 and count:
            ident = 'n{0}-{1}'.format(count, ident)
    branch = run('rev-parse', '--abbrev-ref', 'HEAD')[1]
    if branch and branch != 'HEAD':
        ident = '{0}-{1}'.format(branch, ident)
    rc, _ = run('--work-tree=' + top, '-c', 'core.checkStat=minimal',
                '-c', 'core.fileMode=off', 'diff', '--quiet')
    if rc != 0:
        ident = ident + '-dirty'
    return ident


def baked_version(text):
    """The `@(#)` version string found in vers.c or a kernel, or None."""
    m = SCCS.search(text)
    return m.group(1).strip() if m else None


def ident_matches(text, ident):
    """True if text (vers.c source or kernel bytes decoded latin-1) carries ident
    as the newvers.sh git token: ` <ident>` followed by ` ` or `:`."""
    return re.search(' ' + re.escape(ident) + '[ :]', text) is not None


def stale_kernel_obj(vers_c, ident):
    """Return (stale, baked) for a KERNCONF obj dir's vers.c.

    stale is True only when vers.c exists, ident is known, and vers.c does not
    carry ident. A missing vers.c (fresh obj dir) or unknown ident is not stale.
    """
    if ident is None or not os.path.isfile(vers_c):
        return False, None
    with open(vers_c, 'r', encoding='latin-1') as f:
        text = f.read()
    return not ident_matches(text, ident), baked_version(text)

#!/bin/sh
# Initialize FreeCORE plugin package signing material on the release signer.
# Private key stays under /usr/local/etc/freecore-plugin-pki/private.
#
# This mirrors the operational shape of zfs-one-init-update-pki.sh -- same owner,
# same modes, same layout -- but deliberately NOT its X.509 CA hierarchy. pkg's
# signature_type=fingerprints validates a raw public key against a sha256
# fingerprint and performs no certificate chain validation, so a CA-signed cert
# would be meaningless to it. Do not "fix" this by bolting on the update CA.
#
# The update/ISO PKI is a separate flow and is not touched by this script.

set -eu

PKI_ROOT=${PKI_ROOT:-/usr/local/etc/freecore-plugin-pki}
PRIVATE_DIR="${PKI_ROOT}/private"
PUBLIC_DIR="${PKI_ROOT}/public"
USER_NAME=${RELEASE_USER:-release-publisher}
GROUP_NAME=${RELEASE_GROUP:-release-publisher}
KEY_NAME=${KEY_NAME:-freecore-plugin-pkg}
KEY_BITS=${KEY_BITS:-4096}

if [ "$(id -u)" != "0" ]; then
    echo "Run as root on the release signer" >&2
    exit 1
fi

if ! pw groupshow "${GROUP_NAME}" >/dev/null 2>&1; then
    pw groupadd "${GROUP_NAME}"
fi

if ! id "${USER_NAME}" >/dev/null 2>&1; then
    pw useradd "${USER_NAME}" -g "${GROUP_NAME}" -d /nonexistent \
        -s /usr/sbin/nologin -c "FreeCORE release publisher"
fi

install -d -m 0700 -o "${USER_NAME}" -g "${GROUP_NAME}" "${PRIVATE_DIR}"
install -d -m 0755 -o root -g wheel "${PUBLIC_DIR}"

KEY="${PRIVATE_DIR}/${KEY_NAME}.key"
PUB="${PUBLIC_DIR}/${KEY_NAME}.pub"

# Never regenerate an existing key. sha256(PUB) is the fingerprint baked into
# every published plugin manifest and into every already-installed plugin jail,
# so replacing the key means manifest churn plus breaking existing installs.
if [ ! -f "${KEY}" ]; then
    openssl genrsa -out "${KEY}" "${KEY_BITS}"
fi
chmod 0600 "${KEY}"
chown "${USER_NAME}:${GROUP_NAME}" "${KEY}"

if [ ! -f "${PUB}" ]; then
    openssl rsa -in "${KEY}" -pubout -out "${PUB}"
fi
chmod 0644 "${PUB}"
chown root:wheel "${PUB}"

# A public key that does not match the private key would produce signatures that
# fail fingerprint validation inside every plugin jail, so fail loudly here.
if ! openssl pkey -in "${KEY}" -pubout 2>/dev/null | cmp -s - "${PUB}"; then
    echo "FATAL: ${PUB} does not match ${KEY}" >&2
    exit 1
fi

echo "Private key: ${KEY}"
echo "Public key:  ${PUB}"
echo "Fingerprint: $(sha256 -q "${PUB}")"
echo
echo "Plugin manifests carry that value under the existing \"zfs-one\" label:"
echo '  "fingerprints": { "zfs-one": [ { "function": "sha256", "fingerprint": "<above>" } ] }'
echo
echo "Back the PKI up through the project's offline key-backup procedure after any change:"
echo "  tar -czf freecore-plugin-pki-backup-\$(date +%Y%m%d).tgz -C /usr/local/etc freecore-plugin-pki"

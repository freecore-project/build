#!/bin/sh
# Initialize update signing material on the signer (the release signer).
# Private keys stay under ${PKI_ROOT}/private and never leave this host.
#
# Parameterised by PRODUCT/ORG rather than hardcoded (the internal development record).
# the internal development record (cdrom loader title) and the internal development record (installer OS=) were both
# hardcoded product literals that the PRODUCT cascade could not reach; one of
# them blocked every FreeCORE install. Renaming again should be an env var,
# not an edit to this file.
#
# The naming cluster below is load-bearing and must move as one unit: the CA
# file name, the CA subject, the CRL file name and the per-train cert names
# are also referenced from freenas-pkgtools (certificates/Makefile,
# files/pkg-plist, lib/__init__.py), middleware's nas_ports pkg-plist and
# build's pkg-tools config. Renaming any subset produces an image that cannot
# verify its own update train, and it reviews clean.
#
# Every step is guarded by "if [ ! -f ]", so this script is idempotent and
# ADDITIVE: running it with a new PRODUCT mints beside the previous material
# rather than replacing it. Retiring an old product's CA/trains is a separate,
# deliberate act.

set -eu

PRODUCT=${PRODUCT:-FreeCORE}
ORG=${ORG:-FreeCORE}
COUNTRY=${COUNTRY:-US}
VERSION_SERIES=${VERSION_SERIES:-15.0}

PKI_ROOT=${PKI_ROOT:-/usr/local/etc/zfs-one-update-pki}
PRIVATE_DIR="${PKI_ROOT}/private"
PUBLIC_DIR="${PKI_ROOT}/public"
USER_NAME=${RELEASE_USER:-release-publisher}
GROUP_NAME=${RELEASE_GROUP:-release-publisher}
DAYS=${CERT_DAYS:-3650}

# File names use the lowercased product; cert CNs use it verbatim. Both halves
# are overridable so a rename never has to touch this file.
PRODUCT_LC=$(echo "${PRODUCT}" | tr '[:upper:]' '[:lower:]')
CA_BASENAME=${CA_BASENAME:-${PRODUCT_LC}-update-ca}
CRL_BASENAME=${CRL_BASENAME:-${PRODUCT_LC}_update_crl}

# Train-agnostic certs first, then the per-train leaves. FreeCORE-15.0-STABLE
# is minted up front because freecore-website's enrollment script (the internal development record)
# installs that leaf on a 13.3 box; minting it later would mean re-opening the
# PKI, which is what this one-shot re-mint exists to avoid.
TRAIN_CERTS=${TRAIN_CERTS:-"${PRODUCT}-Nightlies ${PRODUCT}-Production ${PRODUCT}-${VERSION_SERIES}-Nightlies ${PRODUCT}-${VERSION_SERIES}-STABLE"}

if [ "$(id -u)" != "0" ]; then
    echo "Run as root on the signer" >&2
    exit 1
fi

if ! pw groupshow "${GROUP_NAME}" >/dev/null 2>&1; then
    pw groupadd "${GROUP_NAME}"
fi

if ! id "${USER_NAME}" >/dev/null 2>&1; then
    pw useradd "${USER_NAME}" -g "${GROUP_NAME}" -d /nonexistent -s /usr/sbin/nologin -c "${ORG} release publisher"
fi

install -d -m 0700 -o "${USER_NAME}" -g "${GROUP_NAME}" "${PRIVATE_DIR}"
install -d -m 0755 -o root -g wheel "${PUBLIC_DIR}"

CA_KEY="${PRIVATE_DIR}/${CA_BASENAME}.key"
CA_CERT="${PUBLIC_DIR}/${CA_BASENAME}.pem"
CRL_FILE="${PUBLIC_DIR}/${CRL_BASENAME}.pem"

if [ ! -f "${CA_KEY}" ]; then
    openssl genrsa -out "${CA_KEY}" 4096
    chmod 0600 "${CA_KEY}"
    chown "${USER_NAME}:${GROUP_NAME}" "${CA_KEY}"
fi

if [ ! -f "${CA_CERT}" ]; then
    openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days "${DAYS}" \
        -subj "/C=${COUNTRY}/O=${ORG}/CN=${PRODUCT} Update CA" \
        -out "${CA_CERT}"
fi

make_train_cert() {
    name=$1
    key="${PRIVATE_DIR}/${name}.key"
    csr="${PRIVATE_DIR}/${name}.csr"
    cert="${PUBLIC_DIR}/${name}.pem"

    if [ ! -f "${key}" ]; then
        openssl genrsa -out "${key}" 4096
        chmod 0600 "${key}"
        chown "${USER_NAME}:${GROUP_NAME}" "${key}"
    fi

    if [ ! -f "${cert}" ]; then
        openssl req -new -key "${key}" \
            -subj "/C=${COUNTRY}/O=${ORG}/CN=${name}" \
            -out "${csr}"
        openssl x509 -req -in "${csr}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
            -CAcreateserial -out "${cert}" -days "${DAYS}" -sha256
        rm -f "${csr}"
    fi
}

for _cert_name in ${TRAIN_CERTS}; do
    make_train_cert "${_cert_name}"
done

if [ ! -f "${CRL_FILE}" ]; then
    : > "${CRL_FILE}"
fi

echo "Product:      ${PRODUCT} (O=${ORG})"
echo "CA:           ${CA_CERT}"
echo "CRL:          ${CRL_FILE}"
echo "Public certs: ${PUBLIC_DIR}"
echo "Private keys: ${PRIVATE_DIR}"
echo "Use ${PRIVATE_DIR}/${PRODUCT}-${VERSION_SERIES}-Nightlies.key as the freenas-release signing key for the nightlies train."

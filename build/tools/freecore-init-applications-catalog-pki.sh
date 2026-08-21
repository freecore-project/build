#!/bin/sh
# Mint the dedicated FreeCORE Applications catalog signing leaf on the release signer.
#
# The leaf is deliberately separate from update-train signing certificates.  Its
# public certificate is pinned in every image; its private key never leaves the
# signer.  This script is additive and idempotent: an existing key is never
# replaced, and an existing certificate must still match the required profile.
#
# the internal development record

set -eu

PKI_ROOT=${PKI_ROOT:-/usr/local/etc/zfs-one-update-pki}
PRIVATE_DIR="${PKI_ROOT}/private"
PUBLIC_DIR="${PKI_ROOT}/public"
USER_NAME=${RELEASE_USER:-release-publisher}
GROUP_NAME=${RELEASE_GROUP:-release-publisher}
COUNTRY=${COUNTRY:-US}
ORG=${ORG:-FreeCORE}
KEY_BITS=4096
CERT_DAYS=1825
NAME=freecore-applications-catalog
COMMON_NAME='FreeCORE Applications Catalog'

CA_KEY="${PRIVATE_DIR}/freecore-update-ca.key"
CA_CERT="${PUBLIC_DIR}/freecore-update-ca.pem"
KEY="${PRIVATE_DIR}/${NAME}.key"
CERT="${PUBLIC_DIR}/${NAME}.pem"

fail()
{
    echo "FATAL: $*" >&2
    exit 1
}

if [ "$(id -u)" != "0" ]; then
    fail "run as root on the release signer"
fi
if [ ! -s "${CA_KEY}" ] || [ ! -s "${CA_CERT}" ]; then
    fail "the existing FreeCORE Update CA is unavailable"
fi
ca_subject=$(openssl x509 -in "${CA_CERT}" -noout -subject -nameopt RFC2253)
ca_subject=${ca_subject#subject=}
if ! echo "${ca_subject}" | grep -Eq '(^|,)CN=FreeCORE Update CA(,|$)'; then
    fail "the configured issuer is not the FreeCORE Update CA"
fi
# Compare only public DER hashes; key material and private paths are never
# printed by this script.
ca_key_id=$(openssl pkey -in "${CA_KEY}" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)
ca_cert_id=$(openssl x509 -in "${CA_CERT}" -pubkey -noout |
    openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)
[ "${ca_key_id}" = "${ca_cert_id}" ] || fail "the Update CA key does not match its certificate"

install -d -m 0700 -o "${USER_NAME}" -g "${GROUP_NAME}" "${PRIVATE_DIR}"
install -d -m 0755 -o root -g wheel "${PUBLIC_DIR}"

if [ -e "${CERT}" ] && [ ! -e "${KEY}" ]; then
    fail "the existing catalog certificate has no matching private key"
fi
if [ ! -e "${KEY}" ]; then
    openssl genrsa -out "${KEY}" "${KEY_BITS}"
fi
chmod 0600 "${KEY}"
chown "${USER_NAME}:${GROUP_NAME}" "${KEY}"

if [ ! -e "${CERT}" ]; then
    request=$(mktemp /tmp/freecore-applications-catalog.csr.XXXXXX)
    extensions=$(mktemp /tmp/freecore-applications-catalog.ext.XXXXXX)
    trap 'rm -f "${request}" "${extensions}"' EXIT HUP INT TERM

    openssl req -new -key "${KEY}" \
        -subj "/C=${COUNTRY}/O=${ORG}/CN=${COMMON_NAME}" \
        -out "${request}"
    {
        echo 'basicConstraints=critical,CA:FALSE'
        echo 'keyUsage=critical,digitalSignature'
        echo 'extendedKeyUsage=critical,codeSigning'
        echo 'subjectKeyIdentifier=hash'
        echo 'authorityKeyIdentifier=keyid,issuer'
    } > "${extensions}"
    openssl x509 -req -in "${request}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
        -CAcreateserial -days "${CERT_DAYS}" -sha256 \
        -extfile "${extensions}" -out "${CERT}"
    rm -f "${request}" "${extensions}"
    trap - EXIT HUP INT TERM
fi

# Reject a combined PEM before making the certificate world-readable.  The
# catalog signature envelope embeds this file, so accepting trailing private
# key material here would publish the signing key.
canonical_certificate=$(mktemp /tmp/freecore-applications-catalog.pem.XXXXXX)
trap 'rm -f "${canonical_certificate}"' EXIT HUP INT TERM
openssl x509 -in "${CERT}" -out "${canonical_certificate}"
cmp -s "${CERT}" "${canonical_certificate}" || fail "catalog certificate PEM contains non-certificate data"

subject=$(openssl x509 -in "${CERT}" -noout -subject -nameopt RFC2253)
subject=${subject#subject=}
[ "$(echo "${subject}" | grep -o 'CN=' | wc -l | tr -d ' ')" = "1" ] ||
    fail "catalog certificate must contain exactly one common name"
echo "${subject}" | grep -Eq '(^|,)CN=FreeCORE Applications Catalog(,|$)' ||
    fail "catalog certificate has the wrong identity"

key_id=$(openssl pkey -in "${KEY}" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)
cert_id=$(openssl x509 -in "${CERT}" -pubkey -noout |
    openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)
[ "${key_id}" = "${cert_id}" ] || fail "the catalog key does not match its certificate"

openssl verify -CAfile "${CA_CERT}" "${CERT}" >/dev/null || fail "catalog certificate chain validation failed"
certificate_text=$(openssl x509 -in "${CERT}" -noout -text)
echo "${certificate_text}" | grep -Eq 'Public-Key: \(4096 bit\)' || fail "catalog key is not RSA-4096"
echo "${certificate_text}" | grep -Eq 'Signature Algorithm: sha256WithRSAEncryption' ||
    fail "catalog certificate signature algorithm is invalid"
echo "${certificate_text}" | grep -A1 'X509v3 Basic Constraints: critical' |
    grep -Eq 'CA:FALSE' || fail "catalog certificate is not a constrained leaf"
echo "${certificate_text}" | grep -A1 'X509v3 Key Usage: critical' |
    tail -1 | grep -Eq '^[[:space:]]*Digital Signature[[:space:]]*$' ||
    fail "catalog certificate key usage is invalid"
echo "${certificate_text}" | grep -A1 'X509v3 Extended Key Usage: critical' |
    tail -1 | grep -Eq '^[[:space:]]*Code Signing[[:space:]]*$' ||
    fail "catalog certificate extended key usage is invalid"

chmod 0644 "${CERT}"
chown root:wheel "${CERT}"
rm -f "${canonical_certificate}"
trap - EXIT HUP INT TERM

# Print only public metadata.  Private key locations and material are never
# emitted by this tool.
openssl x509 -in "${CERT}" -noout -subject -issuer -serial -dates -fingerprint -sha256
echo "Applications catalog signing leaf is ready."

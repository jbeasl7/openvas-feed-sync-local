# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: Normally defined in byte_func.inc but openvas-nasl-lint will report
# those as not declared in this include.
# Little-endian byte order
BYTE_ORDER_LITTLE_ENDIAN = 1;
# Big-endian byte order
BYTE_ORDER_BIG_ENDIAN = 2;

# nb: These ones are passed globally by ssl_funcs.inc on run-time of the calling VT and were added
# here to silent an undeclared variable reporting of openvas-nasl-lint.
global_var sslv3_tls_raw_ciphers, ec_point_formats, elliptic_curves, signature_schemes;

# @brief Creates a DTLS 1.3 Client Hello packet
#
# @param random Client random to send to the server (32 bytes)
# @param seq_num Sequence number to use
#
# @return Created DTLS 1.3 Client Hello packet if success otherwise NULL
#
function dtls_create_13_client_hello(random, seq_num) {

  local_var random, seq_num;
  local_var fragment, handshake_proto, data, data_len, dtls_header;

  if (isnull(random)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#random#-#dtls_create_13_client_hello");
    return NULL;
  }

  if (isnull(seq_num)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#seq_num#-#dtls_create_13_client_hello");
    return NULL;
  }

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  # n.b. Empty key share should be possible according to RFC 8446 section 4.2.8
  # in order to trigger server side selection of the curve.
  # However it is easier to just supply a key and guess the curve as the server
  # will react either way as he either supports the key and curve or responds
  # with his selected curve as we offer all curves.
  fragment = raw_string(0xfe, 0xfd,                # Version
                        random,                    # Client Random
                        0x00,                      # Session ID length
                        0x00,                      # Cookie length
                        0x00, 0x0A,                # Ciphersuite Length
                        sslv3_tls_raw_ciphers["TLS_AES_128_GCM_SHA256"],
                        sslv3_tls_raw_ciphers["TLS_AES_256_GCM_SHA384"],
                        sslv3_tls_raw_ciphers["TLS_CHACHA20_POLY1305_SHA256"],
                        sslv3_tls_raw_ciphers["TLS_AES_128_CCM_SHA256"],
                        sslv3_tls_raw_ciphers["TLS_AES_128_CCM_8_SHA256"],
                        0x01,                      # Compression Method length
                        0x00,                      # Compression Method
                        0x00, 0x6D,                # Extension length
                        0x00, 0x0a,                # Type: supported groups
                        0x00, 0x16,                # Length
                        0x00, 0x14,                # Supported Groups List Length
                        elliptic_curves["secp256r1"],
                        elliptic_curves["secp384r1"],
                        elliptic_curves["secp521r1"],
                        elliptic_curves["x25519"],
                        elliptic_curves["x448"],
                        elliptic_curves["ffdhe2048"],
                        elliptic_curves["ffdhe3072"],
                        elliptic_curves["ffdhe4096"],
                        elliptic_curves["ffdhe6144"],
                        elliptic_curves["ffdhe8192"],
                        0x00, 0x0d,                # Type: signature algorithms
                        0x00, 0x1E,                # Length
                        0x00, 0x1C,                # Number of suites
                        signature_schemes["rsa_pkcs1_sha256"],
                        signature_schemes["rsa_pkcs1_sha384"],
                        signature_schemes["rsa_pkcs1_sha512"],
                        signature_schemes["ecdsa_secp256r1_sha256"],
                        signature_schemes["ecdsa_secp384r1_sha384"],
                        signature_schemes["ecdsa_secp521r1_sha512"],
                        signature_schemes["rsa_pss_rsae_sha256"],
                        signature_schemes["rsa_pss_rsae_sha384"],
                        signature_schemes["rsa_pss_rsae_sha512"],
                        signature_schemes["ed25519"],
                        signature_schemes["ed448"],
                        signature_schemes["rsa_pss_pss_sha256"],
                        signature_schemes["rsa_pss_pss_sha384"],
                        signature_schemes["rsa_pss_pss_sha512"],
                        0x00, 0x2b,                # Type: supported versions
                        0x00, 0x03,                # Length
                        0x02,                      # Supported Versions List Length
                        0xfe, 0xfc,                # DTLS 1.3 ID
                        0x00, 0x33,                # Type: key share
                        0x00, 0x26,                # Length
                        0x00, 0x24,                # Key/Group Pair List
                        0x00, 0x1d,                # Preshared key for group x25519
                        0x00, 0x20,                # Length of Public Key
                        0x25, 0x80, 0x72, 0xd6,
                        0x13, 0x58, 0x80, 0xd1,
                        0xde, 0xea, 0x32, 0x9a,
                        0xfa, 0x91, 0x21, 0x38,
                        0xe2, 0x51, 0xed, 0x21,
                        0xc2, 0x8e, 0x3b, 0x75,
                        0xed, 0x65, 0xd0, 0xd2,
                        0xad, 0x16, 0x62, 0x54
  );


  handshake_proto = raw_string(0x01,                             # Handshake Type (Client Hello)
                               0x00, mkword(strlen(fragment)),
                               mkword(seq_num),                  # Message Sequence
                               0x00, 0x00, 0x00,                 # Fragment Offset
                               0x00, mkword(strlen(fragment)));  # Fragment Length

  data = handshake_proto + fragment;
  data_len = strlen(data);

  dtls_header = raw_string(0x16,                          # Content-Type (Handshake)
                           0xfe, 0xfd,                    # Version
                           0x00, 0x00,                    # Epoch
                           0x00, 0x00, 0x00, 0x00, 0x00,  # Sequence Number
                           mkbyte(seq_num),
                           mkword(data_len));             # Length of data

  return dtls_header + data;
}


# @brief Creates a DTLS Client Hello packet
#
# @param version The version to use (currently supported DTLS10 (DTLS 1.0),
#                DTLS12 (DTLS 1.2) and DTLS13 (DTLS 1.3)) (default: DTLS10)
# @param random Client random to send to the server (32 bytes)
# @param seq_num Sequence number to use
# @param cookie (optional) Cookie sent by the server
#
# @return Created DTLS Client Hello packet if success otherwise NULL
#
function dtls_create_client_hello(version, random, seq_num, cookie) {

  local_var version, random, seq_num, cookie;
  local_var version_hex, cookie_len, fragment, extensions, ciphersuites;
  local_var handshake_proto, data_len, data, dtls_header;

  local_var dtls_10_ciphersuites, dtls_12_ciphersuites;

  dtls_10_ciphersuites = raw_string(sslv3_tls_raw_ciphers["TLS_NULL_WITH_NULL_NULL"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_NULL_MD5"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_NULL_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_IDEA_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_DES_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_DES_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_DES_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_DES_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_DES_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_DES_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_KRB5_WITH_DES_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_KRB5_WITH_IDEA_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_KRB5_WITH_DES_CBC_MD5"],
                                    sslv3_tls_raw_ciphers["TLS_KRB5_WITH_3DES_EDE_CBC_MD5"],
                                    sslv3_tls_raw_ciphers["TLS_KRB5_WITH_IDEA_CBC_MD5"],
                                    sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"],
                                    sslv3_tls_raw_ciphers["TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_NULL_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_NULL_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_NULL_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_SEED_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_SEED_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_SEED_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_SEED_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_SEED_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_SEED_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_NULL_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_NULL_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_NULL_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_NULL_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_NULL_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_NULL_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_NULL_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_NULL_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_NULL_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_NULL_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_NULL_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_anon_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_SRP_SHA_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_SRP_SHA_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_NULL_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"]);

  dtls_12_ciphersuites = raw_string(dtls_10_ciphersuites,
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_NULL_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_256_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CCM"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CCM"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CCM"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_256_CCM"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_128_CCM_8"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_WITH_AES_256_CCM_8"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_AES_128_CCM_8"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CCM"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CCM"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_128_CCM"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_AES_256_CCM"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_128_CCM_8"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_AES_256_CCM_8"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_DHE_WITH_AES_128_CCM_8"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_DHE_WITH_AES_256_CCM_8"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CCM"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CCM"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"],
                                    sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_128_CCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECCPWD_WITH_AES_256_CCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_SHA256_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_SHA384_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"],
                                    sslv3_tls_raw_ciphers["TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"]);

  if (isnull(version))
    version = "DTLS10";

  if (isnull(random)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#random#-#dtls_create_client_hello");
    return NULL;
  }

  if (isnull(seq_num)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#seq_num#-#dtls_create_client_hello");
    return NULL;
  }

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  if (version == "DTLS10")
    version_hex = raw_string(0xfe, 0xff);                     # DTLS 1.0
  else if (version == "DTLS12")
    version_hex = raw_string(0xfe, 0xfd);                     # DTLS 1.2
  else if (version == "DTLS13")
    version_hex = raw_string(0xfe, 0xfd);                     # DTLS 1.3 needs to use the DTLS 1.2 string
  else {
    set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#dtls_create_client_hello(): Unsupported DTLS Version");
    return NULL;
  }

  if (isnull(cookie) || cookie == "")
    cookie_len = 0;
  else
    cookie_len = strlen(cookie);

  fragment = raw_string(version_hex,               # Version
                        random,                    # Client Random
                        0x00,                      # Session ID length
                        mkbyte(cookie_len));       # Cookie length

  if (!isnull(cookie) || cookie != "")
    fragment = raw_string(fragment, cookie);

  extensions = raw_string(0x00, 0x0b,                # Type: ec_point_formats
                          0x00, 0x04,                # Length
                          0x03,                      # EC point formats length
                          0x00,                      # EC point format: uncompressed
                          ec_point_formats["ansiX962_compressed_prime"],
                          ec_point_formats["ansiX962_compressed_char2"],
                          0x00, 0x0a,                # Type: supported groups
                          0x00, 0x0c,                # Length
                          0x00, 0x0a,                # Supported Groups List Length
                          elliptic_curves["x25519"],
                          elliptic_curves["secp256r1"],
                          elliptic_curves["x448"],
                          elliptic_curves["secp384r1"],
                          elliptic_curves["secp521r1"],
                          0x00, 0x23,                # Type: session ticket
                          0x00, 0x00,                # Length
                          0x00, 0x16,                # Type: encrypt_then_mac
                          0x00, 0x00,                # Length
                          0x00, 0x17,                # extended_master_secret
                          0x00, 0x00);               # Length


  if (version == "DTLS10") {
    ciphersuites = raw_string(mkword(strlen(dtls_10_ciphersuites)), dtls_10_ciphersuites);
    extensions = raw_string(0x00, 0x24,                # Extension length
                            extensions);
  } else if (version == "DTLS12") {
    ciphersuites = raw_string(mkword(strlen(dtls_12_ciphersuites)), dtls_12_ciphersuites);

    extensions = raw_string(0x00, 0x4A,                # Extension length
                            extensions,
                            0x00, 0x0d,                # Type: signature algorithms
                            0x00, 0x22,                # Length
                            0x00, 0x20,                # Length of algorithms
                            signature_schemes["rsa_pkcs1_sha512"],
                            signature_schemes["dsa_sha512"],
                            signature_schemes["ecdsa_secp521r1_sha512"],
                            signature_schemes["rsa_pkcs1_sha384"],
                            signature_schemes["dsa_sha384"],
                            signature_schemes["ecdsa_secp384r1_sha384"],
                            signature_schemes["rsa_pkcs1_sha256"],
                            signature_schemes["dsa_sha256"],
                            signature_schemes["ecdsa_secp256r1_sha256"],
                            signature_schemes["rsa_pkcs1_sha224"],
                            signature_schemes["dsa_sha224"],
                            signature_schemes["ecdsa_sha224"],
                            signature_schemes["rsa_pkcs1_sha1"],
                            signature_schemes["dsa_sha1"],
                            signature_schemes["ecdsa_sha1"],
                            signature_schemes["rsa_pkcs1_md5"]);
  }

  fragment = raw_string(fragment,
                        ciphersuites,
                        0x01,                      # Compression Method length
                        0x00,                      # Compression Method
                        extensions);

  handshake_proto = raw_string(0x01,                             # Handshake Type (Client Hello)
                               0x00, mkword(strlen(fragment)),
                               mkword(seq_num),                  # Message Sequence
                               0x00, 0x00, 0x00,                 # Fragment Offset
                               0x00, mkword(strlen(fragment)));  # Fragment Length

  data = handshake_proto + fragment;
  data_len = strlen(data);

  dtls_header = raw_string(0x16,                          # Content-Type (Handshake)
                           version_hex,                   # Version
                           0x00, 0x00,                    # Epoch
                           0x00, 0x00, 0x00, 0x00, 0x00,  # Sequence Number
                           mkbyte(seq_num),
                           mkword(data_len));             # Length of data

  return dtls_header + data;
}

# @brief Does the DTLS Client Hello handshake part. The client sends a "Client Hello"
#        packet with a client random to the server. The server will send a
#        "Hello Verify Request" back with a cookie. The client sends the same
#        client hello request with the received cookie again. The server will
#        respond with a "Hello Server".
#
# @param socket UDP socket to use
#
# @return Returns the next sequence number to use, or -1 in case of an alert was received
#         or NULL in case of an error.
#
function dtls_client_hello(socket, version) {

  local_var socket, version;
  local_var seq_num, rand, cookie_len, hello1, hello2;
  local_var cookie, recv;

  if (isnull(socket)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#dtls_client_hello");
    return NULL;
  }

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  seq_num = 0;
  rand = dec2hex(num:unixtime()) + rand_str(length:28);
  cookie_len = 0;

  if (version == "DTLS13") {
    hello1 = dtls_create_13_client_hello(random: rand, seq_num: seq_num);
  } else {
    hello1 = dtls_create_client_hello(version: version, random: rand, seq_num: seq_num);
  }
  if (isnull(hello1))
    return NULL;

  send(socket: socket, data: hello1);
  recv = recv(socket: socket, length: 1024, min: 14);

  if (!recv || strlen(recv) < 13)
    return NULL;
  # Check for "Alert"
  if (ord(recv[13]) == 21)
    return make_list("", -1);
  if (version == "DTLS13") {
    # Check for "Server Hello" (0x02)
    if (strlen(recv) < 64|| ord(recv[13]) != 2)
      return NULL;
  } else {
    # Check for "Hello Verify Request" (0x03)
    if (strlen(recv) < 27 || ord(recv[13]) != 3)
      return NULL;
  }

  if (version != "DTLS13") {
    cookie_len = ord(recv[27]);

    if (strlen(recv) < 27 + cookie_len)
      return NULL;

    cookie = substr(recv, 28, 28 + cookie_len - 1);

    seq_num += 1;

    hello2 = dtls_create_client_hello(version: version, random: rand, seq_num: seq_num, cookie: cookie);
    if (isnull(hello2))
      return NULL;

    send(socket: socket, data: hello2);
    recv = recv(socket: socket, length: 1024);

    if (!recv || strlen(recv) < 13)
      return NULL;
    # Check for "Alert"
    if (ord(recv[13]) == 21)
      return make_list("", -1);
    # Check for "Server Hello" (0x02)
    if (!recv || strlen(recv) < 13 || ord(recv[13]) != 2)
      return NULL;
  }

  return make_list(recv, seq_num + 1);
}

# @brief Sends an "Close Notify" Alert message to the server (indicates a closing
#        of the "connection". Some servers might just ignore this.
#
# @param version The version to use (currently supported DTLS10 (DTLS 1.0),
#                DTLS12 (DTLS 1.2) and DTLS13 (DTLS 1.3)) (default: DTLS10)
# @param socket UDP socket to use
# @param seq_num Sequence number to use
#
function dtls_send_alert(socket, seq_num, version) {

  local_var socket, sec_num, version;
  local_var msg;

  if (isnull(socket)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#dtls_send_alert");
    return NULL;
  }

  if (isnull(seq_num)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#seq_num#-#dtls_send_alert");
    return NULL;
  }

  if (version == "DTLS12" || version == "DTLS13") {
    version = raw_string(0xfe, 0xfd);                  # DTLS 1.2
  } else {
    version = raw_string(0xfe, 0xff);                  # DTLS 1.0
  }

  msg = raw_string(0x15,
                   version,
                   0x00, 0x00,                       # Epoch
                   0x00, 0x00, 0x00, 0x00, 0x00,     # Sequence number
                   mkbyte(seq_num),
                   0x00, 0x07,                       # Length
                   0x02,                             # Level (Fatal)
                   0x00,                             # Description (Close Notify)
                   crap(length: 5));

  send(socket: socket, data: msg);
  recv(socket: socket, length: 14);

  return;
}

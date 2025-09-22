# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833152");
  script_cve_id("CVE-2024-23170");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:34 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 01:01:16 +0000 (Fri, 09 Feb 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0037-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0037-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TFW4YTDRTJEE3RUQXN4MRJ2SIL4ISBZT/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219336");
  script_xref(name:"URL", value:"https://mbed-tls.readthedocs.io/en/latest/kb/how-to/rewrite-branch-for-coding-style/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mbedtls' package(s) announced via the openSUSE-SU-2024:0037-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mbedtls fixes the following issues:

- Update to version 2.28.7:

 - Resolves CVE-2024-23170 boo#1219336

- Update to 2.28.6:

 Changes:

 * Mbed TLS is now released under a dual Apache-2.0 OR GPL-2.0-or-later
 license. Users may choose which license they take the code under.

- Update to 2.28.5:

 Features:

 * The documentation of mbedtls_ecp_group now describes the optimized
 representation of A for some curves. Fixes gh#Mbed-TLS/mbedtls#8045.

 Security:

 * Developers using mbedtls_pkcs5_pbes2() or mbedtls_pkcs12_pbe() should
 review the size of the output buffer passed to this function, and note that
 the output after decryption may include CBC padding. Consider moving to the
 new functions mbedtls_pkcs5_pbes2_ext() or mbedtls_pkcs12_pbe_ext() which
 checks for overflow of the output buffer and reports the actual length of
 the output.
 * Improve padding calculations in CBC decryption, NIST key unwrapping and
 RSA OAEP decryption. With the previous implementation, some compilers
 (notably recent versions of Clang and IAR) could produce non-constant time
 code, which could allow a padding oracle attack if the attacker has access
 to precise timing measurements.
 * Fix a buffer overread when parsing short TLS application data records in
 ARC4 or null-cipher cipher suites. Credit to OSS-Fuzz.

 Bugfix:

 * Fix x509 certificate generation to conform to RFC 5480 / RFC 5758 when
 using ECC key. The certificate was rejected by some crypto frameworks.
 Fixes gh#Mbed-TLS/mbedtls#2924.
 * Fix some cases where mbedtls_mpi_mod_exp, RSA key construction or ECDSA
 signature can silently return an incorrect result in low memory conditions.
 * Fix IAR compiler warnings. Fixes gh#Mbed-TLS/mbedtls#7873,
 gh#Mbed-TLS/mbedtls#4300.
 * Fix an issue when parsing an otherName subject alternative name into a
 mbedtls_x509_san_other_name struct. The type-id of the otherName was not
 copied to the struct. This meant that the struct had incomplete information
 about the otherName SAN and contained uninitialized memory.
 * Fix the detection of HardwareModuleName otherName SANs. These were being
 detected by comparing the wrong field and the check was erroneously
 inverted.
 * Fix an error when MBEDTLS_ECDSA_SIGN_ALT is defined but not
 MBEDTLS_ECDSA_VERIFY_ALT, causing ecdsa verify to fail. Fixes
 gh#Mbed-TLS/mbedtls#7498. Functions in the ssl_cache module now return a
 negative MBEDTLS_ERR_xxx error code on failure. Before, they returned 1 to
 indicate failure in some cases involving a missing entry or a full cache.

 Changes:

 * In configurations with ARIA or Camellia but not AES, the value of
 MBEDTLS_CIPHER_BLKSIZE_MAX was 8, rather than 16 as the name might suggest.
 This did not affect any library code, because this macro was only used in
 relation with CMAC which does not support these ciphers. Its value is now
 16 if ARIA or Camellia are present. This may affect ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mbedtls' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libmbedcrypto7", rpm:"libmbedcrypto7~2.28.7~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedcrypto7-32bit", rpm:"libmbedcrypto7-32bit~2.28.7~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedcrypto7-64bit", rpm:"libmbedcrypto7-64bit~2.28.7~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls14", rpm:"libmbedtls14~2.28.7~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls14-32bit", rpm:"libmbedtls14-32bit~2.28.7~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls14-64bit", rpm:"libmbedtls14-64bit~2.28.7~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedx509-1", rpm:"libmbedx509-1~2.28.7~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedx509-1-32bit", rpm:"libmbedx509-1-32bit~2.28.7~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedx509-1-64bit", rpm:"libmbedx509-1-64bit~2.28.7~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mbedtls-devel", rpm:"mbedtls-devel~2.28.7~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

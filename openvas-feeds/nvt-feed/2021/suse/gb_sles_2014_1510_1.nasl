# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.1510.1");
  script_cve_id("CVE-2014-1568", "CVE-2014-1574", "CVE-2014-1575", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1581", "CVE-2014-1583", "CVE-2014-1585", "CVE-2014-1586");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:1510-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:1510-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20141510-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox and mozilla-nss' package(s) announced via the SUSE-SU-2014:1510-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- update to Firefox 31.2.0 ESR (bnc#900941)
 * MFSA 2014-74/CVE-2014-1574/CVE-2014-1575 (bmo#1001994, bmo#1011354,
 bmo#1018916, bmo#1020034, bmo#1023035, bmo#1032208, bmo#1033020,
 bmo#1034230, bmo#1061214, bmo#1061600, bmo#1064346, bmo#1072044,
 bmo#1072174) Miscellaneous memory safety hazards (rv:33.0/rv:31.2)
 * MFSA 2014-75/CVE-2014-1576 (bmo#1041512) Buffer overflow during CSS
 manipulation
 * MFSA 2014-76/CVE-2014-1577 (bmo#1012609) Web Audio memory corruption
 issues with custom waveforms
 * MFSA 2014-77/CVE-2014-1578 (bmo#1063327) Out-of-bounds write with WebM
 video
 * MFSA 2014-79/CVE-2014-1581 (bmo#1068218) Use-after-free interacting
 with text directionality
 * MFSA 2014-81/CVE-2014-1585/CVE-2014-1586 (bmo#1062876, bmo#1062981)
 Inconsistent video sharing within iframe
 * MFSA 2014-82/CVE-2014-1583 (bmo#1015540) Accessing cross-origin
 objects via the Alarms API
- SSLv3 is disabled by default. See README.POODLE for more detailed
 information.

- disable call home features

- update to 3.17.2 (bnc#900941) Bugfix release
 * bmo#1049435 - Importing an RSA private key fails if p
 * bmo#1057161 - NSS hangs with 100% CPU on invalid EC key
 * bmo#1078669 - certutil crashes when using the --certVersion parameter
- changes from earlier version of the 3.17 branch: update to 3.17.1
 (bnc#897890)
 * MFSA 2014-73/CVE-2014-1568 (bmo#1064636, bmo#1069405) RSA Signature
 Forgery in NSS
 * Change library's signature algorithm default to SHA256
 * Add support for draft-ietf-tls-downgrade-scsv
 * Add clang-cl support to the NSS build system
 * Implement TLS 1.3:
 * Part 1. Negotiate TLS 1.3
 * Part 2. Remove deprecated cipher suites andcompression.
 * Add support for little-endian powerpc64 update to 3.17
 * required for Firefox 33 New functionality:
 * When using ECDHE, the TLS server code may be configured to generate a
 fresh ephemeral ECDH key for each handshake, by setting the
 SSL_REUSE_SERVER_ECDHE_KEY socket option to PR_FALSE. The
 SSL_REUSE_SERVER_ECDHE_KEY option defaults to PR_TRUE, which means the
 server's ephemeral ECDH key is reused for multiple handshakes. This
 option does not affect the TLS client code, which always generates a
 fresh ephemeral ECDH key for each handshake. New Macros
 * SSL_REUSE_SERVER_ECDHE_KEY Notable Changes:
 * The manual pages for the certutil and pp tools have been updated to
 document the new parameters that had been added in NSS 3.16.2.");

  script_tag(name:"affected", value:"'MozillaFirefox and mozilla-nss' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~31.2.0esr~6.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~31~4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~31.2.0esr~6.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~31.2.0esr~6.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~31.2.0esr~6.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.17.2~8.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.17.2~8.2", rls:"SLES12.0"))) {
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

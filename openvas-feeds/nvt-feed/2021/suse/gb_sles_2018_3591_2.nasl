# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3591.2");
  script_cve_id("CVE-2017-16541", "CVE-2018-12376", "CVE-2018-12377", "CVE-2018-12378", "CVE-2018-12379", "CVE-2018-12381", "CVE-2018-12383", "CVE-2018-12385", "CVE-2018-12386", "CVE-2018-12387");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 15:51:22 +0000 (Thu, 06 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3591-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3591-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183591-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/703591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/839074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/893359");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-December/004918.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, MozillaFirefox-branding-SLE, apache2-mod_nss, llvm4, mozilla-nspr, mozilla-nss' package(s) announced via the SUSE-SU-2018:3591-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox to ESR 60.2.2 fixes several issues.

These general changes are part of the version 60 release.

- New browser engine with speed improvements
- Redesigned graphical user interface elements
- Unified address and search bar for new installations
- New tab page listing top visited, recently visited and recommended pages
- Support for configuration policies in enterprise deployments via JSON files
- Support for Web Authentication, allowing the use of USB tokens for
 authentication to web sites

The following changes affect compatibility:

- Now exclusively supports extensions built using the WebExtension API.
- Unsupported legacy extensions will no longer work in Firefox 60 ESR
- TLS certificates issued by Symantec before June 1st, 2016 are no longer trusted
 The 'security.pki.distrust_ca_policy' preference can be set to 0 to reinstate
 trust in those certificates

The following issues affect performance:

- new format for storing private keys, certificates and certificate trust
 If the user home or data directory is on a network file system, it is
 recommended that users set the following environment variable to avoid
 slowdowns: NSS_SDB_USE_CACHE=yes
 This setting is not recommended for local, fast file systems.

These security issues were fixed:

- CVE-2018-12381: Dragging and dropping Outlook email message results in page navigation (bsc#1107343).
- CVE-2017-16541: Proxy bypass using automount and autofs (bsc#1107343).
- CVE-2018-12376: Various memory safety bugs (bsc#1107343).
- CVE-2018-12377: Use-after-free in refresh driver timers (bsc#1107343).
- CVE-2018-12378: Use-after-free in IndexedDB (bsc#1107343).
- CVE-2018-12379: Out-of-bounds write with malicious MAR file (bsc#1107343).
- CVE-2018-12386: Type confusion in JavaScript allowed remote code execution (bsc#1110506)
- CVE-2018-12387: Array.prototype.push stack pointer vulnerability may enable exploits in the sandboxed content process (bsc#1110507)
- CVE-2018-12385: Crash in TransportSecurityInfo due to cached data (bsc#1109363)
- CVE-2018-12383: Setting a master password did not delete unencrypted previously stored passwords (bsc#1107343)

This update for mozilla-nspr to version 4.19 fixes the follwing issues

- Added TCP Fast Open functionality
- A socket without PR_NSPR_IO_LAYER will no longer trigger
 an assertion when polling

This update for mozilla-nss to version 3.36.4 fixes the follwing issues

- Connecting to a server that was recently upgraded to TLS 1.3
 would result in a SSL_RX_MALFORMED_SERVER_HELLO error.
- Fix a rare bug with PKCS#12 files.
- Replaces existing vectorized ChaCha20 code with verified
 HACL* implementation.
- TLS 1.3 support has been updated to draft -23.
- Added formally verified implementations of non-vectorized Chacha20
 and non-vectorized Poly1305 64-bit.
- The following CA certificates were Removed:
 OU = Security Communication EV RootCA1
 CN = CA ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox, MozillaFirefox-branding-SLE, apache2-mod_nss, llvm4, mozilla-nspr, mozilla-nss' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~60.2.2esr~109.46.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~60~32.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~60.2.2esr~109.46.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_nss", rpm:"apache2-mod_nss~1.0.14~19.6.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.19~19.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.19~19.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.36.4~58.15.3", rls:"SLES12.0SP4"))) {
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

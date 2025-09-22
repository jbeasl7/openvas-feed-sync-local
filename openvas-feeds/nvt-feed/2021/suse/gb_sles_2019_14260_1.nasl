# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14260.1");
  script_cve_id("CVE-2019-11745", "CVE-2019-13722", "CVE-2019-17005", "CVE-2019-17008", "CVE-2019-17009", "CVE-2019-17010", "CVE-2019-17011", "CVE-2019-17012");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:11 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-13 18:37:37 +0000 (Mon, 13 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14260-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914260-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158527");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-December/006283.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, mozilla-nspr, mozilla-nss' package(s) announced via the SUSE-SU-2019:14260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox, mozilla-nspr, mozilla-nss fixes the following issues:

Update Firefox Extended Support Release to 68.3.0 ESR (MFSA 2019-37 / bsc#1158328)

Security issues fixed:

- CVE-2019-17008: Use-after-free in worker destruction (bmo#1546331).
- CVE-2019-13722: Stack corruption due to incorrect number of arguments in WebRTC code (bmo#1580156).
- CVE-2019-11745: Out of bounds write in NSS when encrypting with a block cipher (bmo#1586176).
- CVE-2019-17009: Updater temporary files accessible to unprivileged processes (bmo#1510494).
- CVE-2019-17010: Use-after-free when performing device orientation checks (bmo#1581084).
- CVE-2019-17005: Buffer overflow in plain text serializer (bmo#1584170).
- CVE-2019-17011: Use-after-free when retrieving a document in antitracking (bmo#1591334).
- CVE-2019-17012: Memory safety bugs fixed in Firefox 71 and Firefox ESR 68.3 (bmo#1449736, bmo#1533957, bmo#1560667, bmo#1567209, bmo#1580288, bmo#1585760, bmo#1592502).

Update mozilla-nss to version 3.47.1 (bsc#1158527):

Security issues fixed:

- CVE-2019-11745: EncryptUpdate should use maxout, not block size.

Bug fixes:

- Fix a crash that could be caused by client certificates during startup (bmo#1590495, bsc#1158527)
- Fix compile-time warnings from uninitialized variables in a perl script (bmo#1589810)
- Support AES HW acceleration on ARMv8 (bmo#1152625)
- Allow per-socket run-time ordering of the cipher suites presented in ClientHello (bmo#1267894)
- Add CMAC to FreeBL and PKCS #11 libraries (bmo#1570501)
- Remove arbitrary HKDF output limit by allocating space as needed (bmo#1577953)

Update mozilla-nspr to version 4.23:

Bug fixes:

- fixed a build failure that was introduced in 4.22
- correctness fix for Win64 socket polling
- whitespace in C files was cleaned up and no longer uses tab characters for indenting
- added support for the ARC architecture
- removed support for the following platforms: OSF1/Tru64, DGUX, IRIX, Symbian, BeOS
- correctness and build fixes");

  script_tag(name:"affected", value:"'MozillaFirefox, mozilla-nspr, mozilla-nss' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.3.0~78.54.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.3.0~78.54.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~68.3.0~78.54.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.47.1~38.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.47.1~38.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.47.1~38.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.47.1~38.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.23~29.9.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.23~29.9.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.23~29.9.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.47.1~38.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.47.1~38.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.47.1~38.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.47.1~38.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.47.1~38.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.47.1~38.12.1", rls:"SLES11.0SP4"))) {
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

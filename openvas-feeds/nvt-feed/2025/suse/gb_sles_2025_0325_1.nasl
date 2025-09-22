# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0325.1");
  script_cve_id("CVE-2018-14679", "CVE-2023-20197", "CVE-2024-20380", "CVE-2024-20505", "CVE-2024-20506", "CVE-2025-20128");
  script_tag(name:"creation_date", value:"2025-02-04 04:25:57 +0000 (Tue, 04 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-06 14:11:27 +0000 (Wed, 06 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0325-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0325-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250325-1.html");
  script_xref(name:"URL", value:"https://blog.clamav.net/2021/09/clamav-01040-released.html");
  script_xref(name:"URL", value:"https://blog.clamav.net/2022/05/clamav-01050-01043-01036-released.html");
  script_xref(name:"URL", value:"https://blog.clamav.net/2022/11/clamav-100-lts-released.html");
  script_xref(name:"URL", value:"https://blog.clamav.net/2023/05/clamav-110-released.html");
  script_xref(name:"URL", value:"https://blog.clamav.net/2024/08/clamav-140-feature-release-and-clamav.html");
  script_xref(name:"URL", value:"https://blog.clamav.net/2024/09/clamav-141-132-107-and-010312-security.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236307");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020258.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2025:0325-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

New version 1.4.2:

 * CVE-2025-20128, bsc#1236307: Fixed a possible buffer overflow
 read bug in the OLE2 file parser that could cause a
 denial-of-service (DoS) condition.

- Start clamonacc with --fdpass to avoid errors due to
 clamd not being able to access user files. (bsc#1232242)

- New version 1.4.1:

 * [link moved to references]

- New version 1.4.0:

 * Added support for extracting ALZ archives.
 * Added support for extracting LHA/LZH archives.
 * Added the ability to disable image fuzzy hashing, if needed.
 For context, image fuzzy hashing is a detection mechanism
 useful for identifying malware by matching images included with
 the malware or phishing email/document.
 * [link moved to references]

- New version 1.3.2:

 * CVE-2024-20506: Changed the logging module to disable following
 symlinks on Linux and Unix systems so as to prevent an attacker
 with existing access to the 'clamd' or 'freshclam' services from
 using a symlink to corrupt system files.
 * CVE-2024-20505: Fixed a possible out-of-bounds read bug in the PDF
 file parser that could cause a denial-of-service condition.
 * Removed unused Python modules from freshclam tests including
 deprecated 'cgi' module that is expected to cause test failures in
 Python 3.13.
 * Fix unit test caused by expiring signing certificate.
 * Fixed a build issue on Windows with newer versions of Rust. Also
 upgraded GitHub Actions imports to fix CI failures.
 * Fixed an unaligned pointer dereference issue on select architectures.
 * Fixes to Jenkins CI pipeline.


- New Version: 1.3.1:

 * CVE-2024-20380: Fixed a possible crash in the HTML file parser
 that could cause a denial-of-service (DoS) condition.
 * Updated select Rust dependencies to the latest versions.
 * Fixed a bug causing some text to be truncated when converting
 from UTF-16.
 * Fixed assorted complaints identified by Coverity static
 analysis.
 * Fixed a bug causing CVDs downloaded by the DatabaseCustomURL
 * Added the new 'valhalla' database name to the list of optional
 databases in preparation for future work.

- New version: 1.3.0:

 * Added support for extracting and scanning attachments found in
 Microsoft OneNote section files. OneNote parsing will be
 enabled by default, but may be optionally disabled.
 * Added file type recognition for compiled Python ('.pyc') files.
 * Improved support for decrypting PDFs with empty passwords.
 * Fixed a warning when scanning some HTML files.
 * ClamOnAcc: Fixed an infinite loop when a watched directory
 does not exist.
 * ClamOnAcc: Fixed an infinite loop when a file has been deleted
 before a scan.

- New version: 1.2.0:

 * Added support for extracting Universal Disk Format (UDF)
 partitions.
 * Added an option to customize the size of ClamAV's clean file
 cache.
 * Raised the MaxScanSize limit so the total amount of data
 scanned when scanning a file ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~1.4.2~150200.8.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~1.4.2~150200.8.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-docs-html", rpm:"clamav-docs-html~1.4.2~150200.8.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~1.4.2~150200.8.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav12", rpm:"libclamav12~1.4.2~150200.8.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclammspack0", rpm:"libclammspack0~1.4.2~150200.8.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam3", rpm:"libfreshclam3~1.4.2~150200.8.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~1.4.2~150200.8.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~1.4.2~150200.8.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-docs-html", rpm:"clamav-docs-html~1.4.2~150200.8.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~1.4.2~150200.8.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav12", rpm:"libclamav12~1.4.2~150200.8.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclammspack0", rpm:"libclammspack0~1.4.2~150200.8.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam3", rpm:"libfreshclam3~1.4.2~150200.8.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~1.4.2~150200.8.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~1.4.2~150200.8.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-docs-html", rpm:"clamav-docs-html~1.4.2~150200.8.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~1.4.2~150200.8.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav12", rpm:"libclamav12~1.4.2~150200.8.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclammspack0", rpm:"libclammspack0~1.4.2~150200.8.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam3", rpm:"libfreshclam3~1.4.2~150200.8.3.1", rls:"SLES15.0SP5"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02050.1");
  script_cve_id("CVE-2024-12718", "CVE-2025-4138", "CVE-2025-4330", "CVE-2025-4516", "CVE-2025-4517");
  script_tag(name:"creation_date", value:"2025-06-23 04:17:35 +0000 (Mon, 23 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02050-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02050-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502050-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244060");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040419.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python39' package(s) announced via the SUSE-SU-2025:02050-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python39 fixes the following issues:

python39 was updated from version 3.9.21 to version 3.9.23:

- Security issues fixed:

 * CVE-2025-4516: Fixed blocking DecodeError handling vulnerability, which could lead to DoS (bsc#1243273)
 * CVE-2024-12718, CVE-2025-4138, CVE-2025-4330, CVE-2025-4517: Fixed multiple issues that allowed tarfile
 extraction filters to be bypassed using crafted symlinks and hard links
 (bsc#1244056, bsc#1244059, bsc#1244060, bsc#1244032)

- Other changes and bugs fixed:

 * Fixed issue with reproducible builds (bsc#1239210)
 * Fixed a potential denial of service vulnerability in the imaplib module.
 * Fixed bugs in the in the folding of rfc2047 encoded-words and in the folding of quoted strings when flattening an
 email message using a modern email policy.
 * Fixed parsing long IPv6 addresses with embedded IPv4 address.
 * Fixed ipaddress.IPv6Address.reverse_pointer output according to RFC 3596, SS2.5.
 * Improved the textual representation of IPv4-mapped IPv6 addresses in ipaddress.
 * ipaddress: fixed hash collisions for IPv4Network and IPv6Network objects
 * os.path.realpath() now accepts a strict keyword-only argument.
 * Stop the processing of long IPv6 addresses early in ipaddress to prevent excessive memory consumption and a minor
 denial-of-service.
 * Updated bundled libexpat to 2.7.1
 * Writers of CPython's documentation can now use next as the version for the versionchanged, versionadded,
 deprecated directives.");

  script_tag(name:"affected", value:"'python39' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0", rpm:"libpython3_9-1_0~3.9.23~150300.4.75.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.23~150300.4.75.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base", rpm:"python39-base~3.9.23~150300.4.75.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses", rpm:"python39-curses~3.9.23~150300.4.75.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm", rpm:"python39-dbm~3.9.23~150300.4.75.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-devel", rpm:"python39-devel~3.9.23~150300.4.75.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-idle", rpm:"python39-idle~3.9.23~150300.4.75.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk", rpm:"python39-tk~3.9.23~150300.4.75.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tools", rpm:"python39-tools~3.9.23~150300.4.75.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0", rpm:"libpython3_9-1_0~3.9.23~150300.4.75.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.23~150300.4.75.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base", rpm:"python39-base~3.9.23~150300.4.75.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses", rpm:"python39-curses~3.9.23~150300.4.75.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm", rpm:"python39-dbm~3.9.23~150300.4.75.1", rls:"SLES15.0SP5"))) {
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

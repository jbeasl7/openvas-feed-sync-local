# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20231.1");
  script_cve_id("CVE-2025-58060", "CVE-2025-58364", "CVE-2025-58436", "CVE-2025-61915");
  script_tag(name:"creation_date", value:"2026-02-13 04:41:11 +0000 (Fri, 13 Feb 2026)");
  script_version("2026-02-13T05:57:48+0000");
  script_tag(name:"last_modification", value:"2026-02-13 05:57:48 +0000 (Fri, 13 Feb 2026)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-04 17:15:19 +0000 (Thu, 04 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20231-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20231-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620231-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254353");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024096.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the SUSE-SU-2026:20231-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cups fixes the following issues:

Update to version 2.4.16.

Security issues fixed:

- CVE-2025-61915: local denial-of-service via cupsd.conf update and related issues (bsc#1253783).
- CVE-2025-58436: slow client communication leads to a possible DoS attack (bsc#1244057).
- CVE-2025-58364: unsafe deserialization and validation of printer attributes can cause a null dereference (bsc#1249128).
- CVE-2025-58060: authentication bypass with AuthType Negotiate (bsc#1249049).

Other updates and bugfixes:

- Version upgrade to 2.4.16:

 * 'cupsUTF8ToCharset' didn't validate 2-byte UTF-8 sequences,
 potentially reading past the end of the source string
 (Issue #1438)
 * The web interface did not support domain usernames fully
 (Issue #1441)
 * Fixed an infinite loop issue in the GTK+ print dialog
 (Issue #1439 boo#1254353)
 * Fixed stopping scheduler on unknown directive in
 configuration (Issue #1443)
 * Fixed packages for Immutable Mode (jsc#PED-14775
 from epic jsc#PED-14688)

- Version upgrade to 2.4.15:

 * Fixed potential crash in 'cups-driverd' when there are
 duplicate PPDs (Issue #1355)
 * Fixed error recovery when scanning for PPDs
 in 'cups-driverd' (Issue #1416)

- Version upgrade to 2.4.14.

- Version upgrade to 2.4.13:

 * Added 'print-as-raster' printer and job attributes
 for forcing rasterization (Issue #1282)
 * Updated documentation (Issue #1086)
 * Updated IPP backend to try a sanitized user name if the
 printer/server does not like the value (Issue #1145)
 * Updated the scheduler to send the 'printer-added'
 or 'printer-modified' events whenever an IPP Everywhere PPD
 is installed (Issue #1244)
 * Updated the scheduler to send the 'printer-modified' event
 whenever the system default printer is changed (Issue #1246)
 * Fixed a memory leak in 'httpClose' (Issue #1223)
 * Fixed missing commas in 'ippCreateRequestedArray'
 (Issue #1234)
 * Fixed subscription issues in the scheduler and D-Bus notifier
 (Issue #1235)
 * Fixed media-default reporting for custom sizes (Issue #1238)
 * Fixed support for IPP/PPD options with periods or underscores
 (Issue #1249)
 * Fixed parsing of real numbers in PPD compiler source files
 (Issue #1263)
 * Fixed scheduler freezing with zombie clients (Issue #1264)
 * Fixed support for the server name in the ErrorLog filename
 (Issue #1277)
 * Fixed job cleanup after daemon restart (Issue #1315)
 * Fixed handling of buggy DYMO USB printer serial numbers
 (Issue #1338)
 * Fixed unreachable block in IPP backend (Issue #1351)
 * Fixed memory leak in _cupsConvertOptions (Issue #1354)

- Version upgrade to 2.4.12:

 * GnuTLS follows system crypto policies now (Issue #1105)
 * Added `NoSystem` SSLOptions value (Issue #1130)
 * Now we raise alert for certificate issues (Issue #1194)
 * Added Kyocera USB quirk (Issue #1198)
 * The scheduler now logs a job's debugging history
 if the backend fails (Issue #1205)
 * Fixed a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cups' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.4.16~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~2.4.16~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-config", rpm:"cups-config~2.4.16~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk", rpm:"cups-ddk~2.4.16~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~2.4.16~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.4.16~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2", rpm:"libcupsimage2~2.4.16~160000.1.1", rls:"SLES16.0.0"))) {
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

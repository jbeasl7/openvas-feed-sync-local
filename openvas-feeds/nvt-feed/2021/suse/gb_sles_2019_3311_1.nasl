# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3311.1");
  script_cve_id("CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1350", "CVE-2019-1351", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1354", "CVE-2019-1387", "CVE-2019-19604");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 19:20:30 +0000 (Wed, 05 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3311-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3311-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193311-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158795");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-December/006258.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the SUSE-SU-2019:3311-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for git fixes the following issues:

Security issues fixed:

- CVE-2019-1349: Fixed issue on Windows, when submodules are cloned recursively, under certain circumstances Git could be fooled into using the same Git directory twice (bsc#1158787).
- CVE-2019-19604: Fixed a recursive clone followed by a submodule update could execute code contained within the repository without the user explicitly having asked for that (bsc#1158795).
- CVE-2019-1387: Fixed recursive clones that are currently affected by a vulnerability that is caused by too-lax validation of submodule names, allowing very targeted attacks via remote code execution in recursive clones (bsc#1158793).
- CVE-2019-1354: Fixed issue on Windows that refuses to write tracked files with filenames that contain backslashes (bsc#1158792).
- CVE-2019-1353: Fixed issue when run in the Windows Subsystem for Linux while accessing a working directory on a regular Windows drive, none of the NTFS protections were active (bsc#1158791).
- CVE-2019-1352: Fixed issue on Windows was unaware of NTFS Alternate Data Streams (bsc#1158790).
- CVE-2019-1351: Fixed issue on Windows mistakes drive letters outside of the US-English alphabet as relative paths (bsc#1158789).
- CVE-2019-1350: Fixed incorrect quoting of command-line arguments allowed remote code execution during a recursive clone in conjunction with SSH URLs (bsc#1158788).
- CVE-2019-1348: Fixed the --export-marks option of fast-import is exposed also via the in-stream command feature export-marks=... and it allows overwriting arbitrary paths (bsc#1158785).
- Fixed an issue where git send-email fails to authenticate with SMTP server (bsc#1082023)");

  script_tag(name:"affected", value:"'git' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.12.3~27.22.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-doc", rpm:"git-doc~2.12.3~27.22.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.12.3~27.22.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-doc", rpm:"git-doc~2.12.3~27.22.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.12.3~27.22.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.12.3~27.22.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.12.3~27.22.1", rls:"SLES12.0SP5"))) {
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

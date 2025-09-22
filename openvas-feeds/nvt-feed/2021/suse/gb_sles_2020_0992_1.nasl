# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0992.1");
  script_cve_id("CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1350", "CVE-2019-1351", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1354", "CVE-2019-1387", "CVE-2020-5260");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 19:20:30 +0000 (Wed, 05 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0992-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0992-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200992-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168930");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-factory/2019-01/msg00490.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-April/006709.html");
  script_xref(name:"URL", value:"https://raw.github.com/git/git/master/Documentation/RelNotes/2.16.0.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the SUSE-SU-2020:0992-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for git fixes the following issues:

Security issue fixed:

- CVE-2020-5260: With a crafted URL that contains a newline in it, the credential
 helper machinery can be fooled to give credential information for a wrong host (bsc#1168930).

Non-security issue fixed:

git was updated to 2.26.0 for SHA256 support (bsc#1167890, jsc#SLE-11608):

- the xinetd snippet was removed
- the System V init script for the git-daemon was replaced by a systemd
 service file of the same name.

git 2.26.0:

* 'git rebase' now uses a different backend that is based on the
 'merge' machinery by default. The 'rebase.backend' configuration
 variable reverts to old behaviour when set to 'apply'
* Improved handling of sparse checkouts
* Improvements to many commands and internal features

git 2.25.1:

* 'git commit' now honors advise.statusHints
* various updates, bug fixes and documentation updates

git 2.25.0:

* The branch description ('git branch --edit-description') has been
 used to fill the body of the cover letters by the format-patch
 command, this has been enhanced so that the subject can also be
 filled.
* A few commands learned to take the pathspec from the standard input
 or a named file, instead of taking it as the command line
 arguments, with the '--pathspec-from-file' option.
* Test updates to prepare for SHA-2 transition continues.
* Redo 'git name-rev' to avoid recursive calls.
* When all files from some subdirectory were renamed to the root
 directory, the directory rename heuristics would fail to detect that
 as a rename/merge of the subdirectory to the root directory, which has
 been corrected.
* HTTP transport had possible allocator/deallocator mismatch, which
 has been corrected.

git 2.24.1:

* CVE-2019-1348: The --export-marks option of fast-import is
 exposed also via the in-stream command feature export-marks=...
 and it allows overwriting arbitrary paths (bsc#1158785)
* CVE-2019-1349: on Windows, when submodules are cloned
 recursively, under certain circumstances Git could be fooled
 into using the same Git directory twice (bsc#1158787)
* CVE-2019-1350: Incorrect quoting of command-line arguments
 allowed remote code execution during a recursive clone in
 conjunction with SSH URLs (bsc#1158788)
* CVE-2019-1351: on Windows mistakes drive letters outside of
 the US-English alphabet as relative paths (bsc#1158789)
* CVE-2019-1352: on Windows was unaware of NTFS Alternate Data
 Streams (bsc#1158790)
* CVE-2019-1353: when run in the Windows Subsystem for Linux
 while accessing a working directory on a regular Windows
 drive, none of the NTFS protections were active (bsc#1158791)
* CVE-2019-1354: on Windows refuses to write tracked files with
 filenames that contain backslashes (bsc#1158792)
* CVE-2019-1387: Recursive clones vulnerability that is caused
 by too-lax validation of submodule names, allowing very
 targeted attacks via remote code execution in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'git' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.26.0~27.27.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-doc", rpm:"git-doc~2.26.0~27.27.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0", rpm:"libpcre2-16-0~10.34~1.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0", rpm:"libpcre2-32-0~10.34~1.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.34~1.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2", rpm:"libpcre2-posix2~10.34~1.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CGI", rpm:"perl-CGI~4.38~1.3.1", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.26.0~27.27.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-doc", rpm:"git-doc~2.26.0~27.27.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0", rpm:"libpcre2-16-0~10.34~1.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0", rpm:"libpcre2-32-0~10.34~1.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.34~1.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2", rpm:"libpcre2-posix2~10.34~1.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CGI", rpm:"perl-CGI~4.38~1.3.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.26.0~27.27.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0", rpm:"libpcre2-16-0~10.34~1.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0", rpm:"libpcre2-32-0~10.34~1.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.34~1.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2", rpm:"libpcre2-posix2~10.34~1.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CGI", rpm:"perl-CGI~4.38~1.3.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.26.0~27.27.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0", rpm:"libpcre2-16-0~10.34~1.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0", rpm:"libpcre2-32-0~10.34~1.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.34~1.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2", rpm:"libpcre2-posix2~10.34~1.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CGI", rpm:"perl-CGI~4.38~1.3.1", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.26.0~27.27.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0", rpm:"libpcre2-16-0~10.34~1.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0", rpm:"libpcre2-32-0~10.34~1.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.34~1.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2", rpm:"libpcre2-posix2~10.34~1.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CGI", rpm:"perl-CGI~4.38~1.3.1", rls:"SLES12.0SP5"))) {
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

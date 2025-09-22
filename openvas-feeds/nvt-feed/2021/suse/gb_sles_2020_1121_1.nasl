# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1121.1");
  script_cve_id("CVE-2017-15298", "CVE-2018-11233", "CVE-2018-11235", "CVE-2018-17456", "CVE-2019-1348", "CVE-2019-1349", "CVE-2019-1350", "CVE-2019-1351", "CVE-2019-1352", "CVE-2019-1353", "CVE-2019-1354", "CVE-2019-1387", "CVE-2019-19604", "CVE-2020-11008", "CVE-2020-5260");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 19:20:30 +0000 (Wed, 05 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1121-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201121-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the SUSE-SU-2020:1121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for git fixes the following issues:

Security issues fixed:

CVE-2020-11008: Specially crafted URLs may have tricked the credentials
 helper to providing credential information that is not appropriate for
 the protocol in use and host being contacted (bsc#1169936)

git was updated to 2.26.1 (bsc#1169786, jsc#ECO-1628, bsc#1149792)

Fix git-daemon not starting after conversion from sysvinit to systemd
 service (bsc#1169605).

CVE-2020-5260: Specially crafted URLs with newline characters could have
 been used to make the Git client to send credential information for a
 wrong host to the attacker's site bsc#1168930

git 2.26.0 (bsc#1167890, jsc#SLE-11608):

'git rebase' now uses a different backend that is based on the 'merge'
 machinery by default. The 'rebase.backend' configuration variable
 reverts to old behaviour when set to 'apply'

Improved handling of sparse checkouts

Improvements to many commands and internal features

git 2.25.2:

bug fixes to various subcommands in specific operations

git 2.25.1:

'git commit' now honors advise.statusHints

various updates, bug fixes and documentation updates

git 2.25.0

The branch description ('git branch --edit-description') has been used
 to fill the body of the cover letters by the format-patch command, this
 has been enhanced so that the subject can also be filled.

A few commands learned to take the pathspec from the standard input
 or a named file, instead of taking it as the command line arguments,
 with the '--pathspec-from-file' option.

Test updates to prepare for SHA-2 transition continues.

Redo 'git name-rev' to avoid recursive calls.

When all files from some subdirectory were renamed to the root
 directory, the directory rename heuristics would fail to detect that as
 a rename/merge of the subdirectory to the root directory, which has been
 corrected.

HTTP transport had possible allocator/deallocator mismatch, which has
 been corrected.

git 2.24.1:

CVE-2019-1348: The --export-marks option of fast-import is exposed also
 via the in-stream command feature export-marks=... and it allows
 overwriting arbitrary paths (bsc#1158785)

CVE-2019-1349: on Windows, when submodules are cloned recursively, under
 certain circumstances Git could be fooled into using the same Git
 directory twice (bsc#1158787)

CVE-2019-1350: Incorrect quoting of command-line arguments allowed
 remote code execution during a recursive clone in conjunction with SSH
 URLs (bsc#1158788)

CVE-2019-1351: on Windows mistakes drive letters outside of the
 US-English alphabet as relative paths (bsc#1158789)

CVE-2019-1352: on Windows was unaware of NTFS Alternate Data Streams
 (bsc#1158790)

CVE-2019-1353: when run in the Windows Subsystem for Linux while
 accessing a working directory on a regular Windows drive, none of the
 NTFS protections were active (bsc#1158791)

CVE-2019-1354: on Windows refuses to write tracked files with ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'git' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-core-debuginfo", rpm:"git-core-debuginfo~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-debuginfo", rpm:"git-debuginfo~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-debugsource", rpm:"git-debugsource~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git", rpm:"git~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-arch", rpm:"git-arch~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-cvs", rpm:"git-cvs~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-daemon", rpm:"git-daemon~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-daemon-debuginfo", rpm:"git-daemon-debuginfo~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-doc", rpm:"git-doc~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-email", rpm:"git-email~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-gui", rpm:"git-gui~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-svn", rpm:"git-svn~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-svn-debuginfo", rpm:"git-svn-debuginfo~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-web", rpm:"git-web~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitk", rpm:"gitk~2.26.1~3.25.2", rls:"SLES15.0SP1"))) {
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

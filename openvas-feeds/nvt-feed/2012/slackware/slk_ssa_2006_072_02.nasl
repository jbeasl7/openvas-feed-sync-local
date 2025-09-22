# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56421");
  script_cve_id("CVE-2006-0049", "CVE-2006-0455");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Slackware: Security Advisory (SSA:2006-072-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-072-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.476477");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg' package(s) announced via the SSA:2006-072-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New GnuPG packages are available for Slackware 9.0, 9.1, 10.0, 10.1, 10.2,
and -current to fix security issues.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/gnupg-1.4.2.2-i486-1.tgz: Upgraded to gnupg-1.4.2.2.
 There have been two security related issues reported recently with GnuPG.
 From the GnuPG 1.4.2.1 and 1.4.2.2 NEWS files:
 Noteworthy changes in version 1.4.2.2 (2006-03-08)
 * Files containing several signed messages are not allowed any
 longer as there is no clean way to report the status of such
 files back to the caller. To partly revert to the old behaviour
 the new option --allow-multisig-verification may be used.
 Noteworthy changes in version 1.4.2.1 (2006-02-14)
 * Security fix for a verification weakness in gpgv. Some input
 could lead to gpgv exiting with 0 even if the detached signature
 file did not carry any signature. This is not as fatal as it
 might seem because the suggestion as always been not to rely on
 th exit code but to parse the --status-fd messages. However it
 is likely that gpgv is used in that simplified way and thus we
 do this release. Same problem with 'gpg --verify' but nobody
 should have used this for signature verification without
 checking the status codes anyway. Thanks to the taviso from
 Gentoo for reporting this problem.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'gnupg' package(s) on Slackware 9.0, Slackware 9.1, Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK10.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.2.2-i486-1", rls:"SLK10.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.2.2-i486-1", rls:"SLK10.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.2.2-i486-1", rls:"SLK10.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.2.2-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.2.2-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.2.2-i486-1", rls:"SLKcurrent"))) {
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

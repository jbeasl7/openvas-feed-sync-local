# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57492");
  script_cve_id("CVE-2006-4924", "CVE-2006-5051", "CVE-2006-5052");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:36:44 +0000 (Fri, 02 Feb 2024)");

  script_name("Slackware: Security Advisory (SSA:2006-272-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|8\.1|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-272-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.592566");
  script_xref(name:"URL", value:"http://www.openssh.com/txt/release-4.4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SSA:2006-272-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New openssh packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, and -current to fix security issues.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/openssh-4.4p1-i486-1_slack10.2.tgz:
 Upgraded to openssh-4.4p1.
 This fixes a few security related issues. From the release notes found at
 [link moved to references]:
 * Fix a pre-authentication denial of service found by Tavis Ormandy,
 that would cause sshd(8) to spin until the login grace time
 expired.
 * Fix an unsafe signal handler reported by Mark Dowd. The signal
 handler was vulnerable to a race condition that could be exploited
 to perform a pre-authentication denial of service. On portable
 OpenSSH, this vulnerability could theoretically lead to
 pre-authentication remote code execution if GSSAPI authentication
 is enabled, but the likelihood of successful exploitation appears
 remote.
 * On portable OpenSSH, fix a GSSAPI authentication abort that could
 be used to determine the validity of usernames on some platforms.
 Links to the CVE entries will be found here:
 [links moved to references]
 After this upgrade, make sure the permissions on /etc/rc.d/rc.sshd are set
 the way you want them. Future upgrades will respect the existing permissions
 settings. Thanks to Manuel Reimer for pointing out that upgrading openssh
 would enable a previously disabled sshd daemon.
 Do better checking of passwd, shadow, and group to avoid adding
 redundant entries to these files. Thanks to Menno Duursma.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'openssh' package(s) on Slackware 8.1, Slackware 9.0, Slackware 9.1, Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"4.4p1-i486-1_slack10.0", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"4.4p1-i486-1_slack10.1", rls:"SLK10.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"4.4p1-i486-1_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK8.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"4.4p1-i386-1_slack8.1", rls:"SLK8.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"4.4p1-i386-1_slack9.0", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"4.4p1-i486-1_slack9.1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"4.4p1-i486-1", rls:"SLKcurrent"))) {
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

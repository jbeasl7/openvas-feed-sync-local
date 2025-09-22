# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57388");
  script_cve_id("CVE-2006-4095", "CVE-2006-4096");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 21:04:44 +0000 (Thu, 15 Feb 2024)");

  script_name("Slackware: Security Advisory (SSA:2006-257-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-257-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.481241");
  script_xref(name:"URL", value:"http://security.FreeBSD.org/advisories/FreeBSD-SA-06:20.bind.asc");
  script_xref(name:"URL", value:"http://www.isc.org/sw/bind/bind-security.php");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SSA:2006-257-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New bind packages are available for Slackware 9.0, 9.1, 10.0, 10.1, 10.2,
and -current to fix a Denial of Service issue.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]

As well as here:
 [link moved to references]

There are no known active exploits at this time.


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/bind-9.3.2_P1-i486-1_slack10.2.tgz:
 Upgraded to bind-9.3.2_P1.
 This update addresses a denial of service vulnerability.
 BIND's CHANGES file says this:
 2066. [security] Handle SIG queries gracefully. [RT #16300]
 The best discussion I've found is in FreeBSD's advisory, so here's a link:
 [link moved to references]
 Also, fixed some missing man pages. (noticed by Xavier Thomassin -- thanks)
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'bind' package(s) on Slackware 9.0, Slackware 9.1, Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.2.6_P1-i486-1_slack10.0", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.3.2_P1-i486-1_slack10.1", rls:"SLK10.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.3.2_P1-i486-1_slack10.2", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.2.6_P1-i386-1_slack9.0", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.2.6_P1-i486-2_slack9.1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.3.2_P1-i486-1", rls:"SLKcurrent"))) {
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

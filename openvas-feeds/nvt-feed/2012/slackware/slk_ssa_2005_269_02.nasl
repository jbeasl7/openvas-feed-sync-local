# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55445");
  script_cve_id("CVE-2005-2495");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2005-269-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2005-269-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.586951");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'X' package(s) announced via the SSA:2005-269-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New X.Org server packages are available for Slackware 10.0, 10.1, 10.2,
and -current to fix a security issue. An integer overflow in the pixmap
handling code may allow the execution of arbitrary code through a
specially crafted pixmap. Slackware 10.2 was patched against this
vulnerability before its release, but new server packages are being issued
for Slackware 10.2 and -current using an improved patch, as there were
some bug reports using certain programs.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/x11-6.8.2-i486-4.tgz: Rebuilt with a modified patch for
 an earlier pixmap overflow issue. The patch released by X.Org was
 slightly different than the one that was circulated previously, and is
 an improved version. There have been reports that the earlier patch
 broke WINE and possibly some other programs.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/x11-xdmx-6.8.2-i486-4.tgz: Patched and rebuilt.
patches/packages/x11-xnest-6.8.2-i486-4.tgz: Patched and rebuilt.
patches/packages/x11-xvfb-6.8.2-i486-4.tgz: Patched and rebuilt.
+--------------------------+");

  script_tag(name:"affected", value:"'X' package(s) on Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"x11", ver:"6.7.0-i486-5", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xnest", ver:"6.7.0-i486-5", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xprt", ver:"6.7.0-i486-5", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xvfb", ver:"6.7.0-i486-5", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"x11", ver:"6.8.1-i486-4", rls:"SLK10.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xdmx", ver:"6.8.1-i486-4", rls:"SLK10.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xnest", ver:"6.8.1-i486-4", rls:"SLK10.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xvfb", ver:"6.8.1-i486-4", rls:"SLK10.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"x11", ver:"6.8.2-i486-4", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xdmx", ver:"6.8.2-i486-4", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xnest", ver:"6.8.2-i486-4", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xvfb", ver:"6.8.2-i486-4", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"x11", ver:"6.8.2-i486-4", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xdmx", ver:"6.8.2-i486-4", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xnest", ver:"6.8.2-i486-4", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xvfb", ver:"6.8.2-i486-4", rls:"SLKcurrent"))) {
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

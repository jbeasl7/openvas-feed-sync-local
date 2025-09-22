# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55444");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2005-269-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2005-269-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.479350");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#Firefox");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla/Firefox' package(s) announced via the SSA:2005-269-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New Mozilla and Firefox packages are available for Slackware 10.0, 10.1,
10.2, and -current to fix security issues:

 MFSA 2005-59 Command-line handling on Linux allows shell execution
 MFSA 2005-58 Firefox 1.0.7 / Mozilla Suite 1.7.12 Vulnerability Fixes
 MFSA 2005-57 IDN heap overrun using soft-hyphens

More details about these issues may be found on the Mozilla web site:

 [links moved to references]


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/mozilla-1.7.12-i486-1.tgz: Upgraded to mozilla-1.7.12.
 This fixes several security issues. For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/mozilla-firefox-1.0.7-i686-1.tgz: Upgraded to firefox-1.0.7.
 This fixes several security issues. For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'Mozilla/Firefox' package(s) on Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.12-i486-1", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.12-noarch-1", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.12-i486-1", rls:"SLK10.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.12-noarch-1", rls:"SLK10.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.12-i486-1", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"1.0.7-i686-1", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.12-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"1.0.7-i686-1", rls:"SLKcurrent"))) {
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

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56693");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2006-114-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-114-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.505446");
  script_xref(name:"URL", value:"http://developer.mozilla.org/devnews/index.php/2006/04/12/sunset-announcement-for-fxtb-10x-and-mozilla-suite-17x/");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla' package(s) announced via the SSA:2006-114-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New Mozilla packages are available for Slackware 10.0, 10.1,
10.2 and -current to fix multiple security issues.

More details about the issues may be found here:

 [link moved to references]

Also note that this release marks the EOL (End Of Life) for the Mozilla
Suite series. It's been a great run, so thanks to everyone who put in
so much effort to make Mozilla a great browser suite. In the next
Slackware release fans of the Mozilla Suite will be able to look
forward to browsing with SeaMonkey, the Suite's successor. Anyone
using an older version of Slackware may want to start thinking about
migrating to another browser -- if not now, when the next problems
with Mozilla are found.

Although the 'sunset announcement' states that mozilla-1.7.13 is the
final mozilla release, I wouldn't be too surprised to see just one
more since there's a Makefile.in bug that needed to be patched here
before Mozilla 1.7.13 would build. If a new release comes out and
fixes only that issue, don't look for a package release on that as
it's already fixed in these packages. If additional issues are
fixed, then there will be new packages. Basically, if upstream
un-EOLs this for a good reason, so will we.


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/mozilla-1.7.13-i486-1.tgz: Upgraded to mozilla-1.7.13.
 This upgrade fixes several possible security bugs.
 For more information, see:
 [link moved to references]
 This release marks the end-of-life of the Mozilla 1.7.x series:
 [link moved to references]
 Mozilla Corporation is recommending that users think about
 migrating to Firefox and Thunderbird.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'mozilla' package(s) on Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.13-i486-1", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.13-noarch-1", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.13-i486-1", rls:"SLK10.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.13-noarch-1", rls:"SLK10.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.13-i486-1", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.13-i486-1", rls:"SLKcurrent"))) {
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

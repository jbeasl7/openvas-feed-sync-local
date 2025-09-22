# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53958");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2005-111-04)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2005-111-04");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.435897");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla/Firefox' package(s) announced via the SSA:2005-111-04 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New Mozilla packages are available for Slackware 10.0, 10.1, and -current
to fix various security issues and bugs. See the Mozilla site for a complete
list of the issues patched:

 [link moved to references]

Also updated is Firefox in Slackware -current.

New versions of the mozilla-plugins symlink creation package are also out for
Slackware 10.0 and 10.1, and a new version of the jre-symlink package for
Slackware -current.


Here are the details from the Slackware 10.1 ChangeLog:
+--------------------------+
patches/packages/mozilla-1.7.7-i486-1.tgz: Upgraded to mozilla-1.7.7.
 This fixes some security issues. For complete details, see:
 [link moved to references]
 (* Security fix *)
patches/packages/mozilla-plugins-1.7.7-noarch-1.tgz: Upgraded Java(TM)
 symlink for Mozilla.
+--------------------------+");

  script_tag(name:"affected", value:"'Mozilla/Firefox' package(s) on Slackware 10.0, Slackware 10.1, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.7-i486-1", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.7-noarch-1", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.7-i486-1", rls:"SLK10.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.7-noarch-1", rls:"SLK10.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"jre-symlink", ver:"1.0.3-noarch-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.7-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"1.0.3-i686-1", rls:"SLKcurrent"))) {
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

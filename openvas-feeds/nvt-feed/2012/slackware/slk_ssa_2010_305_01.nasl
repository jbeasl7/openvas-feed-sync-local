# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68468");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2010-305-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.2|13\.0|13\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2010-305-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2010&m=slackware-security.556706");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/known-vulnerabilities/seamonkey20.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey' package(s) announced via the SSA:2010-305-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New seamonkey packages are available for Slackware 12.2, 13.0, 13.1,
and -current to fix security issues.


Here are the details from the Slackware 13.1 ChangeLog:
+--------------------------+
patches/packages/seamonkey-2.0.10-i486-1_slack13.1.txz: Upgraded.
 This release fixes some more security vulnerabilities.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/seamonkey-solibs-2.0.10-i486-1_slack13.1.txz: Upgraded.
+--------------------------+");

  script_tag(name:"affected", value:"'seamonkey' package(s) on Slackware 12.2, Slackware 13.0, Slackware 13.1, Slackware current.");

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

if(release == "SLK12.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey", ver:"2.0.10-i486-1_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey-solibs", ver:"2.0.10-i486-1_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey", ver:"2.0.10-i486-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey", ver:"2.0.10-x86_64-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey-solibs", ver:"2.0.10-i486-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey-solibs", ver:"2.0.10-x86_64-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey", ver:"2.0.10-i486-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey", ver:"2.0.10-x86_64-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey-solibs", ver:"2.0.10-i486-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey-solibs", ver:"2.0.10-x86_64-1_slack13.1", rls:"SLK13.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey", ver:"2.0.10-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey", ver:"2.0.10-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey-solibs", ver:"2.0.10-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"seamonkey-solibs", ver:"2.0.10-x86_64-1", rls:"SLKcurrent"))) {
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

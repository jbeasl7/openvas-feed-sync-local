# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71971");
  script_cve_id("CVE-2012-2688");
  script_tag(name:"creation_date", value:"2012-09-10 11:16:19 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2012-204-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.0|12\.1|12\.2|13\.0|13\.1|13\.37|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2012-204-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2012&m=slackware-security.479182");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the SSA:2012-204-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New php packages are available for Slackware 12.0, 12.1, 12.2, 13.0, 13.1,
13.37, and -current to fix a security issue.


Here are the details from the Slackware 13.37 ChangeLog:
+--------------------------+
patches/packages/php-5.3.15-i486-1_slack13.37.txz: Upgraded.
 Fixed potential overflow in _php_stream_scandir (CVE-2012-2688).
 (Thanks to Jason Powell, Stas)
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'php' package(s) on Slackware 12.0, Slackware 12.1, Slackware 12.2, Slackware 13.0, Slackware 13.1, Slackware 13.37, Slackware current.");

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

if(release == "SLK12.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.15-i486-1_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.15-i486-1_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.15-i486-1_slack12.2", rls:"SLK12.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.15-i486-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.15-x86_64-1_slack13.0", rls:"SLK13.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.15-i486-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.15-x86_64-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.37") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.15-i486-1_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.15-x86_64-1_slack13.37", rls:"SLK13.37"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.4.5-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.4.5-x86_64-1", rls:"SLKcurrent"))) {
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

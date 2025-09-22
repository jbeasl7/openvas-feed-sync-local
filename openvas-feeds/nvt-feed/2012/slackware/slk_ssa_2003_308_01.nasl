# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53878");
  script_cve_id("CVE-2003-0542");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2003-308-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(8\.1|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-308-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.559833");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache' package(s) announced via the SSA:2003-308-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apache httpd is a hypertext transfer protocol server, and is used
by over two thirds of the Internet's web sites.

Upgraded Apache packages are available for Slackware 8.1, 9.0, 9.1,
and -current. These fix local vulnerabilities that could allow users
who can create or edit Apache config files to gain additional
privileges. Sites running Apache should upgrade to the new packages.

In addition, new mod_ssl packages have been prepared for all platforms,
and new PHP packages have been prepared for Slackware 8.1, 9.0, and
- -current (9.1 already uses PHP 4.3.3). In -current, these packages
also move the Apache module directory from /usr/libexec to
/usr/libexec/apache. Links for all of these related packages are
provided below.

More details about the Apache issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]


Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Mon Nov 3 20:06:29 PST 2003
patches/packages/apache-1.3.29-i486-1.tgz: Upgraded to apache-1.3.29.
 This fixes the following local security issue:
 o CAN-2003-0542 (cve.mitre.org)
 Fix buffer overflows in mod_alias and mod_rewrite which occurred if
 one configured a regular expression with more than 9 captures.
 This vulnerability requires the attacker to create or modify certain
 Apache configuration files, and is not a remote hole. However, it could
 possibly be used to gain additional privileges if access to the Apache
 administrator account can be gained through some other means. All sites
 running Apache should upgrade.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'apache' package(s) on Slackware 8.1, Slackware 9.0, Slackware 9.1, Slackware current.");

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

if(release == "SLK8.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.29-i386-1", rls:"SLK8.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.16_1.3.29-i386-1", rls:"SLK8.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.3-i386-1", rls:"SLK8.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.29-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.16_1.3.29-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.3-i386-1", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.29-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.16_1.3.29-i486-1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.29-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.16_1.3.29-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.3-i486-3", rls:"SLKcurrent"))) {
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

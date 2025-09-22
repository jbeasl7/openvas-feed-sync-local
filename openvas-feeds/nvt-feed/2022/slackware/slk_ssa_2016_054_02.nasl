# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2016.054.02");
  script_cve_id("CVE-2015-7547");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-19 15:51:12 +0000 (Fri, 19 Feb 2016)");

  script_name("Slackware: Security Advisory (SSA:2016-054-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2016-054-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2016&m=slackware-security.569827");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SSA:2016-054-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New glibc packages are available for Slackware 14.1 and -current to
fix security issues.


Here are the details from the Slackware 14.1 ChangeLog:
+--------------------------+
patches/packages/glibc-2.17-i486-11_slack14.1.txz: Rebuilt.
 This update provides a patch to fix the stack-based buffer overflow in
 libresolv that could allow specially crafted DNS responses to seize
 control of execution flow in the DNS client (CVE-2015-7547). However,
 due to a patch applied to Slackware's glibc back in 2009 (don't use the
 gethostbyname4() lookup method as it was causing some cheap routers to
 misbehave), we were not vulnerable to that issue. Nevertheless it seems
 prudent to patch the overflows anyway even if we're not currently using
 the code in question. Thanks to mancha for the backported patch.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/glibc-i18n-2.17-i486-11_slack14.1.txz: Rebuilt.
patches/packages/glibc-profile-2.17-i486-11_slack14.1.txz: Rebuilt.
patches/packages/glibc-solibs-2.17-i486-11_slack14.1.txz: Rebuilt.
+--------------------------+");

  script_tag(name:"affected", value:"'glibc' package(s) on Slackware 14.1, Slackware current.");

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

if(release == "SLK14.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.17-i486-11_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.17-x86_64-11_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.17-i486-11_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.17-x86_64-11_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.17-i486-11_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.17-x86_64-11_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.17-i486-11_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.17-x86_64-11_slack14.1", rls:"SLK14.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.23-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.23-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.23-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.23-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.23-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.23-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.23-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.23-x86_64-1", rls:"SLKcurrent"))) {
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

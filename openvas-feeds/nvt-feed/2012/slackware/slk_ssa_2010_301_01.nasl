# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68470");
  script_cve_id("CVE-2010-3856");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2010-301-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.0|12\.1|12\.2|13\.0|13\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2010-301-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2010&m=slackware-security.1054477");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Oct/344");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SSA:2010-301-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New glibc packages are available for Slackware 12.0, 12.1, 12.2, 13.0, 13.1,
and -current to fix a security issue.


Here are the details from the Slackware 13.1 ChangeLog:
+--------------------------+
patches/packages/glibc-2.11.1-i486-5_slack13.1.txz: Rebuilt.
 Patched 'The GNU C library dynamic linker will dlopen arbitrary DSOs
 during setuid loads.' This security issue allows a local attacker to
 gain root by specifying an unsafe DSO in the library search path to be
 used with a setuid binary in LD_AUDIT mode.
 Bug found by Tavis Ormandy (with thanks to Ben Hawkes and Julien Tinnes).
 For more information, see:
 [links moved to references]
 (* Security fix *)
patches/packages/glibc-i18n-2.11.1-i486-5_slack13.1.txz: Rebuilt.
patches/packages/glibc-profile-2.11.1-i486-5_slack13.1.txz: Rebuilt.
patches/packages/glibc-solibs-2.11.1-i486-5_slack13.1.txz: Upgraded.
 (* Security fix *)
patches/packages/glibc-zoneinfo-2.11.1-noarch-5_slack13.1.txz: Upgraded.
 Rebuilt to tzcode2010n and tzdata2010n.
+--------------------------+");

  script_tag(name:"affected", value:"'glibc' package(s) on Slackware 12.0, Slackware 12.1, Slackware 12.2, Slackware 13.0, Slackware 13.1, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.5-i486-6_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.5-noarch-6_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.5-i486-6_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.5-i486-6_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.5-noarch-9_slack12.0", rls:"SLK12.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.7-i486-12_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.7-noarch-12_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.7-i486-12_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.7-i486-12_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.7-noarch-12_slack12.0", rls:"SLK12.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.7-i486-19_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.7-noarch-19_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.7-i486-19_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.7-i486-19_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.7-noarch-19_slack12.2", rls:"SLK12.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.9-i486-5_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.9-x86_64-5_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.9-i486-5_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.9-x86_64-5_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.9-i486-5_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.9-x86_64-5_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.9-i486-5_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.9-x86_64-5_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.9-noarch-5_slack13.0", rls:"SLK13.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.11.1-i486-5_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.11.1-x86_64-5_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.11.1-i486-5_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.11.1-x86_64-5_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.11.1-i486-5_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.11.1-x86_64-5_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.11.1-i486-5_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.11.1-x86_64-5_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.11.1-noarch-5_slack13.1", rls:"SLK13.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.12.1-i486-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.12.1-x86_64-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.12.1-i486-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.12.1-x86_64-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.12.1-i486-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.12.1-x86_64-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.12.1-i486-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.12.1-x86_64-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.12.1-noarch-3", rls:"SLKcurrent"))) {
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

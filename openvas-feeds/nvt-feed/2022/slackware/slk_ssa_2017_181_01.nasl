# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2017.181.01");
  script_cve_id("CVE-2017-1000366");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-05 17:07:37 +0000 (Wed, 05 Jul 2017)");

  script_name("Slackware: Security Advisory (SSA:2017-181-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2017-181-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2017&m=slackware-security.564513");
  script_xref(name:"URL", value:"https://sourceware.org/git/?p=glibc.git,a=commit,h=3776f38fcd267c127ba5eb222e2c614c191744aa");
  script_xref(name:"URL", value:"https://sourceware.org/git/?p=glibc.git,a=commit,h=3c7cd21290cabdadd72984fb69bc51e64ff1002d");
  script_xref(name:"URL", value:"https://sourceware.org/git/?p=glibc.git,a=commit,h=46703a3995aa3ca2b816814aa4ad05ed524194dd");
  script_xref(name:"URL", value:"https://sourceware.org/git/?p=glibc.git,a=commit,h=adc7e06fb412a2a1ee52f8cb788caf436335b9f3");
  script_xref(name:"URL", value:"https://sourceware.org/git/?p=glibc.git,a=commit,h=c69d4a0f680a24fdbe323764a50382ad324041e9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SSA:2017-181-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New glibc packages are available for Slackware 14.2 and -current to
fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/glibc-2.23-i586-2_slack14.2.txz: Rebuilt.
 Applied upstream security hardening patches from git.
 For more information, see:
 [links moved to references]
 (* Security fix *)
patches/packages/glibc-i18n-2.23-i586-2_slack14.2.txz: Rebuilt.
patches/packages/glibc-profile-2.23-i586-2_slack14.2.txz: Rebuilt.
 (* Security fix *)
patches/packages/glibc-solibs-2.23-i586-2_slack14.2.txz: Rebuilt.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'glibc' package(s) on Slackware 14.2, Slackware current.");

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

if(release == "SLK14.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.23-i586-2_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.23-x86_64-2_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.23-i586-2_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.23-x86_64-2_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.23-i586-2_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.23-x86_64-2_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.23-i586-2_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.23-x86_64-2_slack14.2", rls:"SLK14.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.25-i586-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc", ver:"2.25-x86_64-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.25-i586-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-i18n", ver:"2.25-x86_64-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.25-i586-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-profile", ver:"2.25-x86_64-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.25-i586-3", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"glibc-solibs", ver:"2.25-x86_64-3", rls:"SLKcurrent"))) {
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

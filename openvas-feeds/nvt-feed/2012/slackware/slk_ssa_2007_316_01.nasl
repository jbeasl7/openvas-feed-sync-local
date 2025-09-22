# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.59020");
  script_cve_id("CVE-2007-3387", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2007-316-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|11\.0|12\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2007-316-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.761882");
  script_xref(name:"URL", value:"http://poppler.freedesktop.org/");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20071107-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xpdf/poppler/koffice/kdegraphics' package(s) announced via the SSA:2007-316-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New xpdf packages are available for Slackware 9.1, 10.0, 10.1, 10.2, 11.0,
12.0, and -current. New poppler packages are available for Slackware 12.0
and -current. New koffice packages are available for Slackware 11.0, 12.0,
and -current. New kdegraphics packages are available for Slackware 10.2,
11.0, 12.0, and -current.

These updated packages address similar bugs which could be used to crash
applications linked with poppler or that use code from xpdf through the
use of a malformed PDF document. It is possible that a maliciously
crafted document could cause code to be executed in the context of the
user running the application processing the PDF.

These advisories and CVE entries cover the bugs:
 [links moved to references]


Here are the details from the Slackware 12.0 ChangeLog:
+--------------------------+
patches/packages/kdegraphics-3.5.7-i486-2_slack12.0.tgz:
 Patched xpdf related bugs.
 For more information, see:
 [links moved to references]
 (* Security fix *)
patches/packages/koffice-1.6.3-i486-2_slack12.0.tgz:
 Patched xpdf related bugs.
 For more information, see:
 [links moved to references]
 (* Security fix *)
patches/packages/poppler-0.6.2-i486-1_slack12.0.tgz:
 Upgraded to poppler-0.6.2.
 This release fixes xpdf related bugs.
 For more information, see:
 [links moved to references]
 (* Security fix *)
patches/packages/xpdf-3.02pl2-i486-1_slack12.0.tgz:
 Upgraded to xpdf-3.02pl2.
 The pl2 patch fixes a crash in xpdf.
 Some theorize that this could be used to execute arbitrary code if an
 untrusted PDF file is opened, but no real-world examples are known (yet).
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'xpdf/poppler/koffice/kdegraphics' package(s) on Slackware 9.1, Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware 11.0, Slackware 12.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack10.0", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack10.1", rls:"SLK10.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"kdegraphics", ver:"3.4.2-i486-3_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK11.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"kdegraphics", ver:"3.5.4-i486-2_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"koffice", ver:"1.5.2-i486-5_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"kdegraphics", ver:"3.5.7-i486-2_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"koffice", ver:"1.6.3-i486-2_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"poppler", ver:"0.6.2-i486-1_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack12.0", rls:"SLK12.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack9.1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"kdegraphics", ver:"3.5.8-i486-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"koffice", ver:"1.6.3-i486-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"poppler", ver:"0.6.2-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1", rls:"SLKcurrent"))) {
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

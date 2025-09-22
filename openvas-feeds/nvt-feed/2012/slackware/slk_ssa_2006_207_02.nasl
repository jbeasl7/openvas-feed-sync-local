# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57171");
  script_cve_id("CVE-2006-1861");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2006-207-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-207-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.549901");
  script_xref(name:"URL", value:"http://lists.freedesktop.org/archives/xorg-announce/2006-June/000100.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'x11' package(s) announced via the SSA:2006-207-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New x11 packages are available for Slackware 10.2 and -current to
fix security issues. In addition, fontconfig and freetype have been
split out from the x11 packages in -current, so if you run -current
you'll also need to install those new packages.

More details about the issues may be found here:

 [links moved to references]


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/x11-6.8.2-i486-6_slack10.2.tgz:
 Patched some more possible linux 2.6.x setuid() related bugs:
 [link moved to references]
 Patched CVE-2006-1861 linux 2.6.x setuid() related bugs in freetype2.
 (* Security fix *)
patches/packages/x11-devel-6.8.2-i486-6_slack10.2.tgz: Patched as above.
 (* Security fix *)
patches/packages/x11-xdmx-6.8.2-i486-6_slack10.2.tgz: Rebuilt.
patches/packages/x11-xnest-6.8.2-i486-6_slack10.2.tgz: Rebuilt.
patches/packages/x11-xvfb-6.8.2-i486-6_slack10.2.tgz: Rebuilt.
+--------------------------+");

  script_tag(name:"affected", value:"'x11' package(s) on Slackware 10.2, Slackware current.");

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

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"x11", ver:"6.8.2-i486-6_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-devel", ver:"6.8.2-i486-6_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xdmx", ver:"6.8.2-i486-6_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xnest", ver:"6.8.2-i486-6_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xvfb", ver:"6.8.2-i486-6_slack10.2", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"fontconfig", ver:"2.2.3-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"freetype", ver:"2.1.9-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11", ver:"6.9.0-i486-5", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-devel", ver:"6.9.0-i486-5", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xdmx", ver:"6.9.0-i486-5", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xnest", ver:"6.9.0-i486-5", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"x11-xvfb", ver:"6.9.0-i486-5", rls:"SLKcurrent"))) {
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

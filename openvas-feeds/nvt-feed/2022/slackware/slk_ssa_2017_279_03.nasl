# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2017.279.03");
  script_cve_id("CVE-2017-13721", "CVE-2017-13723");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-05 23:04:49 +0000 (Sun, 05 Nov 2017)");

  script_name("Slackware: Security Advisory (SSA:2017-279-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.0|14\.1|14\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2017-279-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2017&m=slackware-security.872751");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server' package(s) announced via the SSA:2017-279-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New xorg-server packages are available for Slackware 14.0, 14.1, 14.2,
and -current to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/xorg-server-1.18.3-i586-4_slack14.2.txz: Rebuilt.
 This update fixes two security issues:
 Xext/shm: Validate shmseg resource id, otherwise it can belong to a
 non-existing client and abort X server with FatalError 'client not
 in use', or overwrite existing segment of another existing client.
 Generating strings for XKB data used a single shared static buffer,
 which offered several opportunities for errors. Use a ring of
 resizable buffers instead, to avoid problems when strings end up
 longer than anticipated.
 For more information, see:
 [links moved to references]
 (* Security fix *)
patches/packages/xorg-server-xephyr-1.18.3-i586-4_slack14.2.txz: Rebuilt.
patches/packages/xorg-server-xnest-1.18.3-i586-4_slack14.2.txz: Rebuilt.
patches/packages/xorg-server-xvfb-1.18.3-i586-4_slack14.2.txz: Rebuilt.
+--------------------------+");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware current.");

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

if(release == "SLK14.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.12.4-i486-4_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.12.4-x86_64-4_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.12.4-i486-4_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.12.4-x86_64-4_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.12.4-i486-4_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.12.4-x86_64-4_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.12.4-i486-4_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.12.4-x86_64-4_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.14.3-i486-5_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.14.3-x86_64-5_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.14.3-i486-5_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.14.3-x86_64-5_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.14.3-i486-5_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.14.3-x86_64-5_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.14.3-i486-5_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.14.3-x86_64-5_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.18.3-i586-4_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.18.3-x86_64-4_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.18.3-i586-4_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.18.3-x86_64-4_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.18.3-i586-4_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.18.3-x86_64-4_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.18.3-i586-4_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.18.3-x86_64-4_slack14.2", rls:"SLK14.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.19.4-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.19.4-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.19.4-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.19.4-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.19.4-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.19.4-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.19.4-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.19.4-x86_64-1", rls:"SLKcurrent"))) {
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

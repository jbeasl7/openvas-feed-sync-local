# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.056.01");
  script_cve_id("CVE-2025-26594", "CVE-2025-26595", "CVE-2025-26596", "CVE-2025-26597", "CVE-2025-26598", "CVE-2025-26599", "CVE-2025-26600", "CVE-2025-26601");
  script_tag(name:"creation_date", value:"2025-02-26 04:04:45 +0000 (Wed, 26 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 16:15:39 +0000 (Tue, 25 Feb 2025)");

  script_name("Slackware: Security Advisory (SSA:2025-056-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-056-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.772545");
  script_xref(name:"URL", value:"https://lists.x.org/archives/xorg-announce/2025-February/003584.html");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26594");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26595");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26596");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26597");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26598");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26599");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26600");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26601");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server' package(s) announced via the SSA:2025-056-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New xorg-server packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/xorg-server-1.20.14-i586-15_slack15.0.txz: Rebuilt.
 This update fixes security issues:
 Use-after-free of the root cursor.
 Buffer overflow in XkbVModMaskText().
 Heap overflow in XkbWriteKeySyms().
 Buffer overflow in XkbChangeTypesOfKey().
 Out-of-bounds write in CreatePointerBarrierClient().
 Use of uninitialized pointer in compRedirectWindow().
 Use-after-free in PlayReleasedEvents().
 Use-after-free in SyncInitTrigger().
 Thanks to Jan-Niklas Sohn and the Trend Micro Zero Day Initiative.
 For more information, see:
 [links moved to references]
 (* Security fix *)
patches/packages/xorg-server-xephyr-1.20.14-i586-15_slack15.0.txz: Rebuilt.
patches/packages/xorg-server-xnest-1.20.14-i586-15_slack15.0.txz: Rebuilt.
patches/packages/xorg-server-xvfb-1.20.14-i586-15_slack15.0.txz: Rebuilt.
patches/packages/xorg-server-xwayland-21.1.4-i586-13_slack15.0.txz: Rebuilt.
 This update fixes security issues:
 Use-after-free of the root cursor.
 Buffer overflow in XkbVModMaskText().
 Heap overflow in XkbWriteKeySyms().
 Buffer overflow in XkbChangeTypesOfKey().
 Out-of-bounds write in CreatePointerBarrierClient().
 Use of uninitialized pointer in compRedirectWindow().
 Use-after-free in PlayReleasedEvents().
 Use-after-free in SyncInitTrigger().
 Thanks to Jan-Niklas Sohn and the Trend Micro Zero Day Initiative.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Slackware 15.0, Slackware current.");

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

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.20.14-i586-15_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"1.20.14-x86_64-15_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.20.14-i586-15_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"1.20.14-x86_64-15_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.20.14-i586-15_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"1.20.14-x86_64-15_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.20.14-i586-15_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"1.20.14-x86_64-15_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"21.1.4-i586-13_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"21.1.4-x86_64-13_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"21.1.16-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server", ver:"21.1.16-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"21.1.16-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xephyr", ver:"21.1.16-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"21.1.16-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xnest", ver:"21.1.16-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"21.1.16-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xvfb", ver:"21.1.16-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"24.1.6-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xorg-server-xwayland", ver:"24.1.6-x86_64-1", rls:"SLKcurrent"))) {
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

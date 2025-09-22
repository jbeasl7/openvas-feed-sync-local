# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.056.02");
  script_cve_id("CVE-2025-26594", "CVE-2025-26595", "CVE-2025-26596", "CVE-2025-26597", "CVE-2025-26598", "CVE-2025-26599", "CVE-2025-26600", "CVE-2025-26601");
  script_tag(name:"creation_date", value:"2025-02-26 04:04:45 +0000 (Wed, 26 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 16:15:39 +0000 (Tue, 25 Feb 2025)");

  script_name("Slackware: Security Advisory (SSA:2025-056-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-056-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.411351");
  script_xref(name:"URL", value:"https://lists.x.org/archives/xorg-announce/2025-February/003584.html");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26594");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26595");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26596");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26597");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26598");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26599");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26600");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-26601");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tigervnc' package(s) announced via the SSA:2025-056-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New tigervnc packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
extra/tigervnc/tigervnc-1.12.0-i586-8_slack15.0.txz: Rebuilt.
 Recompiled against xorg-server-1.20.14, including patches for
 security issues:
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

  script_tag(name:"affected", value:"'tigervnc' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"tigervnc", ver:"1.12.0-i586-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"tigervnc", ver:"1.12.0-x86_64-8_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"tigervnc", ver:"1.15.0-i686-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"tigervnc", ver:"1.15.0-x86_64-2", rls:"SLKcurrent"))) {
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

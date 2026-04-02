# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2026.070.02");
  script_cve_id("CVE-2025-10911", "CVE-2026-0989", "CVE-2026-0990", "CVE-2026-0992", "CVE-2026-1757");
  script_tag(name:"creation_date", value:"2026-03-13 04:35:08 +0000 (Fri, 13 Mar 2026)");
  script_version("2026-03-13T15:49:08+0000");
  script_tag(name:"last_modification", value:"2026-03-13 15:49:08 +0000 (Fri, 13 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-02 13:15:58 +0000 (Mon, 02 Feb 2026)");

  script_name("Slackware: Security Advisory (SSA:2026-070-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2026-070-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2026&m=slackware-security.391099");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-10911");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0989");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0990");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0992");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-1757");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the SSA:2026-070-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New libxml2 packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/libxml2-2.11.9-i586-8_slack15.0.txz: Rebuilt.
 This update fixes security issues:
 CVE-2026-1757 fix: Memory leak in xmllint Shell - shell.c
 CVE-2026-0990 fix: Prevent infinite recursion in
 xmlCatalogListXMLResolve
 CVE-2026-0992 fix: Exponential behavior when handling
 parser: Fix infinite loop in xmlCtxtParseContent
 CVE-2025-10911 libxslt related: Ignore next/prev of documents when
 traversing XPath
 CVE-2026-0989 fix: Add RelaxNG include limit
 Thanks to r1w1s1 for locating the backported patches.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'libxml2' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.11.9-i586-8_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.11.9-x86_64-8_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.15.2-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.15.2-x86_64-1", rls:"SLKcurrent"))) {
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

# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2026.059.01");
  script_cve_id("CVE-2026-28295", "CVE-2026-28296");
  script_tag(name:"creation_date", value:"2026-03-02 04:36:20 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-26 16:24:09 +0000 (Thu, 26 Feb 2026)");

  script_name("Slackware: Security Advisory (SSA:2026-059-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2026-059-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2026&m=slackware-security.350634");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-28295");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-28296");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gvfs' package(s) announced via the SSA:2026-059-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New gvfs packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/gvfs-1.48.1-i586-2_slack15.0.txz: Rebuilt.
 This update fixes security issues:
 ftp: Use control connection address for PASV data.
 ftp: Reject paths containing CR/LF characters.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'gvfs' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"gvfs", ver:"1.48.1-i586-2_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gvfs", ver:"1.48.1-x86_64-2_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gvfs", ver:"1.58.2-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gvfs", ver:"1.58.2-x86_64-1", rls:"SLKcurrent"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.014.01");
  script_cve_id("CVE-2024-12084", "CVE-2024-12085", "CVE-2024-12086", "CVE-2024-12087", "CVE-2024-12088", "CVE-2024-12747");
  script_tag(name:"creation_date", value:"2025-01-15 04:08:10 +0000 (Wed, 15 Jan 2025)");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-15 15:15:10 +0000 (Wed, 15 Jan 2025)");

  script_name("Slackware: Security Advisory (SSA:2025-014-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-014-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.405905");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/952657");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-12084");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-12085");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-12086");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-12087");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-12088");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-12747");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsync' package(s) announced via the SSA:2025-014-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New rsync packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/rsync-3.4.0-i586-1_slack15.0.txz: Upgraded.
 This is a security release, fixing several important security vulnerabilities:
 Heap Buffer Overflow in Checksum Parsing.
 Info Leak via uninitialized Stack contents defeats ASLR.
 Server leaks arbitrary client files.
 Server can make client write files outside of destination directory using symbolic links.
 --safe-links Bypass.
 Symlink race condition.
 Many thanks to Simon Scannell, Pedro Gallegos, and Jasiel Spelman at
 Google Cloud Vulnerability Research and Aleksei Gorban (Loqpa) for
 discovering these vulnerabilities and working with the rsync project
 to develop and test fixes.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'rsync' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"rsync", ver:"3.4.0-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"rsync", ver:"3.4.0-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"rsync", ver:"3.4.0-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"rsync", ver:"3.4.0-x86_64-1", rls:"SLKcurrent"))) {
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

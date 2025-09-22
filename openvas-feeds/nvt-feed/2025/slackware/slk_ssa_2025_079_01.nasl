# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.079.01");
  script_cve_id("CVE-2024-57970", "CVE-2025-1632", "CVE-2025-25724");
  script_tag(name:"creation_date", value:"2025-03-21 04:04:36 +0000 (Fri, 21 Mar 2025)");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-17 15:56:36 +0000 (Thu, 17 Jul 2025)");

  script_name("Slackware: Security Advisory (SSA:2025-079-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-079-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.364996");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-57970");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-1632");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-25724");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the SSA:2025-079-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New libarchive packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/libarchive-3.7.8-i586-1_slack15.0.txz: Upgraded.
 This update fixes bugs and security issues:
 tar reader: Handle truncation in the middle of a GNU long linkname.
 unzip: fix null pointer dereference.
 tar reader: fix unchecked return value in list_item_verbose().
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'libarchive' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.7.8-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.7.8-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.7.8-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.7.8-x86_64-1", rls:"SLKcurrent"))) {
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

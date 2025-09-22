# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2024.258.01");
  script_cve_id("CVE-2024-20696", "CVE-2024-26256");
  script_tag(name:"creation_date", value:"2024-09-16 04:08:58 +0000 (Mon, 16 Sep 2024)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-09 17:15:47 +0000 (Tue, 09 Apr 2024)");

  script_name("Slackware: Security Advisory (SSA:2024-258-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2024-258-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.406411");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-20696");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-26256");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the SSA:2024-258-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New libarchive packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/libarchive-3.7.5-i586-1_slack15.0.txz: Upgraded.
 This update fixes the following security issues:
 fix multiple vulnerabilities identified by SAST (#2251, #2256)
 cpio: ignore out-of-range gid/uid/size/ino and harden AFIO parsing (#2258)
 lzop: prevent integer overflow (#2174)
 rar4: protect copy_from_lzss_window_to_unp() (#2172, CVE-2024-20696)
 rar4: fix CVE-2024-26256 (#2269)
 rar4: fix OOB in delta and audio filter (#2148, #2149)
 rar4: fix out of boundary access with large files (#2179)
 rar4: add boundary checks to rgb filter (#2210)
 rar4: fix OOB access with unicode filenames (#2203)
 rar5: clear 'data ready' cache on window buffer reallocs (#2265)
 rpm: calculate huge header sizes correctly (#2158)
 unzip: unify EOF handling (#2175)
 util: fix out of boundary access in mktemp functions (#2160)
 uu: stop processing if lines are too long (#2168)
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

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.7.5-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.7.5-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.7.5-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libarchive", ver:"3.7.5-x86_64-1", rls:"SLKcurrent"))) {
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

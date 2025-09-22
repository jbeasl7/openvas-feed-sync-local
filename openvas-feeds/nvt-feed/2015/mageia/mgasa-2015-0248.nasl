# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130128");
  script_cve_id("CVE-2015-3096", "CVE-2015-3098", "CVE-2015-3099", "CVE-2015-3100", "CVE-2015-3101", "CVE-2015-3102", "CVE-2015-3103", "CVE-2015-3104", "CVE-2015-3105", "CVE-2015-3106", "CVE-2015-3107", "CVE-2015-3108", "CVE-2015-3113");
  script_tag(name:"creation_date", value:"2015-10-15 07:43:03 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 17:41:54 +0000 (Tue, 02 Jul 2024)");

  script_name("Mageia: Security Advisory (MGASA-2015-0248)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0248");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0248.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16139");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-11.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-14.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2015-0248 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.468 contains fixes to critical security
vulnerabilities found in earlier versions that could cause a crash and
potentially allow an attacker to take control of the affected system.

Adobe is aware of reports that CVE-2015-3113 is being actively exploited in
the wild via limited, targeted attacks. Systems running Internet Explorer
for Windows 7 and below, as well as Firefox on Windows XP, are known targets.

This update resolves a heap buffer overflow vulnerability that could lead to
code execution (CVE-2015-3113).

This update resolves a vulnerability (CVE-2015-3096) that could be exploited
to bypass the fix for CVE-2014-5333.

This update resolves vulnerabilities that could be exploited to bypass the
same-origin-policy and lead to information disclosure (CVE-2015-3098,
CVE-2015-3099, CVE-2015-3102).

This update resolves a stack overflow vulnerability that could lead to code
execution (CVE-2015-3100).

This update resolves a permission issue in the Flash broker for Internet
Explorer that could be exploited to perform privilege escalation from low to
medium integrity level (CVE-2015-3101).

This update resolves an integer overflow vulnerability that could lead to
code execution (CVE-2015-3104).

This update resolves a memory corruption vulnerability that could lead to
code execution (CVE-2015-3105).

This update resolves use-after-free vulnerabilities that could lead to
code execution (CVE-2015-3103, CVE-2015-3106, CVE-2015-3107).

This update resolves a memory leak vulnerability that could be used to
bypass ASLR (CVE-2015-3108).");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 4, Mageia 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.468~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.468~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.468~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.468~1.mga5.nonfree", rls:"MAGEIA5"))) {
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

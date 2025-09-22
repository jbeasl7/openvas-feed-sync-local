# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0155");
  script_cve_id("CVE-2015-0346", "CVE-2015-0347", "CVE-2015-0348", "CVE-2015-0349", "CVE-2015-0350", "CVE-2015-0351", "CVE-2015-0352", "CVE-2015-0353", "CVE-2015-0354", "CVE-2015-0355", "CVE-2015-0356", "CVE-2015-0357", "CVE-2015-0358", "CVE-2015-0359", "CVE-2015-0360", "CVE-2015-3038", "CVE-2015-3039", "CVE-2015-3040", "CVE-2015-3041", "CVE-2015-3042", "CVE-2015-3043", "CVE-2015-3044");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:34:42 +0000 (Tue, 16 Jul 2024)");

  script_name("Mageia: Security Advisory (MGASA-2015-0155)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0155");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0155.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15697");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-06.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2015-0155 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.457 contains fixes to critical security
vulnerabilities found in earlier versions that could cause a crash and
potentially allow an attacker to take control of the affected system.

This update resolves memory corruption vulnerabilities that could lead to
code execution (CVE-2015-0347, CVE-2015-0350, CVE-2015-0352, CVE-2015-0353,
CVE-2015-0354, CVE-2015-0355, CVE-2015-0360, CVE-2015-3038, CVE-2015-3041,
CVE-2015-3042, CVE-2015-3043).

This update resolves a type confusion vulnerability that could lead to code
execution (CVE-2015-0356).

This update resolves a buffer overflow vulnerability that could lead to
code execution (CVE-2015-0348).

This update resolves use-after-free vulnerabilities that could lead to code
execution (CVE-2015-0349, CVE-2015-0351, CVE-2015-0358, CVE-2015-3039).

This update resolves double-free vulnerabilities that could lead to code
execution (CVE-2015-0346, CVE-2015-0359).

This update resolves memory leak vulnerabilities that could be used to
bypass ASLR (CVE-2015-0357, CVE-2015-3040).

This update resolves a security bypass vulnerability that could lead to
information disclosure (CVE-2015-3044).");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.457~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.457~1.mga4.nonfree", rls:"MAGEIA4"))) {
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

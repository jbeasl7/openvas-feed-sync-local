# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131312");
  script_cve_id("CVE-2016-1006", "CVE-2016-1011", "CVE-2016-1012", "CVE-2016-1013", "CVE-2016-1014", "CVE-2016-1015", "CVE-2016-1016", "CVE-2016-1017", "CVE-2016-1018", "CVE-2016-1019", "CVE-2016-1020", "CVE-2016-1021", "CVE-2016-1022", "CVE-2016-1023", "CVE-2016-1024", "CVE-2016-1025", "CVE-2016-1026", "CVE-2016-1027", "CVE-2016-1028", "CVE-2016-1029", "CVE-2016-1030", "CVE-2016-1031", "CVE-2016-1032", "CVE-2016-1033");
  script_tag(name:"creation_date", value:"2016-05-09 11:18:14 +0000 (Mon, 09 May 2016)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-07 14:50:02 +0000 (Thu, 07 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0134)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0134");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0134.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18158");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-10.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2016-0134 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.616 contains fixes to critical security
vulnerabilities found in earlier versions that could potentially allow
an attacker to take control of the affected system.

This update hardens a mitigation against JIT spraying attacks that could
be used to bypass memory layout randomization mitigations (CVE-2016-1006).

This update resolves type confusion vulnerabilities that could lead to code
execution (CVE-2016-1015, CVE-2016-1019).

This update resolves use-after-free vulnerabilities that could lead to code
execution (CVE-2016-1011, CVE-2016-1013, CVE-2016-1016, CVE-2016-1017,
CVE-2016-1031).

This update resolves memory corruption vulnerabilities that could lead to code
execution (CVE-2016-1012, CVE-2016-1020, CVE-2016-1021, CVE-2016-1022,
CVE-2016-1023, CVE-2016-1024, CVE-2016-1025, CVE-2016-1026, CVE-2016-1027,
CVE-2016-1028, CVE-2016-1029, CVE-2016-1032, CVE-2016-1033).

This update resolves a stack overflow vulnerability that could lead to code
execution (CVE-2016-1018).

This update resolves a security bypass vulnerability (CVE-2016-1030).

This update resolves a vulnerability in the directory search path used to find
resources that could lead to code execution (CVE-2016-1014).

Adobe reports that CVE-2016-1019 is already being actively exploited on Windows
systems.");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.616~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.616~1.mga5.nonfree", rls:"MAGEIA5"))) {
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

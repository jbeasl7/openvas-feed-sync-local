# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131165");
  script_cve_id("CVE-2015-8459", "CVE-2015-8460", "CVE-2015-8634", "CVE-2015-8635", "CVE-2015-8636", "CVE-2015-8638", "CVE-2015-8639", "CVE-2015-8640", "CVE-2015-8641", "CVE-2015-8642", "CVE-2015-8643", "CVE-2015-8644", "CVE-2015-8645", "CVE-2015-8646", "CVE-2015-8647", "CVE-2015-8648", "CVE-2015-8649", "CVE-2015-8650", "CVE-2015-8651");
  script_tag(name:"creation_date", value:"2015-12-29 09:15:47 +0000 (Tue, 29 Dec 2015)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-29 16:57:04 +0000 (Tue, 29 Dec 2015)");

  script_name("Mageia: Security Advisory (MGASA-2015-0493)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0493");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0493.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17411");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-01.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2015-0493 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.559 contains fixes to critical security
vulnerabilities found in earlier versions that could potentially allow an
attacker to take control of the affected system.

This update resolves a type confusion vulnerability that could lead to code
execution (CVE-2015-8644).

This update resolves an integer overflow vulnerability that could lead to code
execution (CVE-2015-8651).

This update resolves use-after-free vulnerabilities that could lead to code
execution (CVE-2015-8634, CVE-2015-8635, CVE-2015-8638, CVE-2015-8639,
CVE-2015-8640, CVE-2015-8641, CVE-2015-8642, CVE-2015-8643, CVE-2015-8646,
CVE-2015-8647, CVE-2015-8648, CVE-2015-8649, CVE-2015-8650).

This update resolves memory corruption vulnerabilities that could lead to code
execution (CVE-2015-8459, CVE-2015-8460, CVE-2015-8636, CVE-2015-8645).");

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

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.559~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.559~1.mga5.nonfree", rls:"MAGEIA5"))) {
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

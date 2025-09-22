# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851152");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2015-12-31 05:12:51 +0100 (Thu, 31 Dec 2015)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-8459", "CVE-2015-8460", "CVE-2015-8634", "CVE-2015-8635",
                "CVE-2015-8636", "CVE-2015-8638", "CVE-2015-8639", "CVE-2015-8640",
                "CVE-2015-8641", "CVE-2015-8642", "CVE-2015-8643", "CVE-2015-8644",
                "CVE-2015-8645", "CVE-2015-8646", "CVE-2015-8647", "CVE-2015-8648",
                "CVE-2015-8649", "CVE-2015-8650", "CVE-2015-8651");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-17 02:59:00 +0000 (Fri, 17 Feb 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for flash-player (SUSE-SU-2015:2401-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for flash-player fixes the following issues:

  - CVE-2015-8644: Type confusion vulnerability that could lead to code
  execution.

  - CVE-2015-8651: Integer overflow vulnerability that could lead to code
  execution.

  - CVE-2015-8634, CVE-2015-8635, CVE-2015-8638, CVE-2015-8639,
  CVE-2015-8640, CVE-2015-8641, CVE-2015-8642, CVE-2015-8643,
  CVE-2015-8646, CVE-2015-8647, CVE-2015-8648, CVE-2015-8649,
  CVE-2015-8650: Use-after-free vulnerabilities that could lead to code
  execution.

  - CVE-2015-8459, CVE-2015-8460, CVE-2015-8636, CVE-2015-8645: Memory
  corruption vulnerabilities that could lead to code execution.");

  script_tag(name:"affected", value:"flash-player on SUSE Linux Enterprise Desktop 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:2401-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLED12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.559~117.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.559~117.1", rls:"SLED12.0SP0"))) {
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

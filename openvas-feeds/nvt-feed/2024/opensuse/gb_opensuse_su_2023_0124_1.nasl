# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833052");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-2929", "CVE-2023-2930", "CVE-2023-2931", "CVE-2023-2932", "CVE-2023-2933", "CVE-2023-2934", "CVE-2023-2935", "CVE-2023-2936", "CVE-2023-2937", "CVE-2023-2938", "CVE-2023-2939", "CVE-2023-2940", "CVE-2023-2941", "CVE-2023-3079");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-12 16:47:28 +0000 (Mon, 12 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:03:25 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2023:0124-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0124-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/A35IT6IFSYXFW7MRV2MPFJWXHDADMI6Q");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2023:0124-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  - Chromium 114.0.5735.106 (boo#1212044):

  * CVE-2023-3079: Type Confusion in V8

  - Chromium 114.0.5735.90 (boo#1211843):

  * CSS text-wrap: balance is available

  * Cookies partitioned by top level site (CHIPS)

  * New Popover API

  - Security fixes:

  * CVE-2023-2929: Out of bounds write in Swiftshader

  * CVE-2023-2930: Use after free in Extensions

  * CVE-2023-2931: Use after free in PDF

  * CVE-2023-2932: Use after free in PDF

  * CVE-2023-2933: Use after free in PDF

  * CVE-2023-2934: Out of bounds memory access in Mojo

  * CVE-2023-2935: Type Confusion in V8

  * CVE-2023-2936: Type Confusion in V8

  * CVE-2023-2937: Inappropriate implementation in Picture In Picture

  * CVE-2023-2938: Inappropriate implementation in Picture In Picture

  * CVE-2023-2939: Insufficient data validation in Installer

  * CVE-2023-2940: Inappropriate implementation in Downloads

  * CVE-2023-2941: Inappropriate implementation in Extensions API");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Backports SLE-15-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~114.0.5735.106~bp154.2.90.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~114.0.5735.106~bp154.2.90.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~114.0.5735.106~bp154.2.90.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~114.0.5735.106~bp154.2.90.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
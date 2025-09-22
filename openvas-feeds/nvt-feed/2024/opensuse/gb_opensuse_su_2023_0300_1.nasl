# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833791");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-5218", "CVE-2023-5473", "CVE-2023-5474", "CVE-2023-5475", "CVE-2023-5476", "CVE-2023-5477", "CVE-2023-5478", "CVE-2023-5479", "CVE-2023-5481", "CVE-2023-5483", "CVE-2023-5484", "CVE-2023-5485", "CVE-2023-5486", "CVE-2023-5487");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-12 15:50:51 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:03:42 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2023:0300-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSEBackportsSLE-15-SP5|openSUSEBackportsSLE-15-SP4)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0300-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/V6FXBWPURXQ5GA2B7HRPHLBGPNS46F3Y");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2023:0300-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 118.0.5993.70 (boo#1216111)

  - CVE-2023-5218: Use after free in Site Isolation

  - CVE-2023-5487: Inappropriate implementation in Fullscreen

  - CVE-2023-5484: Inappropriate implementation in Navigation

  - CVE-2023-5475: Inappropriate implementation in DevTools

  - CVE-2023-5483: Inappropriate implementation in Intents

  - CVE-2023-5481: Inappropriate implementation in Downloads

  - CVE-2023-5476: Use after free in Blink History

  - CVE-2023-5474: Heap buffer overflow in PDF

  - CVE-2023-5479: Inappropriate implementation in Extensions API

  - CVE-2023-5485: Inappropriate implementation in Autofill

  - CVE-2023-5478: Inappropriate implementation in Autofill

  - CVE-2023-5477: Inappropriate implementation in Installer

  - CVE-2023-5486: Inappropriate implementation in Input

  - CVE-2023-5473: Use after free in Cast");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Backports SLE-15-SP4, openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~118.0.5993.70~bp155.2.46.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~118.0.5993.70~bp155.2.46.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~118.0.5993.70~bp155.2.46.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~118.0.5993.70~bp155.2.46.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~118.0.5993.70~bp155.2.46.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~118.0.5993.70~bp155.2.46.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~118.0.5993.70~bp155.2.46.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~118.0.5993.70~bp155.2.46.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~118.0.5993.70~bp154.2.132.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~118.0.5993.70~bp154.2.132.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~118.0.5993.70~bp154.2.132.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~118.0.5993.70~bp154.2.132.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
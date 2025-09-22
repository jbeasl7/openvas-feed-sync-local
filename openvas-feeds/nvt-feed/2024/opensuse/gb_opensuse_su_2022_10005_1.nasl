# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833455");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-1853", "CVE-2022-1854", "CVE-2022-1855", "CVE-2022-1856", "CVE-2022-1857", "CVE-2022-1858", "CVE-2022-1859", "CVE-2022-1860", "CVE-2022-1861", "CVE-2022-1862", "CVE-2022-1863", "CVE-2022-1864", "CVE-2022-1865", "CVE-2022-1866", "CVE-2022-1867", "CVE-2022-1868", "CVE-2022-1869", "CVE-2022-1870", "CVE-2022-1871", "CVE-2022-1872", "CVE-2022-1873", "CVE-2022-1874", "CVE-2022-1875", "CVE-2022-1876");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-03 12:36:39 +0000 (Wed, 03 Aug 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:51:12 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2022:10005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10005-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JSMLLTNKJ3TPX4NE3EBN2DITMAJNWNB6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2022:10005-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:
  Chromium 102.0.5001.61 (boo#1199893)

  * CVE-2022-1853: Use after free in Indexed DB

  * CVE-2022-1854: Use after free in ANGLE

  * CVE-2022-1855: Use after free in Messaging

  * CVE-2022-1856: Use after free in User Education

  * CVE-2022-1857: Insufficient policy enforcement in File System API

  * CVE-2022-1858: Out of bounds read in DevTools

  * CVE-2022-1859: Use after free in Performance Manager

  * CVE-2022-1860: Use after free in UI Foundations

  * CVE-2022-1861: Use after free in Sharing

  * CVE-2022-1862: Inappropriate implementation in Extensions

  * CVE-2022-1863: Use after free in Tab Groups

  * CVE-2022-1864: Use after free in WebApp Installs

  * CVE-2022-1865: Use after free in Bookmarks

  * CVE-2022-1866: Use after free in Tablet Mode

  * CVE-2022-1867: Insufficient validation of untrusted input in Data
       Transfer

  * CVE-2022-1868: Inappropriate implementation in Extensions API

  * CVE-2022-1869: Type Confusion in V8

  * CVE-2022-1870: Use after free in App Service

  * CVE-2022-1871: Insufficient policy enforcement in File System API

  * CVE-2022-1872: Insufficient policy enforcement in Extensions API

  * CVE-2022-1873: Insufficient policy enforcement in COOP

  * CVE-2022-1874: Insufficient policy enforcement in Safe Browsing

  * CVE-2022-1875: Inappropriate implementation in PDF

  * CVE-2022-1876: Heap buffer overflow in DevTools

  - Chromium 101.0.4951.67

  * fixes for other platforms");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~102.0.5005.61~bp154.2.5.3", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~102.0.5005.61~bp154.2.5.3", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~102.0.5005.61~bp154.2.5.3", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~102.0.5005.61~bp154.2.5.3", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~102.0.5005.61~bp154.2.5.3", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~102.0.5005.61~bp154.2.5.3", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~102.0.5005.61~bp154.2.5.3", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~102.0.5005.61~bp154.2.5.3", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
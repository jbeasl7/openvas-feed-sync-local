# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887354");
  script_cve_id("CVE-2024-6988", "CVE-2024-6989", "CVE-2024-6990", "CVE-2024-6991", "CVE-2024-6992", "CVE-2024-6993", "CVE-2024-6994", "CVE-2024-6995", "CVE-2024-6996", "CVE-2024-6997", "CVE-2024-6998", "CVE-2024-6999", "CVE-2024-7000", "CVE-2024-7001", "CVE-2024-7003", "CVE-2024-7004", "CVE-2024-7005", "CVE-2024-7255", "CVE-2024-7256");
  script_tag(name:"creation_date", value:"2024-08-06 07:34:47 +0000 (Tue, 06 Aug 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-02 17:41:48 +0000 (Thu, 02 Jan 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-3a1a0a664e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-3a1a0a664e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-3a1a0a664e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299576");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299689");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300183");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301846");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-3a1a0a664e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to 127.0.6533.88

* Critical CVE-2024-6990: Uninitialized Use in Dawn
* High CVE-2024-7255: Out of bounds read in WebTransport
* High CVE-2024-7256: Insufficient data validation in Dawn

----

 update to 127.0.6533.72

 * CVE-2024-6988: Use after free in Downloads
 * CVE-2024-6989: Use after free in Loader
 * CVE-2024-6991: Use after free in Dawn
 * CVE-2024-6992: Out of bounds memory access in ANGLE
 * CVE-2024-6993: Inappropriate implementation in Canvas
 * CVE-2024-6994: Heap buffer overflow in Layout
 * CVE-2024-6995: Inappropriate implementation in Fullscreen
 * CVE-2024-6996: Race in Frames
 * CVE-2024-6997: Use after free in Tabs
 * CVE-2024-6998: Use after free in User Education
 * CVE-2024-6999: Inappropriate implementation in FedCM
 * CVE-2024-7000: Use after free in CSS. Reported by Anonymous
 * CVE-2024-7001: Inappropriate implementation in HTML
 * CVE-2024-7003: Inappropriate implementation in FedCM
 * CVE-2024-7004: Insufficient validation of untrusted input in Safe Browsing
 * CVE-2024-7005: Insufficient validation of untrusted input in Safe");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~127.0.6533.88~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~127.0.6533.88~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~127.0.6533.88~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~127.0.6533.88~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~127.0.6533.88~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~127.0.6533.88~2.fc40", rls:"FC40"))) {
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

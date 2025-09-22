# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10092199969743");
  script_cve_id("CVE-2025-0291", "CVE-2025-0434", "CVE-2025-0435", "CVE-2025-0436", "CVE-2025-0437", "CVE-2025-0438", "CVE-2025-0439", "CVE-2025-0440", "CVE-2025-0441", "CVE-2025-0442", "CVE-2025-0443", "CVE-2025-0446", "CVE-2025-0447", "CVE-2025-0448");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-16 20:35:01 +0000 (Thu, 16 Jan 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-d9219c6a43)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-d9219c6a43");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-d9219c6a43");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336836");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2336837");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2338180");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2338181");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2338200");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2338218");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2338230");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2338231");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2025-d9219c6a43 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 132.0.6834.83

 * High CVE-2025-0434: Out of bounds memory access in V8
 * High CVE-2025-0435: Inappropriate implementation in Navigation
 * High CVE-2025-0436: Integer overflow in Skia
 * High CVE-2025-0437: Out of bounds read in Metrics
 * High CVE-2025-0438: Stack buffer overflow in Tracing
 * Medium CVE-2025-0439: Race in Frames
 * Medium CVE-2025-0440: Inappropriate implementation in Fullscreen
 * Medium CVE-2025-0441: Inappropriate implementation in Fenced
 * Medium CVE-2025-0442: Inappropriate implementation in Payments
 * Medium CVE-2025-0443: Insufficient data validation in Extensions
 * Low CVE-2025-0446: Inappropriate implementation in Extensions
 * Low CVE-2025-0447: Inappropriate implementation in Navigation
 * Low CVE-2025-0448: Inappropriate implementation in Compositing");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~132.0.6834.83~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~132.0.6834.83~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~132.0.6834.83~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~132.0.6834.83~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~132.0.6834.83~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~132.0.6834.83~1.fc41", rls:"FC41"))) {
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

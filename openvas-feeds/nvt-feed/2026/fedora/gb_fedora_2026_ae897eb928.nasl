# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9710189710198928");
  script_cve_id("CVE-2026-4439", "CVE-2026-4440", "CVE-2026-4441", "CVE-2026-4442", "CVE-2026-4443", "CVE-2026-4444", "CVE-2026-4445", "CVE-2026-4446", "CVE-2026-4447", "CVE-2026-4448", "CVE-2026-4449", "CVE-2026-4450", "CVE-2026-4451", "CVE-2026-4452", "CVE-2026-4453", "CVE-2026-4454", "CVE-2026-4455", "CVE-2026-4456", "CVE-2026-4457", "CVE-2026-4458", "CVE-2026-4459", "CVE-2026-4460", "CVE-2026-4461", "CVE-2026-4462", "CVE-2026-4463", "CVE-2026-4464");
  script_tag(name:"creation_date", value:"2026-03-25 04:43:07 +0000 (Wed, 25 Mar 2026)");
  script_version("2026-03-25T05:58:02+0000");
  script_tag(name:"last_modification", value:"2026-03-25 05:58:02 +0000 (Wed, 25 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-20 15:16:18 +0000 (Fri, 20 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-ae897eb928)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-ae897eb928");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-ae897eb928");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2026-ae897eb928 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 146.0.7680.153

 * CVE-2026-4439: Out of bounds memory access in WebGL
 * CVE-2026-4440: Out of bounds read and write in WebGL
 * CVE-2026-4441: Use after free in Base
 * CVE-2026-4442: Heap buffer overflow in CSS
 * CVE-2026-4443: Heap buffer overflow in WebAudio
 * CVE-2026-4444: Stack buffer overflow in WebRTC
 * CVE-2026-4445: Use after free in WebRTC
 * CVE-2026-4446: Use after free in WebRTC
 * CVE-2026-4447: Inappropriate implementation in V8
 * CVE-2026-4448: Heap buffer overflow in ANGLE
 * CVE-2026-4449: Use after free in Blink
 * CVE-2026-4450: Out of bounds write in V8
 * CVE-2026-4451: Insufficient validation of untrusted input in Navigation
 * CVE-2026-4452: Integer overflow in ANGLE
 * CVE-2026-4453: Integer overflow in Dawn
 * CVE-2026-4454: Use after free in Network
 * CVE-2026-4455: Heap buffer overflow in PDFium
 * CVE-2026-4456: Use after free in Digital Credentials API
 * CVE-2026-4457: Type Confusion in V8
 * CVE-2026-4458: Use after free in Extensions
 * CVE-2026-4459: Out of bounds read and write in WebAudio
 * CVE-2026-4460: Out of bounds read in Skia
 * CVE-2026-4461: Inappropriate implementation in V8
 * CVE-2026-4462: Out of bounds read in Blink
 * CVE-2026-4463: Heap buffer overflow in WebRTC
 * CVE-2026-4464: Integer overflow in ANGLE");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~146.0.7680.153~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~146.0.7680.153~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~146.0.7680.153~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common-debuginfo", rpm:"chromium-common-debuginfo~146.0.7680.153~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~146.0.7680.153~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~146.0.7680.153~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless-debuginfo", rpm:"chromium-headless-debuginfo~146.0.7680.153~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~146.0.7680.153~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui-debuginfo", rpm:"chromium-qt5-ui-debuginfo~146.0.7680.153~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~146.0.7680.153~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui-debuginfo", rpm:"chromium-qt6-ui-debuginfo~146.0.7680.153~1.fc43", rls:"FC43"))) {
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

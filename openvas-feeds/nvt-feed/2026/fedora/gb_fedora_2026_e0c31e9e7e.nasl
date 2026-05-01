# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.1010993110191017101");
  script_cve_id("CVE-2026-5272", "CVE-2026-5273", "CVE-2026-5274", "CVE-2026-5275", "CVE-2026-5276", "CVE-2026-5277", "CVE-2026-5278", "CVE-2026-5279", "CVE-2026-5280", "CVE-2026-5281", "CVE-2026-5282", "CVE-2026-5283", "CVE-2026-5284", "CVE-2026-5285", "CVE-2026-5286", "CVE-2026-5287", "CVE-2026-5288", "CVE-2026-5289", "CVE-2026-5290", "CVE-2026-5291", "CVE-2026-5292");
  script_tag(name:"creation_date", value:"2026-04-16 05:05:42 +0000 (Thu, 16 Apr 2026)");
  script_version("2026-04-16T06:18:46+0000");
  script_tag(name:"last_modification", value:"2026-04-16 06:18:46 +0000 (Thu, 16 Apr 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-04-01 15:23:25 +0000 (Wed, 01 Apr 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-e0c31e9e7e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-e0c31e9e7e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-e0c31e9e7e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2454750");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cef' package(s) announced via the FEDORA-2026-e0c31e9e7e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 146.0.7680.177 + cef-146.0.11+g8e1262b

* High CVE-2026-5273: Use after free in CSS
* High CVE-2026-5272: Heap buffer overflow in GPU
* High CVE-2026-5274: Integer overflow in Codecs
* High CVE-2026-5275: Heap buffer overflow in ANGLE
* High CVE-2026-5276: Insufficient policy enforcement in WebUSB
* High CVE-2026-5277: Integer overflow in ANGLE
* High CVE-2026-5278: Use after free in Web MIDI
* High CVE-2026-5279: Object corruption in V8
* High CVE-2026-5280: Use after free in WebCodecs
* High CVE-2026-5281: Use after free in Dawn
* High CVE-2026-5282: Out of bounds read in WebCodecs
* High CVE-2026-5283: Inappropriate implementation in ANGLE
* High CVE-2026-5284: Use after free in Dawn
* High CVE-2026-5285: Use after free in WebGL
* High CVE-2026-5286: Use after free in Dawn
* High CVE-2026-5287: Use after free in PDF
* High CVE-2026-5288: Use after free in WebView
* High CVE-2026-5289: Use after free in Navigation
* High CVE-2026-5290: Use after free in Compositing
* Medium CVE-2026-5291: Inappropriate implementation in WebGL
* Medium CVE-2026-5292: Out of bounds read in WebCodecs");

  script_tag(name:"affected", value:"'cef' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"cef", rpm:"cef~146.0.11^chromium146.0.7680.177~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-debuginfo", rpm:"cef-debuginfo~146.0.11^chromium146.0.7680.177~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-devel", rpm:"cef-devel~146.0.11^chromium146.0.7680.177~2.fc42", rls:"FC42"))) {
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

# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9510210210299101421");
  script_cve_id("CVE-2026-2648", "CVE-2026-2649", "CVE-2026-2650", "CVE-2026-3061", "CVE-2026-3062", "CVE-2026-3063", "CVE-2026-3536", "CVE-2026-3537", "CVE-2026-3538", "CVE-2026-3539", "CVE-2026-3540", "CVE-2026-3541", "CVE-2026-3542", "CVE-2026-3543", "CVE-2026-3544", "CVE-2026-3545");
  script_tag(name:"creation_date", value:"2026-03-09 04:44:32 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-25 14:41:53 +0000 (Wed, 25 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-95fffce421)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-95fffce421");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-95fffce421");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2437035");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cef' package(s) announced via the FEDORA-2026-95fffce421 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bump to cef-145.0.28+g51162e8 + chromium 145.0.7632.159 (rhbz#2437035)

* CVE-2026-3536: Integer overflow in ANGLE
* CVE-2026-3537: Object lifecycle issue in PowerVR
* CVE-2026-3538: Integer overflow in Skia
* CVE-2026-3539: Object lifecycle issue in DevTools
* CVE-2026-3540: Inappropriate implementation in WebAudio
* CVE-2026-3541: Inappropriate implementation in CSS
* CVE-2026-3542: Inappropriate implementation in WebAssembly
* CVE-2026-3543: Inappropriate implementation in V8
* CVE-2026-3544: Heap buffer overflow in WebCodecs
* CVE-2026-3545: Insufficient data validation in Navigation
* CVE-2026-3061: Out of bounds read in Media
* CVE-2026-3062: Out of bounds read and write in Tint
* CVE-2026-3063: Inappropriate implementation in DevTools
* CVE-2026-2648: Heap buffer overflow in PDFium
* CVE-2026-2649: Integer overflow in V8
* CVE-2026-2650: Heap buffer overflow in Media");

  script_tag(name:"affected", value:"'cef' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"cef", rpm:"cef~145.0.28^chromium145.0.7632.159~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-debuginfo", rpm:"cef-debuginfo~145.0.28^chromium145.0.7632.159~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-devel", rpm:"cef-devel~145.0.28^chromium145.0.7632.159~1.fc42", rls:"FC42"))) {
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

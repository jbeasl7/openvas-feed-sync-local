# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.5821002977648");
  script_cve_id("CVE-2024-11110", "CVE-2024-11111", "CVE-2024-11112", "CVE-2024-11113", "CVE-2024-11114", "CVE-2024-11115", "CVE-2024-11116", "CVE-2024-11117", "CVE-2024-11395");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-02 18:00:46 +0000 (Thu, 02 Jan 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-582d2a7648)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-582d2a7648");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-582d2a7648");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325761");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325762");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325763");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325764");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325765");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325766");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325767");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325768");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325769");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325770");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327554");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327555");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-582d2a7648 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 131.0.6778.85

 * High CVE-2024-11395: Type Confusion in V8
 * High CVE-2024-11110: Inappropriate implementation in Blink
 * Medium CVE-2024-11111: Inappropriate implementation in Autofill
 * Medium CVE-2024-11112: Use after free in Media
 * Medium CVE-2024-11113: Use after free in Accessibility
 * Medium CVE-2024-11114: Inappropriate implementation in Views
 * Medium CVE-2024-11115: Insufficient policy enforcement in Navigation
 * Medium CVE-2024-11116: Inappropriate implementation in Paint
 * Low CVE-2024-11117: Inappropriate implementation in FileSystem");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~131.0.6778.85~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~131.0.6778.85~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~131.0.6778.85~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~131.0.6778.85~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~131.0.6778.85~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~131.0.6778.85~2.fc41", rls:"FC41"))) {
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

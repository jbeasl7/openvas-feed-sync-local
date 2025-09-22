# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.480810099101926");
  script_cve_id("CVE-2024-12692", "CVE-2024-12693", "CVE-2024-12694", "CVE-2024-12695");
  script_tag(name:"creation_date", value:"2024-12-23 04:08:39 +0000 (Mon, 23 Dec 2024)");
  script_version("2025-02-12T05:37:43+0000");
  script_tag(name:"last_modification", value:"2025-02-12 05:37:43 +0000 (Wed, 12 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-11 15:15:14 +0000 (Tue, 11 Feb 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-4808dce926)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-4808dce926");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-4808dce926");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333152");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333153");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333154");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333155");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333156");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333157");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333159");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333160");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-4808dce926 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 131.0.6778.204

 * High CVE-2024-12692: Type Confusion in V8
 * High CVE-2024-12693: Out of bounds memory access in V8
 * High CVE-2024-12694: Use after free in Compositing
 * High CVE-2024-12695: Out of bounds write in V8");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~131.0.6778.204~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~131.0.6778.204~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~131.0.6778.204~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~131.0.6778.204~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~131.0.6778.204~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~131.0.6778.204~1.fc40", rls:"FC40"))) {
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

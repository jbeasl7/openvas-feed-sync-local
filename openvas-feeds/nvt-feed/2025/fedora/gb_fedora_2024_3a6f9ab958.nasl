# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.397610299798958");
  script_cve_id("CVE-2024-9954", "CVE-2024-9955", "CVE-2024-9956", "CVE-2024-9957", "CVE-2024-9958", "CVE-2024-9959", "CVE-2024-9960", "CVE-2024-9961", "CVE-2024-9962", "CVE-2024-9963", "CVE-2024-9964", "CVE-2024-9965", "CVE-2024-9966");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-17 20:06:01 +0000 (Thu, 17 Oct 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-3a6f9ab958)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-3a6f9ab958");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-3a6f9ab958");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318990");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318991");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318992");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318993");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318996");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318998");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318999");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319000");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319001");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319002");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319003");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319004");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319005");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319006");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-3a6f9ab958 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 130.0.6723.58

 * High CVE-2024-9954: Use after free in AI
 * Medium CVE-2024-9955: Use after free in Web Authentication
 * Medium CVE-2024-9956: Inappropriate implementation in Web Authentication
 * Medium CVE-2024-9957: Use after free in UI
 * Medium CVE-2024-9958: Inappropriate implementation in PictureInPicture
 * Medium CVE-2024-9959: Use after free in DevTools
 * Medium CVE-2024-9960: Use after free in Dawn
 * Medium CVE-2024-9961: Use after free in Parcel Tracking
 * Medium CVE-2024-9962: Inappropriate implementation in Permissions
 * Medium CVE-2024-9963: Insufficient data validation in Downloads
 * Low CVE-2024-9964: Inappropriate implementation in Payments
 * Low CVE-2024-9965: Insufficient data validation in DevTools
 * Low CVE-2024-9966: Inappropriate implementation in Navigations");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~130.0.6723.58~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~130.0.6723.58~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~130.0.6723.58~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~130.0.6723.58~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~130.0.6723.58~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~130.0.6723.58~1.fc41", rls:"FC41"))) {
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

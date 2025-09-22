# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886305");
  script_cve_id("CVE-2024-2400", "CVE-2024-2625", "CVE-2024-2626", "CVE-2024-2627", "CVE-2024-2628", "CVE-2024-2629", "CVE-2024-2630", "CVE-2024-2631");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:43 +0000 (Mon, 25 Mar 2024)");
  script_version("2024-09-13T15:40:36+0000");
  script_tag(name:"last_modification", value:"2024-09-13 15:40:36 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-01 15:22:56 +0000 (Mon, 01 Apr 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-f9eb1130c8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-f9eb1130c8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-f9eb1130c8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270389");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270393");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-f9eb1130c8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 123.0.6312.58

 * High CVE-2024-2625: Object lifecycle issue in V8
 * Medium CVE-2024-2626: Out of bounds read in Swiftshader
 * Medium CVE-2024-2627: Use after free in Canvas
 * Medium CVE-2024-2628: Inappropriate implementation in Downloads
 * Medium CVE-2024-2629: Incorrect security UI in iOS
 * Medium CVE-2024-2630: Inappropriate implementation in iOS
 * Low CVE-2024-2631: Inappropriate implementation in iOS");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~123.0.6312.58~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~123.0.6312.58~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~123.0.6312.58~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~123.0.6312.58~1.fc40", rls:"FC40"))) {
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

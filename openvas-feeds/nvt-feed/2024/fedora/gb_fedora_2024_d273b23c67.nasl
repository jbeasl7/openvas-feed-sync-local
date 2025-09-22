# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.10027398239967");
  script_cve_id("CVE-2024-8904", "CVE-2024-8905", "CVE-2024-8906", "CVE-2024-8907", "CVE-2024-8908", "CVE-2024-8909");
  script_tag(name:"creation_date", value:"2024-09-20 04:08:36 +0000 (Fri, 20 Sep 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-02 17:33:01 +0000 (Thu, 02 Jan 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-d273b23c67)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-d273b23c67");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-d273b23c67");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312963");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312964");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312965");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312966");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312967");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312968");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312971");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312972");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312973");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312974");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312975");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312976");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-d273b23c67 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to 129.0.6668.58

 * High CVE-2024-8904: Type Confusion in V8
 * Medium CVE-2024-8905: Inappropriate implementation in V8
 * Medium CVE-2024-8906: Incorrect security UI in Downloads
 * Medium CVE-2024-8907: Insufficient data validation in Omnibox
 * Low CVE-2024-8908: Inappropriate implementation in Autofill
 * Low CVE-2024-8909: Inappropriate implementation in UI");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~129.0.6668.58~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~129.0.6668.58~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~129.0.6668.58~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~129.0.6668.58~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~129.0.6668.58~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~129.0.6668.58~1.fc40", rls:"FC40"))) {
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

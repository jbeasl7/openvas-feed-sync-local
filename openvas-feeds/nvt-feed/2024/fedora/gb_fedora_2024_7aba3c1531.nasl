# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.79798973991531");
  script_cve_id("CVE-2018-20072", "CVE-2021-38023", "CVE-2024-7025", "CVE-2024-9120", "CVE-2024-9121", "CVE-2024-9122", "CVE-2024-9123", "CVE-2024-9369", "CVE-2024-9370");
  script_tag(name:"creation_date", value:"2024-10-07 04:08:22 +0000 (Mon, 07 Oct 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-02 17:55:20 +0000 (Thu, 02 Jan 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-7aba3c1531)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7aba3c1531");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-7aba3c1531");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314382");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314384");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314582");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314584");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314589");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314590");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-7aba3c1531 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to 129.0.6668.89

 * High CVE-2024-7025: Integer overflow in Layout
 * High CVE-2024-9369: Insufficient data validation in Mojo
 * High CVE-2024-9370: Inappropriate implementation in V8");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~129.0.6668.89~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~129.0.6668.89~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~129.0.6668.89~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~129.0.6668.89~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~129.0.6668.89~1.fc39", rls:"FC39"))) {
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

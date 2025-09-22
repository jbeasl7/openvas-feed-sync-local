# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885772");
  script_cve_id("CVE-2024-0232", "CVE-2024-1669", "CVE-2024-1670", "CVE-2024-1671", "CVE-2024-1672", "CVE-2024-1673", "CVE-2024-1674", "CVE-2024-1675", "CVE-2024-1676");
  script_tag(name:"creation_date", value:"2024-02-23 02:04:47 +0000 (Fri, 23 Feb 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-02 19:54:08 +0000 (Mon, 02 Dec 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-4adf990562)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-4adf990562");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-4adf990562");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257887");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265255");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-4adf990562 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to 122.0.6261.57

 * High CVE-2024-1669: Out of bounds memory access in Blink
 * High CVE-2024-1670: Use after free in Mojo
 * Medium CVE-2024-1671: Inappropriate implementation in Site Isolation
 * Medium CVE-2024-1672: Inappropriate implementation in Content Security Policy
 * Medium CVE-2024-1673: Use after free in Accessibility
 * Medium CVE-2024-1674: Inappropriate implementation in Navigation
 * Medium CVE-2024-1675: Insufficient policy enforcement in Download
 * Low CVE-2024-1676: Inappropriate implementation in Navigation");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~122.0.6261.57~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~122.0.6261.57~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~122.0.6261.57~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~122.0.6261.57~1.fc39", rls:"FC39"))) {
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

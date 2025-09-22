# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0054");
  script_cve_id("CVE-2023-46137", "CVE-2024-41671", "CVE-2024-41810");
  script_tag(name:"creation_date", value:"2025-02-13 04:08:38 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-02-13T05:37:41+0000");
  script_tag(name:"last_modification", value:"2025-02-13 05:37:41 +0000 (Thu, 13 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-11 16:17:45 +0000 (Wed, 11 Sep 2024)");

  script_name("Mageia: Security Advisory (MGASA-2025-0054)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0054");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0054.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33807");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6575-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6988-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6988-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-twisted' package(s) announced via the MGASA-2025-0054 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Twisted.web has disordered HTTP pipeline response. (CVE-2023-46137)
Twisted.web has disordered HTTP pipeline response. (CVE-2024-41671)
HTML injection in HTTP redirect body. (CVE-2024-41810)");

  script_tag(name:"affected", value:"'python-twisted' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"python-twisted", rpm:"python-twisted~22.10.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-twisted+tls", rpm:"python3-twisted+tls~22.10.0~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-twisted", rpm:"python3-twisted~22.10.0~2.1.mga9", rls:"MAGEIA9"))) {
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

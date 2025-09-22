# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0023");
  script_cve_id("CVE-2023-30536", "CVE-2024-2961");
  script_tag(name:"creation_date", value:"2025-01-27 04:11:43 +0000 (Mon, 27 Jan 2025)");
  script_version("2025-01-27T05:37:51+0000");
  script_tag(name:"last_modification", value:"2025-01-27 05:37:51 +0000 (Mon, 27 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-01 16:38:35 +0000 (Mon, 01 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2025-0023)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0023");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0023.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33948");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2025/1/21/phpMyAdmin-522-is-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the MGASA-2025-0023 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"fix possible security issue with library code slim/psr7 (CVE-2023-30536)
fix possible security issue relating to iconv (CVE-2024-2961,
PMASA-2025-3)
fix an XSS vulnerability in the check tables feature (PMASA-2025-1)
fix an XSS vulnerability in the Insert tab (PMASA-2025-2)");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~5.2.2~1.mga9", rls:"MAGEIA9"))) {
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

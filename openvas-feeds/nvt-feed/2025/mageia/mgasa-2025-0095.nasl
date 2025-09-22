# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0095");
  script_cve_id("CVE-2025-26699");
  script_tag(name:"creation_date", value:"2025-03-13 04:07:46 +0000 (Thu, 13 Mar 2025)");
  script_version("2025-03-13T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-03-13 05:38:41 +0000 (Thu, 13 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0095)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0095");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0095.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34073");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7335-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the MGASA-2025-0095 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Django 5.1 before 5.1.7, 5.0 before 5.0.13,
and 4.2 before 4.2.20. The django.utils.text.wrap() method and wordwrap
template filter are subject to a potential denial-of-service attack when
used with very long strings. (CVE-2025-26699)");

  script_tag(name:"affected", value:"'python-django' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~4.1.13~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~4.1.13~1.3.mga9", rls:"MAGEIA9"))) {
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

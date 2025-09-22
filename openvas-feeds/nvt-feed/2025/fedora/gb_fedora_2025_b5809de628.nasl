# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.985809100101628");
  script_tag(name:"creation_date", value:"2025-04-16 06:49:11 +0000 (Wed, 16 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-b5809de628)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b5809de628");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b5809de628");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-tcpdf' package(s) announced via the FEDORA-2025-b5809de628 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## Version 6.9.1 (2025-04-03)

- Fixed Path Traversal security vulnerability reported by Positive Technologies.

----

## Version 6.9.0 (2025-03-30)

- Added PHP 8.4 testing.
- Removed tcpdf_import.php and tcpdf_parser.php files (for a parser check the tc-lib-pdf-parser project instead).
- Fix composer.json.");

  script_tag(name:"affected", value:"'php-tcpdf' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf", rpm:"php-tcpdf~6.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-lgc-sans-fonts", rpm:"php-tcpdf-dejavu-lgc-sans-fonts~6.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-lgc-sans-mono-fonts", rpm:"php-tcpdf-dejavu-lgc-sans-mono-fonts~6.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-lgc-serif-fonts", rpm:"php-tcpdf-dejavu-lgc-serif-fonts~6.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-sans-fonts", rpm:"php-tcpdf-dejavu-sans-fonts~6.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-sans-mono-fonts", rpm:"php-tcpdf-dejavu-sans-mono-fonts~6.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-serif-fonts", rpm:"php-tcpdf-dejavu-serif-fonts~6.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-mono-fonts", rpm:"php-tcpdf-gnu-free-mono-fonts~6.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-sans-fonts", rpm:"php-tcpdf-gnu-free-sans-fonts~6.9.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-serif-fonts", rpm:"php-tcpdf-gnu-free-serif-fonts~6.9.1~1.fc40", rls:"FC40"))) {
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

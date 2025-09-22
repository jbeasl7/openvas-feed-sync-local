# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0361");
  script_cve_id("CVE-2024-22641");
  script_tag(name:"creation_date", value:"2024-11-13 04:12:29 +0000 (Wed, 13 Nov 2024)");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0361)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0361");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0361.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33731");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WGK7LQSJONZPU3VOQTQ36UN6OAD6ZM4H/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-tcpdf' package(s) announced via the MGASA-2024-0361 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"TCPDF version 6.6.5 and before is vulnerable to ReDoS (Regular
Expression Denial of Service) if parsing an untrusted SVG file.
(CVE-2024-22641)");

  script_tag(name:"affected", value:"'php-tcpdf' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf", rpm:"php-tcpdf~6.5.0~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu", rpm:"php-tcpdf-dejavu~6.5.0~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-lgc", rpm:"php-tcpdf-dejavu-lgc~6.5.0~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-mono-fonts", rpm:"php-tcpdf-gnu-free-mono-fonts~6.5.0~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-sans-fonts", rpm:"php-tcpdf-gnu-free-sans-fonts~6.5.0~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-serif-fonts", rpm:"php-tcpdf-gnu-free-serif-fonts~6.5.0~1.2.mga9", rls:"MAGEIA9"))) {
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

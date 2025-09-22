# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0378");
  script_cve_id("CVE-2021-31811", "CVE-2021-31812");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-23 20:13:50 +0000 (Wed, 23 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0378)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0378");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0378.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29125");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/MDJKJQOMVFDFIDS27OQJXNOYHV2O273D/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdfbox' package(s) announced via the MGASA-2021-0378 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Apache PDFBox, a carefully crafted PDF file can trigger an
OutOfMemory-Exception while loading the file. This issue affects Apache PDFBox
version 2.0.23 and prior 2.0.x versions (CVE-2021-31811).

In Apache PDFBox, a carefully crafted PDF file can trigger an infinite loop
while loading the file. This issue affects Apache PDFBox version 2.0.23 and
prior 2.0.x versions (CVE-2021-31812).");

  script_tag(name:"affected", value:"'pdfbox' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"fontbox", rpm:"fontbox~2.0.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdfbox", rpm:"pdfbox~2.0.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdfbox-debugger", rpm:"pdfbox-debugger~2.0.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdfbox-javadoc", rpm:"pdfbox-javadoc~2.0.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdfbox-parent", rpm:"pdfbox-parent~2.0.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdfbox-reactor", rpm:"pdfbox-reactor~2.0.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdfbox-tools", rpm:"pdfbox-tools~2.0.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"preflight", rpm:"preflight~2.0.24~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xmpbox", rpm:"xmpbox~2.0.24~1.mga8", rls:"MAGEIA8"))) {
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

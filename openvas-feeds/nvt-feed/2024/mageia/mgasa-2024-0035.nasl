# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0035");
  script_cve_id("CVE-2022-30524", "CVE-2022-30775", "CVE-2022-33108", "CVE-2022-36561", "CVE-2022-38222", "CVE-2022-38334", "CVE-2022-38928", "CVE-2022-41842", "CVE-2022-41843", "CVE-2022-41844", "CVE-2022-43071", "CVE-2022-43295", "CVE-2022-45586", "CVE-2022-45587", "CVE-2023-2662", "CVE-2023-2663", "CVE-2023-2664", "CVE-2023-3044", "CVE-2023-3436");
  script_tag(name:"creation_date", value:"2024-02-12 04:12:31 +0000 (Mon, 12 Feb 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-22 15:31:42 +0000 (Thu, 22 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2024-0035)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0035");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0035.html");
  script_xref(name:"URL", value:"http://www.xpdfreader.com/security-fixes.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30812");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xpdf' package(s) announced via the MGASA-2024-0035 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
Logic bug in text extractor led to invalid memory access.
(CVE-2022-30524)
Integer overflow in rasterizer. (CVE-2022-30775)
PDF object loop in Catalog::countPageTree. (CVE-2022-33108)
PDF object loop in AcroForm::scanField. (CVE-2022-36561)
Logic bug in JBIG2 decoder. (CVE-2022-38222)
PDF object loop in Catalog::countPageTree. (CVE-2022-38334)
Missing bounds check in CFF font converter caused null pointer
dereference. (CVE-2022-38928)
PDF object loop in Catalog::countPageTree. (CVE-2022-41842)
Missing bounds check in CFF font parser caused invalid memory access.
(CVE-2022-41843)
PDF object loop in AcroForm::scanField. (CVE-2022-41844)
PDF object loop in Catalog::readPageLabelTree2. (CVE-2022-43071)
PDF object loop in Catalog::countPageTree. (CVE-2022-43295)
PDF object loop in Catalog::countPageTree. (CVE-2022-45586)
PDF object loop in Catalog::countPageTree. (CVE-2022-45587)
Divide-by-zero in Xpdf 4.04 due to bad color space object.
(CVE-2023-2662)
PDF object loop in Catalog::readPageLabelTree2. (CVE-2023-2663)
PDF object loop in Catalog::readEmbeddedFileTree. (CVE-2023-2664)
Divide-by-zero in Xpdf 4.04 due to very large page size. (CVE-2023-3044)
Deadlock in Xpdf 4.04 due to PDF object stream references.
(CVE-203-3436)");

  script_tag(name:"affected", value:"'xpdf' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~4.05~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xpdf-common", rpm:"xpdf-common~4.05~1.mga9", rls:"MAGEIA9"))) {
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

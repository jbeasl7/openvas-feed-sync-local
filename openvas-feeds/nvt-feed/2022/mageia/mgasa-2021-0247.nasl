# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0247");
  script_cve_id("CVE-2021-32490", "CVE-2021-32491", "CVE-2021-32492", "CVE-2021-32493", "CVE-2021-3500");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-28 20:37:15 +0000 (Mon, 28 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0247)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0247");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0247.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29000");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/AFBA3B7ZE5WL3W3IC3SJOZLTIMZPKXES/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4957-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2667");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'djvulibre' package(s) announced via the MGASA-2021-0247 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stack overflow in function DJVU::DjVuDocument::get_djvu_file() via crafted
djvu file. (CVE-2021-3500).

Out of bounds write in function DJVU::filter_bv()
via crafted djvu file. (CVE-2021-32490).

Integer overflow in function render() in tools/ddjvu via crafted djvu file.
(CVE-2021-32491)

Out of bounds read in function DJVU::DataPool::has_data() via crafted djvu
file. (CVE-2021-32492).

Heap buffer overflow in function DJVU::GBitmap::decode() via crafted djvu
file. (CVE-2021-32493).");

  script_tag(name:"affected", value:"'djvulibre' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"djvulibre", rpm:"djvulibre~3.5.27~5.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64djvulibre-devel", rpm:"lib64djvulibre-devel~3.5.27~5.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64djvulibre21", rpm:"lib64djvulibre21~3.5.27~5.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdjvulibre-devel", rpm:"libdjvulibre-devel~3.5.27~5.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdjvulibre21", rpm:"libdjvulibre21~3.5.27~5.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"djvulibre", rpm:"djvulibre~3.5.28~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64djvulibre-devel", rpm:"lib64djvulibre-devel~3.5.28~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64djvulibre21", rpm:"lib64djvulibre21~3.5.28~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdjvulibre-devel", rpm:"libdjvulibre-devel~3.5.28~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdjvulibre21", rpm:"libdjvulibre21~3.5.28~1.1.mga8", rls:"MAGEIA8"))) {
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

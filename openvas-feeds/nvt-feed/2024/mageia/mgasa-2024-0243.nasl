# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0243");
  script_cve_id("CVE-2023-49460", "CVE-2023-49462", "CVE-2023-49463", "CVE-2023-49464");
  script_tag(name:"creation_date", value:"2024-06-28 04:11:20 +0000 (Fri, 28 Jun 2024)");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-11 17:31:56 +0000 (Mon, 11 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0243)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0243");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0243.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33332");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6847-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libheif' package(s) announced via the MGASA-2024-0243 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libheif incorrectly handled certain image data.
An attacker could possibly use this issue to crash the program,
resulting in a denial of service. (CVE-2019-11471)
Reza Mirzazade Farkhani discovered that libheif incorrectly handled
certain image data. An attacker could possibly use this issue to crash
the program, resulting in a denial of service. (CVE-2020-23109)
Eugene Lim discovered that libheif incorrectly handled certain image
data.
An attacker could possibly use this issue to crash the program,
resulting in a denial of service. (CVE-2023-0996)
Min Jang discovered that libheif incorrectly handled certain image data.
An attacker could possibly use this issue to crash the program,
resulting in a denial of service. (CVE-2023-29659)
Yuchuan Meng discovered that libheif incorrectly handled certain image
data.
An attacker could possibly use this issue to crash the program,
resulting in a denial of service. (CVE-2023-49460, CVE-2023-49462,
CVE-2023-49463, CVE-2023-49464)");

  script_tag(name:"affected", value:"'libheif' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64heif-devel", rpm:"lib64heif-devel~1.16.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64heif-devel", rpm:"lib64heif-devel~1.16.2~1.1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64heif1", rpm:"lib64heif1~1.16.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64heif1", rpm:"lib64heif1~1.16.2~1.1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif", rpm:"libheif~1.16.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif", rpm:"libheif~1.16.2~1.1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-devel", rpm:"libheif-devel~1.16.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-devel", rpm:"libheif-devel~1.16.2~1.1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1", rpm:"libheif1~1.16.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1", rpm:"libheif1~1.16.2~1.1.mga9.tainted", rls:"MAGEIA9"))) {
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

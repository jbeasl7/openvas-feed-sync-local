# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0408");
  script_cve_id("CVE-2018-17961", "CVE-2018-18073", "CVE-2018-18284");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-19 22:29:01 +0000 (Fri, 19 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0408)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0408");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0408.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23659");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/10/09/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/10/10/12");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/10/11/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/10/16/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the MGASA-2018-0408 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ghostscript packages fix many bugs and security vulnerabilities:

Bypassing executeonly to escape -dSAFER sandbox. (CVE-2018-17961)

Saved execution stacks can leak operator arrays. (CVE-2018-18073)

1Policy operator gives access to .forceput. (CVE-2018-18284)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.25~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~9.25~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~9.25~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.25~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~9.25~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~9.25~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs-devel", rpm:"lib64gs-devel~9.25~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs9", rpm:"lib64gs9~9.25~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs-devel", rpm:"lib64ijs-devel~0.35~140.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~140.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~9.25~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs9", rpm:"libgs9~9.25~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs-devel", rpm:"libijs-devel~0.35~140.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~140.2.mga6", rls:"MAGEIA6"))) {
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

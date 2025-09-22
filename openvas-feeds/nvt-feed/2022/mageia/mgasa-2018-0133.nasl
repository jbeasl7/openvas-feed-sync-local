# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0133");
  script_cve_id("CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-14 18:39:35 +0000 (Wed, 14 Mar 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0133");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0133.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22610");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4115");
  script_xref(name:"URL", value:"https://www.quagga.net/security/Quagga-2018-1114.txt");
  script_xref(name:"URL", value:"https://www.quagga.net/security/Quagga-2018-1550.txt");
  script_xref(name:"URL", value:"https://www.quagga.net/security/Quagga-2018-1975.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga' package(s) announced via the MGASA-2018-0133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is an update to fix several security issues.
1. CVE-2018-5379: Fix double free of unknown attribute
2. CVE-2018-5380: debug print of received NOTIFY data can over-read msg array
3. CVE-2018-5381: fix infinite loop on certain invalid OPEN messages");

  script_tag(name:"affected", value:"'quagga' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64quagga-devel", rpm:"lib64quagga-devel~0.99.24.1~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quagga0", rpm:"lib64quagga0~0.99.24.1~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga-devel", rpm:"libquagga-devel~0.99.24.1~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga0", rpm:"libquagga0~0.99.24.1~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.24.1~6.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga-contrib", rpm:"quagga-contrib~0.99.24.1~6.1.mga6", rls:"MAGEIA6"))) {
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

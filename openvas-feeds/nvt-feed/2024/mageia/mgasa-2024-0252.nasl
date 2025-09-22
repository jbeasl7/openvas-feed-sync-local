# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0252");
  script_cve_id("CVE-2024-36600");
  script_tag(name:"creation_date", value:"2024-07-04 04:11:34 +0000 (Thu, 04 Jul 2024)");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0252)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0252");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0252.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33349");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6855-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcdio' package(s) announced via the MGASA-2024-0252 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer Overflow Vulnerability in libcdio v2.1.0 allows an attacker to
execute arbitrary code via a crafted ISO 9660 image file.
(CVE-2024-36600)");

  script_tag(name:"affected", value:"'libcdio' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64cdio++1", rpm:"lib64cdio++1~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cdio-devel", rpm:"lib64cdio-devel~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cdio19", rpm:"lib64cdio19~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64iso9660++0", rpm:"lib64iso9660++0~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64iso9660_11", rpm:"lib64iso9660_11~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64udf0", rpm:"lib64udf0~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio++1", rpm:"libcdio++1~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio", rpm:"libcdio~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio-apps", rpm:"libcdio-apps~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio-devel", rpm:"libcdio-devel~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdio19", rpm:"libcdio19~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiso9660++0", rpm:"libiso9660++0~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiso9660_11", rpm:"libiso9660_11~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudf0", rpm:"libudf0~2.1.0~4.1.mga9", rls:"MAGEIA9"))) {
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

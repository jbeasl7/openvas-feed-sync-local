# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0230");
  script_cve_id("CVE-2021-20307");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-09 13:11:46 +0000 (Fri, 09 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0230)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0230");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0230.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28997");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JE6YZSXNVD6WZ3AG3ENL2DIHQFF24LYX/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2624");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpano13' package(s) announced via the MGASA-2021-0230 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Format string vulnerability in panoFileOutputNamesCreate() in libpano13 2.9.20.rc2 and earlier can lead to read and write arbitrary memory values (CVE-2021-20307).");

  script_tag(name:"affected", value:"'libpano13' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64pano13-devel", rpm:"lib64pano13-devel~2.9.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pano13-devel", rpm:"lib64pano13-devel~2.9.20~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pano13_3", rpm:"lib64pano13_3~2.9.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pano13_3", rpm:"lib64pano13_3~2.9.20~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13", rpm:"libpano13~2.9.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13", rpm:"libpano13~2.9.20~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13-devel", rpm:"libpano13-devel~2.9.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13-devel", rpm:"libpano13-devel~2.9.20~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13-tools", rpm:"libpano13-tools~2.9.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13-tools", rpm:"libpano13-tools~2.9.20~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13_3", rpm:"libpano13_3~2.9.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13_3", rpm:"libpano13_3~2.9.20~1.mga7.tainted", rls:"MAGEIA7"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64pano13-devel", rpm:"lib64pano13-devel~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pano13-devel", rpm:"lib64pano13-devel~2.9.20~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pano13_3", rpm:"lib64pano13_3~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pano13_3", rpm:"lib64pano13_3~2.9.20~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13", rpm:"libpano13~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13", rpm:"libpano13~2.9.20~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13-devel", rpm:"libpano13-devel~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13-devel", rpm:"libpano13-devel~2.9.20~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13-tools", rpm:"libpano13-tools~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13-tools", rpm:"libpano13-tools~2.9.20~1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13_3", rpm:"libpano13_3~2.9.20~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpano13_3", rpm:"libpano13_3~2.9.20~1.mga8.tainted", rls:"MAGEIA8"))) {
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

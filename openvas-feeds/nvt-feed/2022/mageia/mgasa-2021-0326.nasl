# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0326");
  script_cve_id("CVE-2021-20296", "CVE-2021-23169", "CVE-2021-23215", "CVE-2021-26260", "CVE-2021-3474", "CVE-2021-3475", "CVE-2021-3476", "CVE-2021-3477", "CVE-2021-3478", "CVE-2021-3479", "CVE-2021-3598", "CVE-2021-3605");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 18:24:07 +0000 (Fri, 11 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0326)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0326");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0326.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29005");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4KYNJSMVA6YJY5NMKDZ5SAISKZG2KCKC/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4900-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4996-1");
  script_xref(name:"URL", value:"https://www.openexr.com/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the MGASA-2021-0326 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated openexr packages fix security vulnerabilities:

It was discovered that OpenEXR incorrectly handled certain malformed EXR
image files. If a user were tricked into opening a crafted EXR image file,
a remote attacker could cause a denial of service, or possibly execute
arbitrary code (CVE-2021-3474, CVE-2021-3475, CVE-2021-3476, CVE-2021-3477,
CVE-2021-3478, CVE-2021-3479, CVE-2021-3598, CVE-2021-3605, CVE-2021-20296,
CVE-2021-23169, CVE-2021-23215, CVE-2021-26260).");

  script_tag(name:"affected", value:"'openexr' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ilmimf2_3_24", rpm:"lib64ilmimf2_3_24~2.3.0~2.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openexr-devel", rpm:"lib64openexr-devel~2.3.0~2.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libilmimf2_3_24", rpm:"libilmimf2_3_24~2.3.0~2.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenexr-devel", rpm:"libopenexr-devel~2.3.0~2.4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~2.3.0~2.4.mga7", rls:"MAGEIA7"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64ilmbase-devel", rpm:"lib64ilmbase-devel~2.5.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ilmbase2_5_25", rpm:"lib64ilmbase2_5_25~2.5.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ilmimf2_5_25", rpm:"lib64ilmimf2_5_25~2.5.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openexr-devel", rpm:"lib64openexr-devel~2.5.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libilmbase-devel", rpm:"libilmbase-devel~2.5.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libilmbase2_5_25", rpm:"libilmbase2_5_25~2.5.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libilmimf2_5_25", rpm:"libilmimf2_5_25~2.5.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenexr-devel", rpm:"libopenexr-devel~2.5.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~2.5.7~1.mga8", rls:"MAGEIA8"))) {
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

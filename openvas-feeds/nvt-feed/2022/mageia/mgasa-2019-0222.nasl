# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0222");
  script_cve_id("CVE-2017-7607", "CVE-2017-7608", "CVE-2017-7609", "CVE-2017-7610", "CVE-2017-7611", "CVE-2017-7612", "CVE-2017-7613", "CVE-2018-16062", "CVE-2018-16402", "CVE-2018-16403", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7149", "CVE-2019-7150", "CVE-2019-7664", "CVE-2019-7665");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-29 13:29:10 +0000 (Mon, 29 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2019-0222)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0222");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0222.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23160");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/Z6QQTO2CLXUBNNOX4DEZ5XXWJYV3SYVN/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3670-1/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4012-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils' package(s) announced via the MGASA-2019-0222 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that elfutils incorrectly handled certain malformed
files. If a user or automated system were tricked into processing a
specially crafted file, elfutils could be made to crash or consume
resources, resulting in a denial of service (CVE-2017-7607, CVE-2017-7608,
CVE-2017-7609, CVE-2017-7610, CVE-2017-7611, CVE-2017-7612, CVE-2017-7613,
CVE-2018-16062, CVE-2018-16402, CVE-2018-16403, CVE-2018-18310,
CVE-2018-18520, CVE-2018-18521, CVE-2019-7149, CVE-2019-7150,
CVE-2019-7665).

In elfutils 0.175, a negative-sized memcpy is attempted in elf_cvt_note
in libelf/note_xlate.h because of an incorrect overflow check. Crafted elf
input causes a segmentation fault, leading to denial of service (program
crash) (CVE-2019-7664).");

  script_tag(name:"affected", value:"'elfutils' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.176~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64elfutils-devel", rpm:"lib64elfutils-devel~0.176~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64elfutils-static-devel", rpm:"lib64elfutils-static-devel~0.176~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64elfutils1", rpm:"lib64elfutils1~0.176~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelfutils-devel", rpm:"libelfutils-devel~0.176~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelfutils-static-devel", rpm:"libelfutils-static-devel~0.176~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelfutils1", rpm:"libelfutils1~0.176~1.mga6", rls:"MAGEIA6"))) {
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

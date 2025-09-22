# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131218");
  script_cve_id("CVE-2015-8803", "CVE-2015-8804", "CVE-2015-8805");
  script_tag(name:"creation_date", value:"2016-02-11 05:22:17 +0000 (Thu, 11 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-03 19:52:30 +0000 (Thu, 03 Mar 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0061)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0061");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0061.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/02/03/1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17669");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-February/176807.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nettle, nettle2.7' package(s) announced via the MGASA-2016-0061 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated nettle2.7 and nettle packages fix security vulnerabilities:

Two carry propagation bugs in elliptic curve scalar multiplications that
affect the NIST P-256 curve. The bugs are in the C code and affect multiple
architectures (CVE-2015-8803, CVE-2015-8805).

A carry propagation bug in elliptic curve scalar multiplications that
affect the NIST P-384 curve. The bug is in the assembly code and only affects
the x86_64 architecture (CVE-2015-8804).");

  script_tag(name:"affected", value:"'nettle, nettle2.7' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64hogweed2", rpm:"lib64hogweed2~2.7.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hogweed3", rpm:"lib64hogweed3~3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nettle-devel", rpm:"lib64nettle-devel~3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nettle2.7-devel", rpm:"lib64nettle2.7-devel~2.7.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nettle4", rpm:"lib64nettle4~2.7.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nettle5", rpm:"lib64nettle5~3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed2", rpm:"libhogweed2~2.7.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhogweed3", rpm:"libhogweed3~3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle-devel", rpm:"libnettle-devel~3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle2.7-devel", rpm:"libnettle2.7-devel~2.7.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle4", rpm:"libnettle4~2.7.1~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnettle5", rpm:"libnettle5~3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nettle", rpm:"nettle~3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nettle2.7", rpm:"nettle2.7~2.7.1~6.1.mga5", rls:"MAGEIA5"))) {
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

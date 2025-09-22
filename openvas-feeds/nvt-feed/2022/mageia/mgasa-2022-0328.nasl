# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0328");
  script_cve_id("CVE-2022-37434");
  script_tag(name:"creation_date", value:"2022-09-19 05:11:13 +0000 (Mon, 19 Sep 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 18:38:23 +0000 (Thu, 11 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0328)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0328");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0328.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30715");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JWN4VE3JQR4O2SOUS5TXNLANRPMHWV4I/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5570-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5218");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/08/09/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zlib' package(s) announced via the MGASA-2022-0328 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow
in inflate in inflate.c via a large gzip header extra field. NOTE: only
applications that call inflateGetHeader are affected. Some common
applications bundle the affected zlib source code but may be unable to
call inflateGetHeader (e.g., see the nodejs/node reference).
(CVE-2022-37434)");

  script_tag(name:"affected", value:"'zlib' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64minizip-devel", rpm:"lib64minizip-devel~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64minizip1", rpm:"lib64minizip1~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib-devel", rpm:"lib64zlib-devel~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib-static-devel", rpm:"lib64zlib-static-devel~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib1", rpm:"lib64zlib1~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip-devel", rpm:"libminizip-devel~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1", rpm:"libminizip1~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib-devel", rpm:"libzlib-devel~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib-static-devel", rpm:"libzlib-static-devel~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib1", rpm:"libzlib1~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib", rpm:"zlib~1.2.12~1.3.mga8", rls:"MAGEIA8"))) {
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

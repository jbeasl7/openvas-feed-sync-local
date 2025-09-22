# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131176");
  script_cve_id("CVE-2009-0689");
  script_tag(name:"creation_date", value:"2016-01-14 05:28:49 +0000 (Thu, 14 Jan 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2016-0013)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0013");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0013.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/12/19/3");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17375");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-December/174612.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mono' package(s) announced via the MGASA-2016-0013 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that float-parsing code used in Mono before 4.2 is derived
from code vulnerable to CVE-2009-0689. The issue concerns the 'freelist'
array, which is a global array of 16 pointers to 'Bigint'. This array is
part of a memory allocation and reuse system which attempts to reduce the
number of 'malloc' and 'free' calls. The system allocates blocks in
power-of-two sizes, from 2^0 through 2^15, and stores freed blocks of each
size in a linked list rooted at the corresponding cell of 'freelist'. The
'Balloc' and 'Bfree' functions which operate this system fail to check if
the size parameter 'k' is within the allocated 0..15 range. As a result, a
sufficiently large allocation will have k=16 and treat the word
immediately after 'freelist' as a pointer to a previously-allocated chunk.
The specific results may vary significantly based on the version,
platform, and compiler, since they depend on the layout of variables in
memory. An attacker who can cause a carefully-chosen string to be
converted to a floating-point number can cause a crash and potentially
induce arbitrary code execution.");

  script_tag(name:"affected", value:"'mono' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64mono-devel", rpm:"lib64mono-devel~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mono0", rpm:"lib64mono0~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mono2.0_1", rpm:"lib64mono2.0_1~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmono-devel", rpm:"libmono-devel~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmono0", rpm:"libmono0~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmono2.0_1", rpm:"libmono2.0_1~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono", rpm:"mono~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-data", rpm:"mono-data~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-data-oracle", rpm:"mono-data-oracle~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-data-postgresql", rpm:"mono-data-postgresql~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-data-sqlite", rpm:"mono-data-sqlite~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-doc", rpm:"mono-doc~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-extras", rpm:"mono-extras~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-ibm-data-db2", rpm:"mono-ibm-data-db2~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-locale-extras", rpm:"mono-locale-extras~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-nunit", rpm:"mono-nunit~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-rx-core", rpm:"mono-rx-core~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-rx-desktop", rpm:"mono-rx-desktop~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-wcf", rpm:"mono-wcf~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-web", rpm:"mono-web~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-winforms", rpm:"mono-winforms~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-winfxcore", rpm:"mono-winfxcore~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monodoc-core", rpm:"monodoc-core~3.12.1~1.2.mga5", rls:"MAGEIA5"))) {
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

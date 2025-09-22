# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130110");
  script_cve_id("CVE-2015-5073");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:50 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-15 18:40:58 +0000 (Thu, 15 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0267)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0267");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0267.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/06/26/3");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16217");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcre' package(s) announced via the MGASA-2015-0267 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PCRE library is prone to a vulnerability which leads to Heap Overflow.
During subpattern calculation of a malformed regular expression, an offset
that is used as an array index is fully controlled and can be large enough
so that unexpected heap memory regions are accessed (CVE-2015-5073).");

  script_tag(name:"affected", value:"'pcre' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre-devel", rpm:"lib64pcre-devel~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre1", rpm:"lib64pcre1~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre16_0", rpm:"lib64pcre16_0~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre32_0", rpm:"lib64pcre32_0~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcrecpp-devel", rpm:"lib64pcrecpp-devel~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcrecpp0", rpm:"lib64pcrecpp0~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix-devel", rpm:"lib64pcreposix-devel~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix0", rpm:"lib64pcreposix0~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix1", rpm:"lib64pcreposix1~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre-devel", rpm:"libpcre-devel~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16_0", rpm:"libpcre16_0~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre32_0", rpm:"libpcre32_0~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp-devel", rpm:"libpcrecpp-devel~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0", rpm:"libpcrecpp0~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix-devel", rpm:"libpcreposix-devel~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0", rpm:"libpcreposix0~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix1", rpm:"libpcreposix1~8.37~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre", rpm:"pcre~8.37~2.1.mga5", rls:"MAGEIA5"))) {
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

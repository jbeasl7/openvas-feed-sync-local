# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120224");
  script_cve_id("CVE-2015-2325", "CVE-2015-2326", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025", "CVE-2015-4026");
  script_tag(name:"creation_date", value:"2015-09-08 11:20:48 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-24 13:51:00 +0000 (Fri, 24 Jan 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-534)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-534");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-534.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php54' package(s) announced via the ALAS-2015-534 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer underflow flaw leading to out-of-bounds memory access was found in the way PHP's Phar extension parsed Phar archives. A specially crafted archive could cause PHP to crash or, possibly, execute arbitrary code when opened. (CVE-2015-4021)

An integer overflow flaw leading to a heap based buffer overflow was found in the way PHP's FTP extension parsed file listing FTP server responses. A malicious FTP server could use this flaw to cause a PHP application to crash or, possibly, execute arbitrary code. (CVE-2015-4022)

A flaw was found in the way PHP parsed multipart HTTP POST requests. A specially crafted request could cause PHP to use an excessive amount of CPU time. (CVE-2015-4024)

It was found that certain PHP functions did not properly handle file names containing a NULL character. A remote attacker could possibly use this flaw to make a PHP script access unexpected files and bypass intended file system access restrictions. (CVE-2015-4025)

It was found that certain PHP functions did not properly handle file names containing a NULL character. A remote attacker could possibly use this flaw to make a PHP script access unexpected files and bypass intended file system access restrictions. (CVE-2015-4026)

PCRE library is prone to a heap overflow vulnerability. Due to insufficient bounds checking inside compile_branch(), the heap memory could be overflowed via a crafted regular expression. Since PCRE library is widely used, this vulnerability should affect many applications using it. An attacker may exploit this issue to execute arbitrary code in the context of the user running the affected application. (CVE-2015-2325)

PCRE library is prone to a vulnerability which leads to Heap overflow. Without enough bound checking inside pcre_compile2(), the heap memory could be overflowed via a crafted regular expression. Since PCRE library is widely used, this vulnerability should affect many applications. An attacker may exploit this issue to execute arbitrary code in the context of the user running the affected application. (CVE-2015-2326)");

  script_tag(name:"affected", value:"'php54' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"php54", rpm:"php54~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-bcmath", rpm:"php54-bcmath~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-cli", rpm:"php54-cli~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-common", rpm:"php54-common~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-dba", rpm:"php54-dba~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-debuginfo", rpm:"php54-debuginfo~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-devel", rpm:"php54-devel~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-embedded", rpm:"php54-embedded~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-enchant", rpm:"php54-enchant~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-fpm", rpm:"php54-fpm~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-gd", rpm:"php54-gd~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-imap", rpm:"php54-imap~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-intl", rpm:"php54-intl~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-ldap", rpm:"php54-ldap~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-mbstring", rpm:"php54-mbstring~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-mcrypt", rpm:"php54-mcrypt~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-mssql", rpm:"php54-mssql~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-mysql", rpm:"php54-mysql~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-mysqlnd", rpm:"php54-mysqlnd~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-odbc", rpm:"php54-odbc~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-pdo", rpm:"php54-pdo~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-pgsql", rpm:"php54-pgsql~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-process", rpm:"php54-process~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-pspell", rpm:"php54-pspell~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-recode", rpm:"php54-recode~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-snmp", rpm:"php54-snmp~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-soap", rpm:"php54-soap~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-tidy", rpm:"php54-tidy~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-xml", rpm:"php54-xml~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-xmlrpc", rpm:"php54-xmlrpc~5.4.41~1.69.amzn1", rls:"AMAZON"))) {
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

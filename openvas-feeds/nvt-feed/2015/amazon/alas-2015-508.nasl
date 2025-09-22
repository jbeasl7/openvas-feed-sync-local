# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120365");
  script_cve_id("CVE-2015-0231", "CVE-2015-2305", "CVE-2015-2331");
  script_tag(name:"creation_date", value:"2015-09-08 11:24:41 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-508)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-508");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-508.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php56' package(s) announced via the ALAS-2015-508 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free flaw was found in the way PHP's unserialize() function processed data. If a remote attacker was able to pass crafted input to PHP's unserialize() function, they could cause the PHP interpreter to crash or, possibly, execute arbitrary code. (CVE-2015-0231)

An integer overflow flaw, leading to a heap-based buffer overflow, was found in the way libzip, which is also embedded in PHP, processed certain ZIP archives. If an attacker were able to supply a specially crafted ZIP archive to an application using libzip, it could cause the application to crash or, possibly, execute arbitrary code. (CVE-2015-2331)

Integer overflow in the regcomp implementation in the Henry Spencer BSD regex library (aka rxspencer) alpha3.8.g5 on 32-bit platforms, as used in NetBSD through 6.1.5 and other products, might allow context-dependent attackers to execute arbitrary code via a large regular expression that leads to a heap-based buffer overflow. (CVE-2015-2305)");

  script_tag(name:"affected", value:"'php56' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"php56", rpm:"php56~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-bcmath", rpm:"php56-bcmath~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-cli", rpm:"php56-cli~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-common", rpm:"php56-common~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-dba", rpm:"php56-dba~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-dbg", rpm:"php56-dbg~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-debuginfo", rpm:"php56-debuginfo~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-devel", rpm:"php56-devel~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-embedded", rpm:"php56-embedded~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-enchant", rpm:"php56-enchant~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-fpm", rpm:"php56-fpm~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-gd", rpm:"php56-gd~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-gmp", rpm:"php56-gmp~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-imap", rpm:"php56-imap~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-intl", rpm:"php56-intl~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-ldap", rpm:"php56-ldap~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-mbstring", rpm:"php56-mbstring~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-mcrypt", rpm:"php56-mcrypt~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-mssql", rpm:"php56-mssql~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-mysqlnd", rpm:"php56-mysqlnd~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-odbc", rpm:"php56-odbc~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-opcache", rpm:"php56-opcache~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-pdo", rpm:"php56-pdo~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-pgsql", rpm:"php56-pgsql~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-process", rpm:"php56-process~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-pspell", rpm:"php56-pspell~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-recode", rpm:"php56-recode~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-snmp", rpm:"php56-snmp~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-soap", rpm:"php56-soap~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-tidy", rpm:"php56-tidy~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-xml", rpm:"php56-xml~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php56-xmlrpc", rpm:"php56-xmlrpc~5.6.7~1.110.amzn1", rls:"AMAZON"))) {
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

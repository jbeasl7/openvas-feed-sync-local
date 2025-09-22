# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1253.1");
  script_cve_id("CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4026", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4643", "CVE-2015-4644");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-16 20:40:50 +0000 (Mon, 16 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1253-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1253-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151253-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the SUSE-SU-2015:1253-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This security update of PHP fixes the following issues:
Security issues fixed:
* CVE-2015-4024 [bnc#931421]: Fixed multipart/form-data remote DOS
 Vulnerability.
* CVE-2015-4026 [bnc#931776]: pcntl_exec() did not check path validity.
* CVE-2015-4022 [bnc#931772]: Fixed and overflow in ftp_genlist() that
 resulted in a heap overflow.
* CVE-2015-4021 [bnc#931769]: Fixed memory corruption in
 phar_parse_tarfile when entry filename starts with NULL.
* CVE-2015-4148 [bnc#933227]: Fixed SoapClient's do_soap_call() type
 confusion after unserialize() information disclosure.
* CVE-2015-4602 [bnc#935224]: Fixed an incomplete Class unserialization
 type confusion.
* CVE-2015-4599, CVE-2015-4600, CVE-2015-4601 [bnc#935226]: Fixed type
 confusion issues in unserialize() with various SOAP methods.
* CVE-2015-4603 [bnc#935234]: Fixed exception::getTraceAsString type
 confusion issue after unserialize.
* CVE-2015-4644 [bnc#935274]: Fixed a crash in php_pgsql_meta_data.
* CVE-2015-4643 [bnc#935275]: Fixed an integer overflow in ftp_genlist()
 that could result in a heap overflow.
* CVE-2015-3411, CVE-2015-3412, CVE-2015-4598 [bnc#935227], [bnc#935232]:
 Added missing null byte checks for paths in various PHP extensions.
Bugs fixed:
* configure php-fpm with --localstatedir=/var [bnc#927147]
* fix timezone map [bnc#919080]");

  script_tag(name:"affected", value:"'php5' package(s) on SUSE Linux Enterprise Module for Web Scripting 12, SUSE Linux Enterprise Software Development Kit 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php5-debuginfo", rpm:"apache2-mod_php5-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5", rpm:"php5~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-bcmath-debuginfo", rpm:"php5-bcmath-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-bz2-debuginfo", rpm:"php5-bz2-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-calendar-debuginfo", rpm:"php5-calendar-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ctype-debuginfo", rpm:"php5-ctype-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-curl-debuginfo", rpm:"php5-curl-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dba-debuginfo", rpm:"php5-dba-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-debuginfo", rpm:"php5-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-debugsource", rpm:"php5-debugsource~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-dom-debuginfo", rpm:"php5-dom-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-enchant", rpm:"php5-enchant~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-enchant-debuginfo", rpm:"php5-enchant-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-exif-debuginfo", rpm:"php5-exif-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fastcgi-debuginfo", rpm:"php5-fastcgi-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fileinfo", rpm:"php5-fileinfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fileinfo-debuginfo", rpm:"php5-fileinfo-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fpm", rpm:"php5-fpm~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-fpm-debuginfo", rpm:"php5-fpm-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ftp-debuginfo", rpm:"php5-ftp-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gd-debuginfo", rpm:"php5-gd-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gettext-debuginfo", rpm:"php5-gettext-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-gmp-debuginfo", rpm:"php5-gmp-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-iconv-debuginfo", rpm:"php5-iconv-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-intl", rpm:"php5-intl~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-intl-debuginfo", rpm:"php5-intl-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-json", rpm:"php5-json~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-json-debuginfo", rpm:"php5-json-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-ldap-debuginfo", rpm:"php5-ldap-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mbstring-debuginfo", rpm:"php5-mbstring-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mcrypt-debuginfo", rpm:"php5-mcrypt-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-mysql-debuginfo", rpm:"php5-mysql-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-odbc-debuginfo", rpm:"php5-odbc-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-openssl-debuginfo", rpm:"php5-openssl-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pcntl-debuginfo", rpm:"php5-pcntl-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pdo-debuginfo", rpm:"php5-pdo-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pgsql-debuginfo", rpm:"php5-pgsql-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-pspell-debuginfo", rpm:"php5-pspell-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-shmop-debuginfo", rpm:"php5-shmop-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-snmp-debuginfo", rpm:"php5-snmp-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-soap-debuginfo", rpm:"php5-soap-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sockets-debuginfo", rpm:"php5-sockets-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sqlite-debuginfo", rpm:"php5-sqlite-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-suhosin-debuginfo", rpm:"php5-suhosin-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvmsg-debuginfo", rpm:"php5-sysvmsg-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvsem-debuginfo", rpm:"php5-sysvsem-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-sysvshm-debuginfo", rpm:"php5-sysvshm-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-tokenizer-debuginfo", rpm:"php5-tokenizer-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-wddx-debuginfo", rpm:"php5-wddx-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlreader-debuginfo", rpm:"php5-xmlreader-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlrpc-debuginfo", rpm:"php5-xmlrpc-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlwriter", rpm:"php5-xmlwriter~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xmlwriter-debuginfo", rpm:"php5-xmlwriter-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-xsl-debuginfo", rpm:"php5-xsl-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-zip", rpm:"php5-zip~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-zip-debuginfo", rpm:"php5-zip-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.5.14~30.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php5-zlib-debuginfo", rpm:"php5-zlib-debuginfo~5.5.14~30.1", rls:"SLES12.0"))) {
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

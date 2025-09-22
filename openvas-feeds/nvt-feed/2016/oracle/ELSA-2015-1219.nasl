# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122867");
  script_cve_id("CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025", "CVE-2015-4026", "CVE-2015-4598", "CVE-2015-4643", "CVE-2015-4644");
  script_tag(name:"creation_date", value:"2016-02-05 12:01:36 +0000 (Fri, 05 Feb 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Oracle: Security Advisory (ELSA-2015-1219)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1219");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1219.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php54-php' package(s) announced via the ELSA-2015-1219 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.4.40-3]
- fix more functions accept paths with NUL character #1213407

[5.4.40-2]
- core: fix multipart/form-data request can use excessive
 amount of CPU usage CVE-2015-4024
- fix various functions accept paths with NUL character
 CVE-2015-4025, CVE-2015-4026
- ftp: fix integer overflow leading to heap overflow when
 reading FTP file listing CVE-2015-4022
- phar: fix memory corruption in phar_parse_tarfile caused by
 empty entry file name CVE-2015-4021
- pgsql: fix NULL pointer dereference CVE-2015-1352");

  script_tag(name:"affected", value:"'php54-php' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"php54-php", rpm:"php54-php~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-bcmath", rpm:"php54-php-bcmath~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-cli", rpm:"php54-php-cli~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-common", rpm:"php54-php-common~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-dba", rpm:"php54-php-dba~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-devel", rpm:"php54-php-devel~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-enchant", rpm:"php54-php-enchant~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-fpm", rpm:"php54-php-fpm~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-gd", rpm:"php54-php-gd~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-imap", rpm:"php54-php-imap~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-intl", rpm:"php54-php-intl~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-ldap", rpm:"php54-php-ldap~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-mbstring", rpm:"php54-php-mbstring~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-mysqlnd", rpm:"php54-php-mysqlnd~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-odbc", rpm:"php54-php-odbc~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pdo", rpm:"php54-php-pdo~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pgsql", rpm:"php54-php-pgsql~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-process", rpm:"php54-php-process~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pspell", rpm:"php54-php-pspell~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-recode", rpm:"php54-php-recode~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-snmp", rpm:"php54-php-snmp~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-soap", rpm:"php54-php-soap~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-tidy", rpm:"php54-php-tidy~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-xml", rpm:"php54-php-xml~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-xmlrpc", rpm:"php54-php-xmlrpc~5.4.40~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"php54-php", rpm:"php54-php~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-bcmath", rpm:"php54-php-bcmath~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-cli", rpm:"php54-php-cli~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-common", rpm:"php54-php-common~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-dba", rpm:"php54-php-dba~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-devel", rpm:"php54-php-devel~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-enchant", rpm:"php54-php-enchant~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-fpm", rpm:"php54-php-fpm~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-gd", rpm:"php54-php-gd~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-intl", rpm:"php54-php-intl~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-ldap", rpm:"php54-php-ldap~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-mbstring", rpm:"php54-php-mbstring~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-mysqlnd", rpm:"php54-php-mysqlnd~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-odbc", rpm:"php54-php-odbc~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pdo", rpm:"php54-php-pdo~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pgsql", rpm:"php54-php-pgsql~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-process", rpm:"php54-php-process~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-pspell", rpm:"php54-php-pspell~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-recode", rpm:"php54-php-recode~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-snmp", rpm:"php54-php-snmp~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-soap", rpm:"php54-php-soap~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-xml", rpm:"php54-php-xml~5.4.40~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php54-php-xmlrpc", rpm:"php54-php-xmlrpc~5.4.40~3.el7", rls:"OracleLinux7"))) {
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

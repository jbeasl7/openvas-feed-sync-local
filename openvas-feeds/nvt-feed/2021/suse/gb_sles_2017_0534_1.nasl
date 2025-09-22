# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0534.1");
  script_cve_id("CVE-2015-8876", "CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160", "CVE-2016-10161", "CVE-2016-10162", "CVE-2016-10166", "CVE-2016-10167", "CVE-2016-10168", "CVE-2016-7478", "CVE-2016-7479", "CVE-2016-7480", "CVE-2016-9138", "CVE-2017-5340");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-11 18:04:46 +0000 (Wed, 11 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0534-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0534-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170534-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7' package(s) announced via the SUSE-SU-2017:0534-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php7 fixes the following security issues:
- CVE-2016-7480: The SplObjectStorage unserialize implementation in
 ext/spl/spl_observer.c in PHP did not verify that a key is an object,
 which allowed remote attackers to execute arbitrary code or cause a
 denial
 of service (uninitialized memory access) via crafted serialized data.
 (bsc#1019568)
- CVE-2017-5340: Zend/zend_hash.c in PHP mishandled certain cases that
 require large array allocations, which allowed remote attackers to
 execute arbitrary code or cause a denial of service (integer overflow,
 uninitialized memory access, and use of arbitrary destructor function
 pointers) via crafted serialized data. (bsc#1019570)
- CVE-2016-7479: In all versions of PHP 7, during the unserialization
 process, resizing the 'properties' hash table of a serialized object may
 have lead to use-after-free. A remote attacker may exploit this bug to
 gain arbitrary code execution. (bsc#1019547)
- CVE-2016-7478: Zend/zend_exceptions.c in PHP allowed remote attackers to
 cause a denial of service (infinite loop) via a crafted Exception object
 in serialized data, a related issue to CVE-2015-8876. (bsc#1019550)
- CVE-2016-10159: Integer overflow in the phar_parse_pharfile function in
 ext/phar/phar.c in PHP allowed remote attackers to cause a denial
 of service (memory consumption or application crash) via a truncated
 manifest entry in a PHAR archive. (bsc#1022255)
- CVE-2016-10160: Off-by-one error in the phar_parse_pharfile function in
 ext/phar/phar.c in PHP allowed remote attackers to cause a denial
 of service (memory corruption) or possibly execute arbitrary code via a
 crafted PHAR archive with an alias mismatch. (bsc#1022257)
- CVE-2016-10161: The object_common1 function in
 ext/standard/var_unserializer.c in PHP allowed remote attackers to cause
 a denial of service (buffer over-read and application crash) via crafted
 serialized data that is mishandled in a finish_nested_data call.
 (bsc#1022260)
- CVE-2016-10162: The php_wddx_pop_element function in ext/wddx/wddx.c in
 PHP 7 allowed remote attackers to cause a denial of service (NULL
 pointer dereference and application crash) via an inapplicable class
 name in a wddxPacket XML document, leading to mishandling in a
 wddx_deserialize call. (bsc#1022262)
- CVE-2016-10166: A potential unsigned underflow in gd interpolation
 functions could lead to memory corruption in the PHP gd module
 (bsc#1022263)
- CVE-2016-10167: A denial of service problem in gdImageCreateFromGd2Ctx()
 could lead to php out of memory even on small files. (bsc#1022264)
- CVE-2016-10168: A signed integer overflow in the gd module could lead to
 memory corruption (bsc#1022265)
- CVE-2016-9138: PHP mishandled property modification during __wakeup
 processing, which allows remote attackers to cause a denial of service
 or possibly have unspecified other impact via crafted serialized data,
 as demonstrated by Exception::__toString with DateInterval::__wakeup.
 (bsc#1008026)");

  script_tag(name:"affected", value:"'php7' package(s) on SUSE Linux Enterprise Module for Web Scripting 12, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php7", rpm:"apache2-mod_php7~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php7-debuginfo", rpm:"apache2-mod_php7-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7", rpm:"php7~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bcmath", rpm:"php7-bcmath~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bcmath-debuginfo", rpm:"php7-bcmath-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bz2", rpm:"php7-bz2~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bz2-debuginfo", rpm:"php7-bz2-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-calendar", rpm:"php7-calendar~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-calendar-debuginfo", rpm:"php7-calendar-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ctype", rpm:"php7-ctype~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ctype-debuginfo", rpm:"php7-ctype-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-curl", rpm:"php7-curl~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-curl-debuginfo", rpm:"php7-curl-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dba", rpm:"php7-dba~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dba-debuginfo", rpm:"php7-dba-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-debuginfo", rpm:"php7-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-debugsource", rpm:"php7-debugsource~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dom", rpm:"php7-dom~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dom-debuginfo", rpm:"php7-dom-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-enchant", rpm:"php7-enchant~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-enchant-debuginfo", rpm:"php7-enchant-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-exif", rpm:"php7-exif~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-exif-debuginfo", rpm:"php7-exif-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fastcgi", rpm:"php7-fastcgi~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fastcgi-debuginfo", rpm:"php7-fastcgi-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fileinfo", rpm:"php7-fileinfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fileinfo-debuginfo", rpm:"php7-fileinfo-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fpm", rpm:"php7-fpm~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fpm-debuginfo", rpm:"php7-fpm-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ftp", rpm:"php7-ftp~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ftp-debuginfo", rpm:"php7-ftp-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gd", rpm:"php7-gd~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gd-debuginfo", rpm:"php7-gd-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gettext", rpm:"php7-gettext~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gettext-debuginfo", rpm:"php7-gettext-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gmp", rpm:"php7-gmp~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gmp-debuginfo", rpm:"php7-gmp-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-iconv", rpm:"php7-iconv~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-iconv-debuginfo", rpm:"php7-iconv-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-imap", rpm:"php7-imap~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-imap-debuginfo", rpm:"php7-imap-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-intl", rpm:"php7-intl~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-intl-debuginfo", rpm:"php7-intl-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-json", rpm:"php7-json~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-json-debuginfo", rpm:"php7-json-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ldap", rpm:"php7-ldap~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ldap-debuginfo", rpm:"php7-ldap-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mbstring", rpm:"php7-mbstring~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mbstring-debuginfo", rpm:"php7-mbstring-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mcrypt", rpm:"php7-mcrypt~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mcrypt-debuginfo", rpm:"php7-mcrypt-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mysql", rpm:"php7-mysql~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mysql-debuginfo", rpm:"php7-mysql-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-odbc", rpm:"php7-odbc~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-odbc-debuginfo", rpm:"php7-odbc-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-opcache", rpm:"php7-opcache~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-opcache-debuginfo", rpm:"php7-opcache-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-openssl", rpm:"php7-openssl~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-openssl-debuginfo", rpm:"php7-openssl-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pcntl", rpm:"php7-pcntl~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pcntl-debuginfo", rpm:"php7-pcntl-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pdo", rpm:"php7-pdo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pdo-debuginfo", rpm:"php7-pdo-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pear", rpm:"php7-pear~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pear-Archive_Tar", rpm:"php7-pear-Archive_Tar~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pgsql", rpm:"php7-pgsql~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pgsql-debuginfo", rpm:"php7-pgsql-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-phar", rpm:"php7-phar~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-phar-debuginfo", rpm:"php7-phar-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-posix", rpm:"php7-posix~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-posix-debuginfo", rpm:"php7-posix-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pspell", rpm:"php7-pspell~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pspell-debuginfo", rpm:"php7-pspell-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-shmop", rpm:"php7-shmop~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-shmop-debuginfo", rpm:"php7-shmop-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-snmp", rpm:"php7-snmp~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-snmp-debuginfo", rpm:"php7-snmp-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-soap", rpm:"php7-soap~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-soap-debuginfo", rpm:"php7-soap-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sockets", rpm:"php7-sockets~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sockets-debuginfo", rpm:"php7-sockets-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sqlite", rpm:"php7-sqlite~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sqlite-debuginfo", rpm:"php7-sqlite-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvmsg", rpm:"php7-sysvmsg~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvmsg-debuginfo", rpm:"php7-sysvmsg-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvsem", rpm:"php7-sysvsem~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvsem-debuginfo", rpm:"php7-sysvsem-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvshm", rpm:"php7-sysvshm~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvshm-debuginfo", rpm:"php7-sysvshm-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-tokenizer", rpm:"php7-tokenizer~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-tokenizer-debuginfo", rpm:"php7-tokenizer-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-wddx", rpm:"php7-wddx~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-wddx-debuginfo", rpm:"php7-wddx-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlreader", rpm:"php7-xmlreader~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlreader-debuginfo", rpm:"php7-xmlreader-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlrpc", rpm:"php7-xmlrpc~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlrpc-debuginfo", rpm:"php7-xmlrpc-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlwriter", rpm:"php7-xmlwriter~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlwriter-debuginfo", rpm:"php7-xmlwriter-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xsl", rpm:"php7-xsl~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xsl-debuginfo", rpm:"php7-xsl-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zip", rpm:"php7-zip~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zip-debuginfo", rpm:"php7-zip-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zlib", rpm:"php7-zlib~7.0.7~35.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zlib-debuginfo", rpm:"php7-zlib-debuginfo~7.0.7~35.1", rls:"SLES12.0"))) {
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

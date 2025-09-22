# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2460.2");
  script_cve_id("CVE-2016-4473", "CVE-2016-5399", "CVE-2016-6128", "CVE-2016-6161", "CVE-2016-6207", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6292", "CVE-2016-6295", "CVE-2016-6296", "CVE-2016-6297", "CVE-2016-7124", "CVE-2016-7125", "CVE-2016-7126", "CVE-2016-7127", "CVE-2016-7128", "CVE-2016-7129", "CVE-2016-7130", "CVE-2016-7131", "CVE-2016-7132", "CVE-2016-7133", "CVE-2016-7134", "CVE-2016-7412", "CVE-2016-7413", "CVE-2016-7414", "CVE-2016-7416", "CVE-2016-7417", "CVE-2016-7418");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-19 14:22:36 +0000 (Mon, 19 Sep 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2460-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2460-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162460-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7' package(s) announced via the SUSE-SU-2016:2460-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php7 fixes the following security issues:
* CVE-2016-6128: Invalid color index not properly handled [bsc#987580]
* CVE-2016-6161: global out of bounds read when encoding gif from
 malformed input withgd2togif [bsc#988032]
* CVE-2016-6292: Null pointer dereference in exif_process_user_comment
 [bsc#991422]
* CVE-2016-6295: Use after free in SNMP with GC and unserialize()
 [bsc#991424]
* CVE-2016-6297: Stack-based buffer overflow vulnerability in
 php_stream_zip_opener [bsc#991426]
* CVE-2016-6291: Out-of-bounds access in exif_process_IFD_in_MAKERNOTE
 [bsc#991427]
* CVE-2016-6289: Integer overflow leads to buffer overflow in
 virtual_file_ex [bsc#991428]
* CVE-2016-6290: Use after free in unserialize() with Unexpected Session
 Deserialization [bsc#991429]
* CVE-2016-5399: Improper error handling in bzread() [bsc#991430]
* CVE-2016-6296: Heap buffer overflow vulnerability in simplestring_addn
 in simplestring.c [bsc#991437]
* CVE-2016-6207: Integer overflow error within _gdContributionsAlloc()
 [bsc#991434]
* CVE-2016-4473: Invalid free() instead of efree() in phar_extract_file()
* CVE-2016-7124: Create an Unexpected Object and Don't Invoke __wakeup()
 in Deserialization
* CVE-2016-7125: PHP Session Data Injection Vulnerability
* CVE-2016-7126: select_colors write out-of-bounds
* CVE-2016-7127: imagegammacorrect allowed arbitrary write access
* CVE-2016-7128: Memory Leakage In exif_process_IFD_in_TIFF
* CVE-2016-7129: wddx_deserialize allowed illegal memory access
* CVE-2016-7131: wddx_deserialize null dereference with invalid xml
* CVE-2016-7132: wddx_deserialize null dereference in php_wddx_pop_element
* CVE-2016-7133: memory allocator fails to realloc small block to large one
* CVE-2016-7134: Heap overflow in the function curl_escape
* CVE-2016-7130: wddx_deserialize null dereference
* CVE-2016-7413: Use after free in wddx_deserialize
* CVE-2016-7412: Heap overflow in mysqlnd when not receiving UNSIGNED_FLAG
 in BIT field
* CVE-2016-7417: Missing type check when unserializing SplArray
* CVE-2016-7416: Stack based buffer overflow in msgfmt_format_message
* CVE-2016-7418: Null pointer dereference in php_wddx_push_element
* CVE-2016-7414: Out of bounds heap read when verifying signature of zip
 phar in phar_parse_zipfile");

  script_tag(name:"affected", value:"'php7' package(s) on SUSE Linux Enterprise Module for Web Scripting 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php7", rpm:"apache2-mod_php7~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php7-debuginfo", rpm:"apache2-mod_php7-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7", rpm:"php7~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bcmath", rpm:"php7-bcmath~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bcmath-debuginfo", rpm:"php7-bcmath-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bz2", rpm:"php7-bz2~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bz2-debuginfo", rpm:"php7-bz2-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-calendar", rpm:"php7-calendar~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-calendar-debuginfo", rpm:"php7-calendar-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ctype", rpm:"php7-ctype~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ctype-debuginfo", rpm:"php7-ctype-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-curl", rpm:"php7-curl~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-curl-debuginfo", rpm:"php7-curl-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dba", rpm:"php7-dba~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dba-debuginfo", rpm:"php7-dba-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-debuginfo", rpm:"php7-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-debugsource", rpm:"php7-debugsource~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dom", rpm:"php7-dom~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dom-debuginfo", rpm:"php7-dom-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-enchant", rpm:"php7-enchant~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-enchant-debuginfo", rpm:"php7-enchant-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-exif", rpm:"php7-exif~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-exif-debuginfo", rpm:"php7-exif-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fastcgi", rpm:"php7-fastcgi~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fastcgi-debuginfo", rpm:"php7-fastcgi-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fileinfo", rpm:"php7-fileinfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fileinfo-debuginfo", rpm:"php7-fileinfo-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fpm", rpm:"php7-fpm~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fpm-debuginfo", rpm:"php7-fpm-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ftp", rpm:"php7-ftp~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ftp-debuginfo", rpm:"php7-ftp-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gd", rpm:"php7-gd~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gd-debuginfo", rpm:"php7-gd-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gettext", rpm:"php7-gettext~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gettext-debuginfo", rpm:"php7-gettext-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gmp", rpm:"php7-gmp~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gmp-debuginfo", rpm:"php7-gmp-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-iconv", rpm:"php7-iconv~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-iconv-debuginfo", rpm:"php7-iconv-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-imap", rpm:"php7-imap~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-imap-debuginfo", rpm:"php7-imap-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-intl", rpm:"php7-intl~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-intl-debuginfo", rpm:"php7-intl-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-json", rpm:"php7-json~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-json-debuginfo", rpm:"php7-json-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ldap", rpm:"php7-ldap~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ldap-debuginfo", rpm:"php7-ldap-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mbstring", rpm:"php7-mbstring~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mbstring-debuginfo", rpm:"php7-mbstring-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mcrypt", rpm:"php7-mcrypt~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mcrypt-debuginfo", rpm:"php7-mcrypt-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mysql", rpm:"php7-mysql~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mysql-debuginfo", rpm:"php7-mysql-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-odbc", rpm:"php7-odbc~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-odbc-debuginfo", rpm:"php7-odbc-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-opcache", rpm:"php7-opcache~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-opcache-debuginfo", rpm:"php7-opcache-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-openssl", rpm:"php7-openssl~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-openssl-debuginfo", rpm:"php7-openssl-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pcntl", rpm:"php7-pcntl~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pcntl-debuginfo", rpm:"php7-pcntl-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pdo", rpm:"php7-pdo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pdo-debuginfo", rpm:"php7-pdo-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pear", rpm:"php7-pear~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pear-Archive_Tar", rpm:"php7-pear-Archive_Tar~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pgsql", rpm:"php7-pgsql~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pgsql-debuginfo", rpm:"php7-pgsql-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-phar", rpm:"php7-phar~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-phar-debuginfo", rpm:"php7-phar-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-posix", rpm:"php7-posix~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-posix-debuginfo", rpm:"php7-posix-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pspell", rpm:"php7-pspell~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pspell-debuginfo", rpm:"php7-pspell-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-shmop", rpm:"php7-shmop~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-shmop-debuginfo", rpm:"php7-shmop-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-snmp", rpm:"php7-snmp~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-snmp-debuginfo", rpm:"php7-snmp-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-soap", rpm:"php7-soap~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-soap-debuginfo", rpm:"php7-soap-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sockets", rpm:"php7-sockets~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sockets-debuginfo", rpm:"php7-sockets-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sqlite", rpm:"php7-sqlite~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sqlite-debuginfo", rpm:"php7-sqlite-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvmsg", rpm:"php7-sysvmsg~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvmsg-debuginfo", rpm:"php7-sysvmsg-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvsem", rpm:"php7-sysvsem~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvsem-debuginfo", rpm:"php7-sysvsem-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvshm", rpm:"php7-sysvshm~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvshm-debuginfo", rpm:"php7-sysvshm-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-tokenizer", rpm:"php7-tokenizer~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-tokenizer-debuginfo", rpm:"php7-tokenizer-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-wddx", rpm:"php7-wddx~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-wddx-debuginfo", rpm:"php7-wddx-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlreader", rpm:"php7-xmlreader~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlreader-debuginfo", rpm:"php7-xmlreader-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlrpc", rpm:"php7-xmlrpc~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlrpc-debuginfo", rpm:"php7-xmlrpc-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlwriter", rpm:"php7-xmlwriter~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlwriter-debuginfo", rpm:"php7-xmlwriter-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xsl", rpm:"php7-xsl~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xsl-debuginfo", rpm:"php7-xsl-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zip", rpm:"php7-zip~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zip-debuginfo", rpm:"php7-zip-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zlib", rpm:"php7-zlib~7.0.7~15.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zlib-debuginfo", rpm:"php7-zlib-debuginfo~7.0.7~15.1", rls:"SLES12.0"))) {
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

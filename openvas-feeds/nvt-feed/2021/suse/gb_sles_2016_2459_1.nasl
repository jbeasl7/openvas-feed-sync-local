# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2459.1");
  script_cve_id("CVE-2016-7124", "CVE-2016-7125", "CVE-2016-7126", "CVE-2016-7127", "CVE-2016-7128", "CVE-2016-7129", "CVE-2016-7130", "CVE-2016-7131", "CVE-2016-7132", "CVE-2016-7411", "CVE-2016-7412", "CVE-2016-7413", "CVE-2016-7414", "CVE-2016-7416", "CVE-2016-7417", "CVE-2016-7418");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-19 14:22:36 +0000 (Mon, 19 Sep 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2459-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2459-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162459-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999679");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999820");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-October/002310.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php53' package(s) announced via the SUSE-SU-2016:2459-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php53 fixes the following security issues:

* CVE-2016-7124: Create an Unexpected Object and Don't Invoke __wakeup() in Deserialization
* CVE-2016-7125: PHP Session Data Injection Vulnerability
* CVE-2016-7126: select_colors write out-of-bounds
* CVE-2016-7127: imagegammacorrect allowed arbitrary write access
* CVE-2016-7128: Memory Leakage In exif_process_IFD_in_TIFF
* CVE-2016-7129: wddx_deserialize allows illegal memory access
* CVE-2016-7130: wddx_deserialize null dereference
* CVE-2016-7131: wddx_deserialize null dereference with invalid xml
* CVE-2016-7132: wddx_deserialize null dereference in php_wddx_pop_element
* CVE-2016-7411: php5: Memory corruption when destructing deserialized object
* CVE-2016-7412: Heap overflow in mysqlnd when not receiving UNSIGNED_FLAG in BIT field
* CVE-2016-7413: Use after free in wddx_deserialize
* CVE-2016-7414: Out of bounds heap read when verifying signature of zip phar in phar_parse_zipfile
* CVE-2016-7416: Stack based buffer overflow in msgfmt_format_message
* CVE-2016-7417: Missing type check when unserializing SplArray
* CVE-2016-7418: Null pointer dereference in php_wddx_push_element");

  script_tag(name:"affected", value:"'php53' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php53", rpm:"apache2-mod_php53~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-bz2", rpm:"php53-bz2~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-calendar", rpm:"php53-calendar~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ctype", rpm:"php53-ctype~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-curl", rpm:"php53-curl~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-dom", rpm:"php53-dom~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-exif", rpm:"php53-exif~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-fastcgi", rpm:"php53-fastcgi~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-fileinfo", rpm:"php53-fileinfo~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ftp", rpm:"php53-ftp~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gettext", rpm:"php53-gettext~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gmp", rpm:"php53-gmp~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-iconv", rpm:"php53-iconv~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-json", rpm:"php53-json~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mcrypt", rpm:"php53-mcrypt~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-openssl", rpm:"php53-openssl~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pcntl", rpm:"php53-pcntl~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pear", rpm:"php53-pear~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-shmop", rpm:"php53-shmop~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-suhosin", rpm:"php53-suhosin~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvmsg", rpm:"php53-sysvmsg~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvsem", rpm:"php53-sysvsem~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvshm", rpm:"php53-sysvshm~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-tokenizer", rpm:"php53-tokenizer~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-wddx", rpm:"php53-wddx~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlreader", rpm:"php53-xmlreader~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlwriter", rpm:"php53-xmlwriter~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xsl", rpm:"php53-xsl~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-zip", rpm:"php53-zip~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-zlib", rpm:"php53-zlib~5.3.17~84.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php53", rpm:"apache2-mod_php53~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-bz2", rpm:"php53-bz2~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-calendar", rpm:"php53-calendar~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ctype", rpm:"php53-ctype~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-curl", rpm:"php53-curl~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-dom", rpm:"php53-dom~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-exif", rpm:"php53-exif~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-fastcgi", rpm:"php53-fastcgi~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-fileinfo", rpm:"php53-fileinfo~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ftp", rpm:"php53-ftp~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gettext", rpm:"php53-gettext~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gmp", rpm:"php53-gmp~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-iconv", rpm:"php53-iconv~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-json", rpm:"php53-json~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mcrypt", rpm:"php53-mcrypt~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-openssl", rpm:"php53-openssl~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pcntl", rpm:"php53-pcntl~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pear", rpm:"php53-pear~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-shmop", rpm:"php53-shmop~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-suhosin", rpm:"php53-suhosin~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvmsg", rpm:"php53-sysvmsg~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvsem", rpm:"php53-sysvsem~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvshm", rpm:"php53-sysvshm~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-tokenizer", rpm:"php53-tokenizer~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-wddx", rpm:"php53-wddx~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlreader", rpm:"php53-xmlreader~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlwriter", rpm:"php53-xmlwriter~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xsl", rpm:"php53-xsl~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-zip", rpm:"php53-zip~5.3.17~84.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-zlib", rpm:"php53-zlib~5.3.17~84.1", rls:"SLES11.0SP4"))) {
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

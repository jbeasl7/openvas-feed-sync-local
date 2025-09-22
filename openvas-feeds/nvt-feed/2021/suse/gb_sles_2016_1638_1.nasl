# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1638.1");
  script_cve_id("CVE-2004-1019", "CVE-2006-7243", "CVE-2014-0207", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3515", "CVE-2014-3597", "CVE-2014-3668", "CVE-2014-3669", "CVE-2014-3670", "CVE-2014-4049", "CVE-2014-4670", "CVE-2014-4698", "CVE-2014-4721", "CVE-2014-5459", "CVE-2014-8142", "CVE-2014-9652", "CVE-2014-9705", "CVE-2014-9709", "CVE-2014-9767", "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-1352", "CVE-2015-2301", "CVE-2015-2305", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3152", "CVE-2015-3329", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4026", "CVE-2015-4116", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4643", "CVE-2015-4644", "CVE-2015-5161", "CVE-2015-5589", "CVE-2015-5590", "CVE-2015-6831", "CVE-2015-6833", "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-6838", "CVE-2015-7803", "CVE-2015-8835", "CVE-2015-8838", "CVE-2015-8866", "CVE-2015-8867", "CVE-2015-8873", "CVE-2015-8874", "CVE-2015-8879", "CVE-2016-2554", "CVE-2016-3141", "CVE-2016-3142", "CVE-2016-3185", "CVE-2016-4070", "CVE-2016-4073", "CVE-2016-4342", "CVE-2016-4346", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096", "CVE-2016-5114");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-24 17:53:58 +0000 (Tue, 24 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1638-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1638-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161638-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/886059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/886060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/893849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/893853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982162");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-June/002131.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php53' package(s) announced via the SUSE-SU-2016:1638-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php53 to version 5.3.17 fixes the following issues:

These security issues were fixed:
- CVE-2016-5093: get_icu_value_internal out-of-bounds read (bnc#982010).
- CVE-2016-5094: Don't create strings with lengths outside int range (bnc#982011).
- CVE-2016-5095: Don't create strings with lengths outside int range (bnc#982012).
- CVE-2016-5096: int/size_t confusion in fread (bsc#982013).
- CVE-2016-5114: fpm_log.c memory leak and buffer overflow (bnc#982162).
- CVE-2015-8879: The odbc_bindcols function in ext/odbc/php_odbc.c in PHP mishandles driver behavior for SQL_WVARCHAR columns, which allowed remote attackers to cause a denial of service (application crash) in opportunistic circumstances by leveraging use of the odbc_fetch_array function to access a certain type of Microsoft SQL Server table (bsc#981050).
- CVE-2015-4116: Use-after-free vulnerability in the spl_ptr_heap_insert function in ext/spl/spl_heap.c in PHP allowed remote attackers to execute arbitrary code by triggering a failed SplMinHeap::compare operation (bsc#980366).
- CVE-2015-8874: Stack consumption vulnerability in GD in PHP allowed remote attackers to cause a denial of service via a crafted imagefilltoborder call (bsc#980375).
- CVE-2015-8873: Stack consumption vulnerability in Zend/zend_exceptions.c in PHP allowed remote attackers to cause a denial of service (segmentation fault) via recursive method calls (bsc#980373).
- CVE-2016-4540: The grapheme_stripos function in ext/intl/grapheme/grapheme_string.c in PHP allowed remote attackers to cause a denial of service (out-of-bounds read) or possibly have unspecified other impact via a negative offset (bsc#978829).
- CVE-2016-4541: The grapheme_strpos function in ext/intl/grapheme/grapheme_string.c in PHP allowed remote attackers to cause a denial of service (out-of-bounds read) or possibly have unspecified other impact via a negative offset (bsc#978829.
- CVE-2016-4542: The exif_process_IFD_TAG function in ext/exif/exif.c in PHP did not properly construct spprintf arguments, which allowed remote attackers to cause a denial of service (out-of-bounds read) or possibly have unspecified other impact via crafted header data (bsc#978830).
- CVE-2016-4543: The exif_process_IFD_in_JPEG function in ext/exif/exif.c in PHP did not validate IFD sizes, which allowed remote attackers to cause a denial of service (out-of-bounds read) or possibly have unspecified other impact via crafted header data (bsc#978830.
- CVE-2016-4544: The exif_process_TIFF_in_JPEG function in ext/exif/exif.c in PHP did not validate TIFF start data, which allowed remote attackers to cause a denial of service (out-of-bounds read) or possibly have unspecified other impact via crafted header data (bsc#978830.
- CVE-2016-4537: The bcpowmod function in ext/bcmath/bcmath.c in PHP accepted a negative integer for the scale argument, which allowed remote attackers to cause a denial of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php53' package(s) on SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php53", rpm:"apache2-mod_php53~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-bz2", rpm:"php53-bz2~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-calendar", rpm:"php53-calendar~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ctype", rpm:"php53-ctype~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-curl", rpm:"php53-curl~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-dom", rpm:"php53-dom~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-exif", rpm:"php53-exif~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-fastcgi", rpm:"php53-fastcgi~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-fileinfo", rpm:"php53-fileinfo~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ftp", rpm:"php53-ftp~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gettext", rpm:"php53-gettext~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gmp", rpm:"php53-gmp~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-iconv", rpm:"php53-iconv~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-json", rpm:"php53-json~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mcrypt", rpm:"php53-mcrypt~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-openssl", rpm:"php53-openssl~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pcntl", rpm:"php53-pcntl~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pear", rpm:"php53-pear~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-shmop", rpm:"php53-shmop~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-suhosin", rpm:"php53-suhosin~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvmsg", rpm:"php53-sysvmsg~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvsem", rpm:"php53-sysvsem~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvshm", rpm:"php53-sysvshm~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-tokenizer", rpm:"php53-tokenizer~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-wddx", rpm:"php53-wddx~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlreader", rpm:"php53-xmlreader~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlwriter", rpm:"php53-xmlwriter~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xsl", rpm:"php53-xsl~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-zip", rpm:"php53-zip~5.3.17~47.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-zlib", rpm:"php53-zlib~5.3.17~47.1", rls:"SLES11.0SP2"))) {
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

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0370.1");
  script_cve_id("CVE-2013-4113", "CVE-2013-4248", "CVE-2013-4635", "CVE-2013-6420", "CVE-2013-6501", "CVE-2013-6712", "CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-2497", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3515", "CVE-2014-3668", "CVE-2014-3669", "CVE-2014-3670", "CVE-2014-4049", "CVE-2014-4670", "CVE-2014-4698", "CVE-2014-4721", "CVE-2014-5459", "CVE-2014-8142", "CVE-2014-9652", "CVE-2014-9705", "CVE-2014-9709", "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-2301", "CVE-2015-2305", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3329", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4026", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4643", "CVE-2015-4644");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-16 20:40:50 +0000 (Mon, 16 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0370-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0370-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150370-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/837746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/842676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882992");
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
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923946");
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
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935275");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-February/001251.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php53' package(s) announced via the SUSE-SU-2015:0370-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following vulnerabilities in php:

 * Heap corruption issue in exif_thumbnail(). (CVE-2014-3670)
 * Integer overflow in unserialize(). (CVE-2014-3669)
 * Xmlrpc ISO8601 date format parsing out-of-bounds read in mkgmtime().
 (CVE-2014-3668)

Security Issues:

 * CVE-2014-3669
 <[link moved to references]>
 * CVE-2014-3670
 <[link moved to references]>
 * CVE-2014-3668
 <[link moved to references]>");

  script_tag(name:"affected", value:"'php53' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php53", rpm:"apache2-mod_php53~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-bz2", rpm:"php53-bz2~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-calendar", rpm:"php53-calendar~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ctype", rpm:"php53-ctype~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-curl", rpm:"php53-curl~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-dom", rpm:"php53-dom~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-exif", rpm:"php53-exif~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-fastcgi", rpm:"php53-fastcgi~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-fileinfo", rpm:"php53-fileinfo~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ftp", rpm:"php53-ftp~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gettext", rpm:"php53-gettext~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-gmp", rpm:"php53-gmp~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-iconv", rpm:"php53-iconv~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-json", rpm:"php53-json~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mcrypt", rpm:"php53-mcrypt~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-openssl", rpm:"php53-openssl~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pcntl", rpm:"php53-pcntl~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pear", rpm:"php53-pear~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-shmop", rpm:"php53-shmop~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-suhosin", rpm:"php53-suhosin~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvmsg", rpm:"php53-sysvmsg~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvsem", rpm:"php53-sysvsem~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-sysvshm", rpm:"php53-sysvshm~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-tokenizer", rpm:"php53-tokenizer~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-wddx", rpm:"php53-wddx~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlreader", rpm:"php53-xmlreader~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xmlwriter", rpm:"php53-xmlwriter~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-xsl", rpm:"php53-xsl~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-zip", rpm:"php53-zip~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php53-zlib", rpm:"php53-zlib~5.3.17~0.31.1", rls:"SLES11.0SP3"))) {
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

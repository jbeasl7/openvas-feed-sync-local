# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856613");
  script_cve_id("CVE-2024-8925", "CVE-2024-8927", "CVE-2024-9026");
  script_tag(name:"creation_date", value:"2024-10-19 04:00:43 +0000 (Sat, 19 Oct 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 18:28:34 +0000 (Wed, 16 Oct 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3733-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3733-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243733-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231382");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-October/019658.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7' package(s) announced via the SUSE-SU-2024:3733-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php7 fixes the following issues:

- CVE-2024-8925: Fixed erroneous parsing of multipart form data in HTTP POST requests leads to legitimate data not being processed (bsc#1231360)
- CVE-2024-8927: Fixed cgi.force_redirect configuration is bypassable due to an environment variable collision (bsc#1231358)
- CVE-2024-9026: Fixed pollution of worker output logs in PHP-FPM (bsc#1231382)");

  script_tag(name:"affected", value:"'php7' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php7", rpm:"apache2-mod_php7~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7", rpm:"php7~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bcmath", rpm:"php7-bcmath~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bz2", rpm:"php7-bz2~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-calendar", rpm:"php7-calendar~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-cli", rpm:"php7-cli~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ctype", rpm:"php7-ctype~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-curl", rpm:"php7-curl~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dba", rpm:"php7-dba~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-devel", rpm:"php7-devel~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dom", rpm:"php7-dom~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-embed", rpm:"php7-embed~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-enchant", rpm:"php7-enchant~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-exif", rpm:"php7-exif~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fastcgi", rpm:"php7-fastcgi~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fileinfo", rpm:"php7-fileinfo~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fpm", rpm:"php7-fpm~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ftp", rpm:"php7-ftp~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gd", rpm:"php7-gd~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gettext", rpm:"php7-gettext~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gmp", rpm:"php7-gmp~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-iconv", rpm:"php7-iconv~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-intl", rpm:"php7-intl~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-json", rpm:"php7-json~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ldap", rpm:"php7-ldap~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mbstring", rpm:"php7-mbstring~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mysql", rpm:"php7-mysql~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-odbc", rpm:"php7-odbc~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-opcache", rpm:"php7-opcache~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-openssl", rpm:"php7-openssl~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pcntl", rpm:"php7-pcntl~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pdo", rpm:"php7-pdo~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pgsql", rpm:"php7-pgsql~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-phar", rpm:"php7-phar~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-posix", rpm:"php7-posix~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-readline", rpm:"php7-readline~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-shmop", rpm:"php7-shmop~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-snmp", rpm:"php7-snmp~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-soap", rpm:"php7-soap~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sockets", rpm:"php7-sockets~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sodium", rpm:"php7-sodium~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sqlite", rpm:"php7-sqlite~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvmsg", rpm:"php7-sysvmsg~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvsem", rpm:"php7-sysvsem~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvshm", rpm:"php7-sysvshm~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-test", rpm:"php7-test~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-tidy", rpm:"php7-tidy~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-tokenizer", rpm:"php7-tokenizer~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlreader", rpm:"php7-xmlreader~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlrpc", rpm:"php7-xmlrpc~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlwriter", rpm:"php7-xmlwriter~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xsl", rpm:"php7-xsl~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zip", rpm:"php7-zip~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zlib", rpm:"php7-zlib~7.4.33~150400.4.40.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php7", rpm:"apache2-mod_php7~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7", rpm:"php7~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bcmath", rpm:"php7-bcmath~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-bz2", rpm:"php7-bz2~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-calendar", rpm:"php7-calendar~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-cli", rpm:"php7-cli~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ctype", rpm:"php7-ctype~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-curl", rpm:"php7-curl~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dba", rpm:"php7-dba~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-devel", rpm:"php7-devel~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-dom", rpm:"php7-dom~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-embed", rpm:"php7-embed~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-enchant", rpm:"php7-enchant~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-exif", rpm:"php7-exif~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fastcgi", rpm:"php7-fastcgi~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fileinfo", rpm:"php7-fileinfo~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-fpm", rpm:"php7-fpm~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ftp", rpm:"php7-ftp~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gd", rpm:"php7-gd~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gettext", rpm:"php7-gettext~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-gmp", rpm:"php7-gmp~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-iconv", rpm:"php7-iconv~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-intl", rpm:"php7-intl~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-json", rpm:"php7-json~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-ldap", rpm:"php7-ldap~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mbstring", rpm:"php7-mbstring~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-mysql", rpm:"php7-mysql~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-odbc", rpm:"php7-odbc~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-opcache", rpm:"php7-opcache~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-openssl", rpm:"php7-openssl~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pcntl", rpm:"php7-pcntl~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pdo", rpm:"php7-pdo~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-pgsql", rpm:"php7-pgsql~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-phar", rpm:"php7-phar~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-posix", rpm:"php7-posix~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-readline", rpm:"php7-readline~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-shmop", rpm:"php7-shmop~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-snmp", rpm:"php7-snmp~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-soap", rpm:"php7-soap~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sockets", rpm:"php7-sockets~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sodium", rpm:"php7-sodium~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sqlite", rpm:"php7-sqlite~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvmsg", rpm:"php7-sysvmsg~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvsem", rpm:"php7-sysvsem~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-sysvshm", rpm:"php7-sysvshm~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-test", rpm:"php7-test~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-tidy", rpm:"php7-tidy~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-tokenizer", rpm:"php7-tokenizer~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlreader", rpm:"php7-xmlreader~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlrpc", rpm:"php7-xmlrpc~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xmlwriter", rpm:"php7-xmlwriter~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-xsl", rpm:"php7-xsl~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zip", rpm:"php7-zip~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php7-zlib", rpm:"php7-zlib~7.4.33~150400.4.40.1", rls:"openSUSELeap15.6"))) {
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

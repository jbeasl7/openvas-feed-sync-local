# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856587");
  script_cve_id("CVE-2024-8925", "CVE-2024-8927", "CVE-2024-9026");
  script_tag(name:"creation_date", value:"2024-10-17 04:01:32 +0000 (Thu, 17 Oct 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 18:28:34 +0000 (Wed, 16 Oct 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3664-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3664-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243664-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231382");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-October/037274.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php8' package(s) announced via the SUSE-SU-2024:3664-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php8 fixes the following issues:

- CVE-2024-8925: Fixed erroneous parsing of multipart form data in HTTP POST requests leads to legitimate data not being processed (bsc#1231360)
- CVE-2024-8927: Fixed cgi.force_redirect configuration is bypassable due to an environment variable collision (bsc#1231358)
- CVE-2024-9026: Fixed pollution of worker output logs in PHP-FPM (bsc#1231382)");

  script_tag(name:"affected", value:"'php8' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php8", rpm:"apache2-mod_php8~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8", rpm:"php8~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-bcmath", rpm:"php8-bcmath~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-bz2", rpm:"php8-bz2~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-calendar", rpm:"php8-calendar~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-cli", rpm:"php8-cli~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-ctype", rpm:"php8-ctype~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-curl", rpm:"php8-curl~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-dba", rpm:"php8-dba~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-devel", rpm:"php8-devel~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-dom", rpm:"php8-dom~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-embed", rpm:"php8-embed~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-enchant", rpm:"php8-enchant~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-exif", rpm:"php8-exif~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fastcgi", rpm:"php8-fastcgi~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fileinfo", rpm:"php8-fileinfo~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-fpm", rpm:"php8-fpm~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-ftp", rpm:"php8-ftp~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-gd", rpm:"php8-gd~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-gettext", rpm:"php8-gettext~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-gmp", rpm:"php8-gmp~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-iconv", rpm:"php8-iconv~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-intl", rpm:"php8-intl~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-ldap", rpm:"php8-ldap~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-mbstring", rpm:"php8-mbstring~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-mysql", rpm:"php8-mysql~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-odbc", rpm:"php8-odbc~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-opcache", rpm:"php8-opcache~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-openssl", rpm:"php8-openssl~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-pcntl", rpm:"php8-pcntl~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-pdo", rpm:"php8-pdo~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-pgsql", rpm:"php8-pgsql~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-phar", rpm:"php8-phar~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-posix", rpm:"php8-posix~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-readline", rpm:"php8-readline~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-shmop", rpm:"php8-shmop~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-snmp", rpm:"php8-snmp~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-soap", rpm:"php8-soap~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sockets", rpm:"php8-sockets~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sodium", rpm:"php8-sodium~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sqlite", rpm:"php8-sqlite~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sysvmsg", rpm:"php8-sysvmsg~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sysvsem", rpm:"php8-sysvsem~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-sysvshm", rpm:"php8-sysvshm~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-test", rpm:"php8-test~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-tidy", rpm:"php8-tidy~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-tokenizer", rpm:"php8-tokenizer~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-xmlreader", rpm:"php8-xmlreader~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-xmlwriter", rpm:"php8-xmlwriter~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-xsl", rpm:"php8-xsl~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-zip", rpm:"php8-zip~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-zlib", rpm:"php8-zlib~8.0.30~150400.4.46.1", rls:"openSUSELeap15.5"))) {
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

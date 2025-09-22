# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886756");
  script_cve_id("CVE-2022-31629", "CVE-2024-1874", "CVE-2024-2756", "CVE-2024-3096");
  script_tag(name:"creation_date", value:"2024-05-27 10:46:39 +0000 (Mon, 27 May 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:32:25 +0000 (Fri, 30 Sep 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2024-b46619f761)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-b46619f761");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-b46619f761");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275058");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275059");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275061");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275062");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/11808");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/12019");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13203");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13402");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13452");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13508");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13517");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13531");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13544");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13604");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13612");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13670");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13680");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13685");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13690");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13712");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13784");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-h746-cjrr-wfmr");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-pc52-254m-w9w7");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-wpj3-hf5j-x4v4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the FEDORA-2024-b46619f761 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**PHP version 8.2.18** (11 Apr 2024)

**Core:**

* Fixed bug [GH-13612]([link moved to references]) (Corrupted memory in destructor with weak references). (nielsdos)
* Fixed bug [GH-13784]([link moved to references]) (AX_GCC_FUNC_ATTRIBUTE failure). (Remi)
* Fixed bug [GH-13670]([link moved to references]) (GC does not scale well with a lot of objects created in destructor). (Arnaud)

**DOM:**

* Add some missing ZPP checks. (nielsdos)
* Fix potential memory leak in XPath evaluation results. (nielsdos)
* Fix phpdoc for DOMDocument load methods. (VincentLanglet)

**FPM**

* Fix incorrect check in fpm_shm_free(). (nielsdos)

**GD:**

* Fixed bug [GH-12019]([link moved to references]) (add GDLIB_CFLAGS in feature tests). (Michael Orlitzky)

**Gettext:**

* Fixed sigabrt raised with dcgettext/dcngettext calls with gettext 0.22.5 with category set to LC_ALL. (David Carlier)

**MySQLnd:**

* Fix [GH-13452]([link moved to references]) (Fixed handshake response [mysqlnd]). (Saki Takamachi)
* Fix incorrect charset length in check_mb_eucjpms(). (nielsdos)

**Opcache:**

* Fixed [GH-13508]([link moved to references]) (JITed QM_ASSIGN may be optimized out when op1 is null). (Arnaud, Dmitry)
* Fixed [GH-13712]([link moved to references]) (Segmentation fault for enabled observers when calling trait method of internal trait when opcache is loaded). (Bob)

**PDO:**

* Fix various PDORow bugs. (Girgias)

**Random:**

* Fixed bug [GH-13544]([link moved to references]) (Pre-PHP 8.2 compatibility for mt_srand with unknown modes). (timwolla)
* Fixed bug [GH-13690]([link moved to references]) (Global Mt19937 is not properly reset in-between requests when MT_RAND_PHP is used). (timwolla)

**Session:**

* Fixed bug [GH-13680]([link moved to references]) (Segfault with session_decode and compilation error). (nielsdos)

**Sockets:**

* Fixed bug [GH-13604]([link moved to references]) (socket_getsockname returns random characters in the end of the socket name). (David Carlier)

**SPL:**

* Fixed bug [GH-13531]([link moved to references]) (Unable to resize SplfixedArray after being unserialized in PHP 8.2.15). (nielsdos)
* Fixed bug [GH-13685]([link moved to references]) (Unexpected null pointer in zend_string.h). (nielsdos)

**Standard:**

* Fixed bug [GH-11808]([link moved to references]) (Live filesystem modified by tests). (nielsdos)
* Fixed [GH-13402]([link moved to references]) (Added validation of `\n` in $additional_headers of mail()). (SakiTakamachi)
* Fixed bug [GH-13203]([link moved to references]) (file_put_contents fail on strings over 4GB on Windows). (divinity76)
* Fixed bug [GHSA-pc52-254m-w9w7]([link moved to references]) (Command injection via array-ish $command parameter of proc_open). (CVE-2024-1874) (Jakub Zelenka)
* Fixed bug [GHSA-wpj3-hf5j-x4v4]([link moved to references]) (__Host-/__Secure- cookie bypass due to partial CVE-2022-31629 fix). (**CVE-2024-2756**) (nielsdos)
* ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath-debuginfo", rpm:"php-bcmath-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli-debuginfo", rpm:"php-cli-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common", rpm:"php-common~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common-debuginfo", rpm:"php-common-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba-debuginfo", rpm:"php-dba-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg", rpm:"php-dbg~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg-debuginfo", rpm:"php-dbg-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debugsource", rpm:"php-debugsource~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded-debuginfo", rpm:"php-embedded-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant-debuginfo", rpm:"php-enchant-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi", rpm:"php-ffi~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi-debuginfo", rpm:"php-ffi-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm-debuginfo", rpm:"php-fpm-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd-debuginfo", rpm:"php-gd-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp", rpm:"php-gmp~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp-debuginfo", rpm:"php-gmp-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl-debuginfo", rpm:"php-intl-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap-debuginfo", rpm:"php-ldap-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring-debuginfo", rpm:"php-mbstring-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd-debuginfo", rpm:"php-mysqlnd-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc-debuginfo", rpm:"php-odbc-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache", rpm:"php-opcache~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache-debuginfo", rpm:"php-opcache-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib", rpm:"php-pdo-dblib~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib-debuginfo", rpm:"php-pdo-dblib-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-debuginfo", rpm:"php-pdo-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird", rpm:"php-pdo-firebird~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird-debuginfo", rpm:"php-pdo-firebird-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql-debuginfo", rpm:"php-pgsql-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process", rpm:"php-process~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process-debuginfo", rpm:"php-process-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell-debuginfo", rpm:"php-pspell-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp-debuginfo", rpm:"php-snmp-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap-debuginfo", rpm:"php-soap-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium", rpm:"php-sodium~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium-debuginfo", rpm:"php-sodium-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy-debuginfo", rpm:"php-tidy-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~8.2.18~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml-debuginfo", rpm:"php-xml-debuginfo~8.2.18~1.fc39", rls:"FC39"))) {
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

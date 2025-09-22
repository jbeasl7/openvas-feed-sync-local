# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887234");
  script_cve_id("CVE-2012-1823", "CVE-2024-1874", "CVE-2024-2408", "CVE-2024-4577", "CVE-2024-5458", "CVE-2024-5585");
  script_tag(name:"creation_date", value:"2024-06-13 04:07:03 +0000 (Thu, 13 Jun 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:48:42 +0000 (Tue, 16 Jul 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-52c23ef1ec)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-52c23ef1ec");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-52c23ef1ec");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2291252");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2291253");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/pull/13817");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/13970");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14100");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14109");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14124");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14140");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14175");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14183");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14189");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14215");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14255");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-9fcc-425m-g385");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-w8qr-v226-r27w");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the FEDORA-2024-52c23ef1ec advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**PHP version 8.2.20** (06 Jun 2024)

**CGI:**

* Fixed buffer limit on Windows, replacing read call usage by _read. (David Carlier)
* Fixed bug [GHSA-3qgc-jrrr-25jv]([link moved to references]) (Bypass of CVE-2012-1823, Argument Injection in PHP-CGI). (CVE-2024-4577) (nielsdos)

**CLI:**

* Fixed bug [GH-14189]([link moved to references]) (PHP Interactive shell input state incorrectly handles quoted heredoc literals.). (nielsdos)

**Core:**

* Fixed bug [GH-13970]([link moved to references]) (Incorrect validation of #[Attribute] flags type for non-compile-time expressions). (ilutov)
* Fixed bug [GH-14140]([link moved to references]) (Floating point bug in range operation on Apple Silicon hardware). (Derick, Saki)

**DOM:**

* Fix crashes when entity declaration is removed while still having entity references. (nielsdos)
* Fix references not handled correctly in C14N. (nielsdos)
* Fix crash when calling childNodes next() when iterator is exhausted. (nielsdos)
* Fix crash in ParentNode::append() when dealing with a fragment containing text nodes. (nielsdos)

**FFI:**

* Fixed bug [GH-14215]([link moved to references]) (Cannot use FFI::load on CRLF header file with apache2handler). (nielsdos)

**Filter:**

* Fixed bug [GHSA-w8qr-v226-r27w]([link moved to references]) (Filter bypass in filter_var FILTER_VALIDATE_URL). (**CVE-2024-5458**) (nielsdos)

**FPM:**

* Fix bug [GH-14175]([link moved to references]) (Show decimal number instead of scientific notation in systemd status). (Benjamin Cremer)

**Hash:**

* ext/hash: Swap the checking order of `__has_builtin` and `__GNUC__` (Saki Takamachi)

**Intl:**

* Fixed build regression on systems without C++17 compilers. (Calvin Buckley, Peter Kokot)

**Ini:**

* Fixed bug [GH-14100]([link moved to references]) (Corrected spelling mistake in php.ini files). (Marcus Xavier)

**MySQLnd:**

* Fix bug [GH-14255]([link moved to references]) (mysqli_fetch_assoc reports error from nested query). (Kamil Tekiela)

**Opcache:**

* Fixed bug [GH-14109]([link moved to references]) (Fix accidental persisting of internal class constant in shm). (ilutov)

**OpenSSL:**

* The openssl_private_decrypt function in PHP, when using PKCS1 padding (OPENSSL_PKCS1_PADDING, which is the default), is vulnerable to the Marvin Attack unless it is used with an OpenSSL version that includes the changes from this pull request: [link moved to references] (rsa_pkcs1_implicit_rejection). These changes are part of OpenSSL 3.2 and have also been backported to stable versions of various Linux distributions, as well as to the PHP builds provided for Windows since the previous release. All distributors and builders should ensure that this version is used to prevent PHP from being vulnerable. (**CVE-2024-2408**)

**Standard:**

* Fixed bug [GHSA-9fcc-425m-g385]([link moved to references]) (Bypass of CVE-2024-1874). (CVE-2024-5585) (nielsdos)

**XML:**

* Fixed bug ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath-debuginfo", rpm:"php-bcmath-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli-debuginfo", rpm:"php-cli-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common", rpm:"php-common~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common-debuginfo", rpm:"php-common-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba-debuginfo", rpm:"php-dba-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg", rpm:"php-dbg~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg-debuginfo", rpm:"php-dbg-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debugsource", rpm:"php-debugsource~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded-debuginfo", rpm:"php-embedded-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant-debuginfo", rpm:"php-enchant-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi", rpm:"php-ffi~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi-debuginfo", rpm:"php-ffi-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm-debuginfo", rpm:"php-fpm-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd-debuginfo", rpm:"php-gd-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp", rpm:"php-gmp~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp-debuginfo", rpm:"php-gmp-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl-debuginfo", rpm:"php-intl-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap-debuginfo", rpm:"php-ldap-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring-debuginfo", rpm:"php-mbstring-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd-debuginfo", rpm:"php-mysqlnd-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc-debuginfo", rpm:"php-odbc-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache", rpm:"php-opcache~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache-debuginfo", rpm:"php-opcache-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib", rpm:"php-pdo-dblib~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib-debuginfo", rpm:"php-pdo-dblib-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-debuginfo", rpm:"php-pdo-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird", rpm:"php-pdo-firebird~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird-debuginfo", rpm:"php-pdo-firebird-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql-debuginfo", rpm:"php-pgsql-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process", rpm:"php-process~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process-debuginfo", rpm:"php-process-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell-debuginfo", rpm:"php-pspell-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp-debuginfo", rpm:"php-snmp-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap-debuginfo", rpm:"php-soap-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium", rpm:"php-sodium~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium-debuginfo", rpm:"php-sodium-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy-debuginfo", rpm:"php-tidy-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~8.2.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml-debuginfo", rpm:"php-xml-debuginfo~8.2.20~1.fc39", rls:"FC39"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.41017101299401010");
  script_cve_id("CVE-2024-11235", "CVE-2025-1217", "CVE-2025-1219", "CVE-2025-1734", "CVE-2025-1736", "CVE-2025-1861");
  script_tag(name:"creation_date", value:"2025-03-21 04:05:21 +0000 (Fri, 21 Mar 2025)");
  script_version("2025-07-03T05:42:53+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:53 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-02 20:17:38 +0000 (Wed, 02 Jul 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-4e7e2c40e0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-4e7e2c40e0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-4e7e2c40e0");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15902");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17387");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17398");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17503");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17577");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17618");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17623");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17643");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17650");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17654");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17704");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17718");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17745");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17772");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17797");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17808");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17837");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17847");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17868");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/17899");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-52jp-hrpf-2jff");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-hgf54-96fm-v528");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-p3x9-6h7p-cgfc");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-pcmh-g36c-qc44");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-rwp7-7vc6-8477");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-v8xr-gpvj-cx9g");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-wg4p-4hqh-c3g9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the FEDORA-2025-4e7e2c40e0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**PHP version 8.3.19** (13 Mar 2025)

**BCMath:**

* Fixed bug [GH-17398]([link moved to references]) (bcmul memory leak). (SakiTakamachi)

**Core:**

* Fixed bug [GH-17623]([link moved to references]) (Broken stack overflow detection for variable compilation). (ilutov)
* Fixed bug [GH-17618]([link moved to references]) (UnhandledMatchError does not take zend.exception_ignore_args=1 into account). (timwolla)
* Fix fallback paths in fast_long_{add,sub}_function. (nielsdos)
* Fixed bug [GH-17718]([link moved to references]) (Calling static methods on an interface that has `__callStatic` is allowed). (timwolla)
* Fixed bug [GH-17797]([link moved to references]) (zend_test_compile_string crash on invalid script path). (David Carlier)
* Fixed [GHSA-rwp7-7vc6-8477]([link moved to references]) (Reference counting in php_request_shutdown causes Use-After-Free). (**CVE-2024-11235**) (ilutov)

**DOM:**

* Fixed bug [GH-17847]([link moved to references]) (xinclude destroys live node). (nielsdos)

**FFI:**

* Fix FFI Parsing of Pointer Declaration Lists. (davnotdev)

**FPM:**

* Fixed bug [GH-17643]([link moved to references]) (FPM with httpd ProxyPass encoded PATH_INFO env). (Jakub Zelenka)

**GD:**

* Fixed bug [GH-17772]([link moved to references]) (imagepalettetotruecolor crash with memory_limit=2M). (David Carlier)

**LDAP:**

* Fixed bug [GH-17704]([link moved to references]) (ldap_search fails when $attributes contains a non-packed array with numerical keys). (nielsdos, 7u83)

**LibXML:**

* Fixed [GHSA-wg4p-4hqh-c3g9]([link moved to references]) (Reocurrence of php#72714). (nielsdos)
* Fixed [GHSA-p3x9-6h7p-cgfc]([link moved to references]) (libxml streams use wrong `content-type` header when requesting a redirected resource). (**CVE-2025-1219**) (timwolla)

**MBString:**

* Fixed bug [GH-17503]([link moved to references]) (Undefined float conversion in mb_convert_variables). (cmb)

**Opcache:**

* Fixed bug [GH-17654]([link moved to references]) (Multiple classes using same trait causes function JIT crash). (nielsdos)
* Fixed bug [GH-17577]([link moved to references]) (JIT packed type guard crash). (nielsdos, Dmitry)
* Fixed bug [GH-17899]([link moved to references]) (zend_test_compile_string with invalid path when opcache is enabled). (David Carlier)
* Fixed bug [GH-17868]([link moved to references]) (Cannot allocate memory with tracing JIT). (nielsdos)

**PDO_SQLite:**

* Fixed [GH-17837]([link moved to references]) ()::getColumnMeta() on unexecuted statement segfaults). (cmb)
* Fix cycle leak in sqlite3 setAuthorizer(). (nielsdos)

**Phar:**

* Fixed bug [GH-17808]([link moved to references]): PharFileInfo refcount bug. (nielsdos)

**PHPDBG:**

* Partially fixed bug [GH-17387]([link moved to references]) (Trivial crash in phpdbg lexer). (nielsdos)
* Fix memory leak in phpdbg calling registered function. (nielsdos)

**Reflection:**

* Fixed bug [GH-15902]([link moved to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath-debuginfo", rpm:"php-bcmath-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli-debuginfo", rpm:"php-cli-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common", rpm:"php-common~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common-debuginfo", rpm:"php-common-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba-debuginfo", rpm:"php-dba-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg", rpm:"php-dbg~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg-debuginfo", rpm:"php-dbg-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debugsource", rpm:"php-debugsource~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded-debuginfo", rpm:"php-embedded-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant-debuginfo", rpm:"php-enchant-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi", rpm:"php-ffi~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi-debuginfo", rpm:"php-ffi-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm-debuginfo", rpm:"php-fpm-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd-debuginfo", rpm:"php-gd-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp", rpm:"php-gmp~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp-debuginfo", rpm:"php-gmp-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl-debuginfo", rpm:"php-intl-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap-debuginfo", rpm:"php-ldap-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring-debuginfo", rpm:"php-mbstring-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd-debuginfo", rpm:"php-mysqlnd-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc-debuginfo", rpm:"php-odbc-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache", rpm:"php-opcache~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache-debuginfo", rpm:"php-opcache-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib", rpm:"php-pdo-dblib~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib-debuginfo", rpm:"php-pdo-dblib-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-debuginfo", rpm:"php-pdo-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird", rpm:"php-pdo-firebird~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird-debuginfo", rpm:"php-pdo-firebird-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql-debuginfo", rpm:"php-pgsql-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process", rpm:"php-process~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process-debuginfo", rpm:"php-process-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell-debuginfo", rpm:"php-pspell-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp-debuginfo", rpm:"php-snmp-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap-debuginfo", rpm:"php-soap-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium", rpm:"php-sodium~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium-debuginfo", rpm:"php-sodium-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy-debuginfo", rpm:"php-tidy-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~8.3.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml-debuginfo", rpm:"php-xml-debuginfo~8.3.19~1.fc40", rls:"FC40"))) {
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

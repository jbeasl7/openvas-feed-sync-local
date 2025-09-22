# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.10101003901003598");
  script_cve_id("CVE-2024-11233", "CVE-2024-11234", "CVE-2024-11236", "CVE-2024-8929", "CVE-2024-8932");
  script_tag(name:"creation_date", value:"2024-11-28 04:08:44 +0000 (Thu, 28 Nov 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-24 01:15:04 +0000 (Sun, 24 Nov 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-e0d390d35b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e0d390d35b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-e0d390d35b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328035");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328614");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328673");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328738");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14687");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/14732");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16168");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16174");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16290");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16292");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16293");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16302");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16316");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16318");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16326");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16334");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16336");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16337");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16338");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16357");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16361");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16371");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16373");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16385");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16390");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16397");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16406");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16408");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16409");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16411");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16427");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16429");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16433");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16450");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16454");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16464");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16473");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16477");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16478");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16479");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16501");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16508");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16509");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16515");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16523");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16533");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16535");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16559");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16588");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16589");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16591");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16592");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16593");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16595");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16601");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16604");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16628");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16646");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/16648");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-4w77-75f9-2c8w");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-5hqh-c84r-qjcv");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-c5f2-jwm7-mmq2");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-g665-fm4p-vhff");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-h35g-vwh6-m678");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-r977-prxv-hc43");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the FEDORA-2024-e0d390d35b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**PHP version 8.3.14** (21 Nov 2024)

**CLI:**

* Fixed bug [GH-16373]([link moved to references]) (Shebang is not skipped for router script in cli-server started through shebang). (ilutov)
* Fixed bug [GHSA-4w77-75f9-2c8w]([link moved to references]) (Heap-Use-After-Free in sapi_read_post_data Processing in CLI SAPI Interface). (nielsdos)

**COM:**

* Fixed out of bound writes to SafeArray data. (cmb)

**Core:**

* Fixed bug [GH-16168]([link moved to references]) (php 8.1 and earlier crash immediately when compiled with Xcode 16 clang on macOS 15). (nielsdos)
* Fixed bug [GH-16371]([link moved to references]) (Assertion failure in Zend/zend_weakrefs.c:646). (Arnaud)
* Fixed bug [GH-16515]([link moved to references]) (Incorrect propagation of ZEND_ACC_RETURN_REFERENCE for call trampoline). (ilutov)
* Fixed bug [GH-16509]([link moved to references]) (Incorrect line number in function redeclaration error). (ilutov)
* Fixed bug [GH-16508]([link moved to references]) (Incorrect line number in inheritance errors of delayed early bound classes). (ilutov)
* Fixed bug [GH-16648]([link moved to references]) (Use-after-free during array sorting). (ilutov)

**Curl:**

* Fixed bug [GH-16302]([link moved to references]) (CurlMultiHandle holds a reference to CurlHandle if curl_multi_add_handle fails). (timwolla)

**Date:**

* Fixed bug [GH-16454]([link moved to references]) (Unhandled INF in date_sunset() with tiny $utcOffset). (cmb)
* Fixed bug [GH-14732]([link moved to references]) (date_sun_info() fails for non-finite values). (cmb)

**DBA:**

* Fixed bug [GH-16390]([link moved to references]) (dba_open() can segfault for 'pathless' streams). (cmb)

**DOM:**

* Fixed bug [GH-16316]([link moved to references]) (DOMXPath breaks when not initialized properly). (nielsdos)
* Add missing hierarchy checks to replaceChild. (nielsdos)
* Fixed bug [GH-16336]([link moved to references]) (Attribute intern document mismanagement). (nielsdos)
* Fixed bug [GH-16338]([link moved to references]) (Null-dereference in ext/dom/node.c). (nielsdos)
* Fixed bug [GH-16473]([link moved to references]) (dom_import_simplexml stub is wrong). (nielsdos)
* Fixed bug [GH-16533]([link moved to references]) (Segfault when adding attribute to parent that is not an element). (nielsdos)
* Fixed bug [GH-16535]([link moved to references]) (UAF when using document as a child). (nielsdos)
* Fixed bug [GH-16593]([link moved to references]) (Assertion failure in DOM->replaceChild). (nielsdos)
* Fixed bug [GH-16595]([link moved to references]) (Another UAF in DOM -> cloneNode). (nielsdos)

**EXIF:**

* Fixed bug [GH-16409]([link moved to references]) (Segfault in exif_thumbnail when not dealing with a real file). (nielsdos, cmb)

**FFI:**

* Fixed bug [GH-16397]([link moved to references]) (Segmentation fault when comparing FFI object). (nielsdos)

**Filter:**

* Fixed bug [GH-16523]([link moved to references]) ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath-debuginfo", rpm:"php-bcmath-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli-debuginfo", rpm:"php-cli-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common", rpm:"php-common~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common-debuginfo", rpm:"php-common-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba-debuginfo", rpm:"php-dba-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg", rpm:"php-dbg~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg-debuginfo", rpm:"php-dbg-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debugsource", rpm:"php-debugsource~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded-debuginfo", rpm:"php-embedded-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant-debuginfo", rpm:"php-enchant-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi", rpm:"php-ffi~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi-debuginfo", rpm:"php-ffi-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm-debuginfo", rpm:"php-fpm-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd-debuginfo", rpm:"php-gd-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp", rpm:"php-gmp~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp-debuginfo", rpm:"php-gmp-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl-debuginfo", rpm:"php-intl-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap-debuginfo", rpm:"php-ldap-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring-debuginfo", rpm:"php-mbstring-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd-debuginfo", rpm:"php-mysqlnd-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc-debuginfo", rpm:"php-odbc-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache", rpm:"php-opcache~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache-debuginfo", rpm:"php-opcache-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib", rpm:"php-pdo-dblib~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib-debuginfo", rpm:"php-pdo-dblib-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-debuginfo", rpm:"php-pdo-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird", rpm:"php-pdo-firebird~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird-debuginfo", rpm:"php-pdo-firebird-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql-debuginfo", rpm:"php-pgsql-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process", rpm:"php-process~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process-debuginfo", rpm:"php-process-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell-debuginfo", rpm:"php-pspell-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp-debuginfo", rpm:"php-snmp-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap-debuginfo", rpm:"php-soap-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium", rpm:"php-sodium~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium-debuginfo", rpm:"php-sodium-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy-debuginfo", rpm:"php-tidy-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~8.3.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml-debuginfo", rpm:"php-xml-debuginfo~8.3.14~1.fc40", rls:"FC40"))) {
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

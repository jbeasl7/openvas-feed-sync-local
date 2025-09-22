# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.7998009941001027");
  script_cve_id("CVE-2024-4577", "CVE-2024-8925", "CVE-2024-8926", "CVE-2024-8927", "CVE-2024-9026");
  script_tag(name:"creation_date", value:"2024-10-04 04:08:17 +0000 (Fri, 04 Oct 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-10 12:50:06 +0000 (Mon, 10 Jun 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-7c800c4df7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7c800c4df7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-7c800c4df7");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15330");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15408");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15432");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15514");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15515");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15547");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15551");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15552");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15565");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15587");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15628");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15658");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15661");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/15752");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-865w-9rf3-2wh5");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-94p6-54jq-9mwp");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-9pqp-7h25-4f32");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-p99j-rfp4-xqvq");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the FEDORA-2024-7c800c4df7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**PHP version 8.2.24** (26 Sep 2024)

**CGI:**

* Fixed bug [GHSA-p99j-rfp4-xqvq]([link moved to references]) (Bypass of CVE-2024-4577, Parameter Injection Vulnerability). (**CVE-2024-8926**) (nielsdos)
* Fixed bug [GHSA-94p6-54jq-9mwp]([link moved to references]) (cgi.force_redirect configuration is bypassable due to the environment variable collision). (**CVE-2024-8927**) (nielsdos)

**Core:**

* Fixed bug [GH-15408]([link moved to references]) (MSan false-positve on zend_max_execution_timer). (zeriyoshi)
* Fixed bug [GH-15515]([link moved to references]) (Configure error grep illegal option q). (Peter Kokot)
* Fixed bug [GH-15514]([link moved to references]) (Configure error: genif.sh: syntax error). (Peter Kokot)
* Fixed bug [GH-15565]([link moved to references]) (--disable-ipv6 during compilation produces error EAI_SYSTEM not found). (nielsdos)
* Fixed bug [GH-15587]([link moved to references]) (CRC32 API build error on arm 32-bit). (Bernd Kuhls, Thomas Petazzoni)
* Fixed bug [GH-15330]([link moved to references]) (Do not scan generator frames more than once). (Arnaud)
* Fixed uninitialized lineno in constant AST of internal enums. (ilutov)

**Curl:**

* FIxed bug [GH-15547]([link moved to references]) (curl_multi_select overflow on timeout argument). (David Carlier)

**DOM:**

* Fixed bug [GH-15551]([link moved to references]) (Segmentation fault (access null pointer) in ext/dom/xml_common.h). (nielsdos)

**Fileinfo:**

* Fixed bug [GH-15752]([link moved to references]) (Incorrect error message for finfo_file with an empty filename argument). (DanielEScherzer)

**FPM:**

* Fixed bug [GHSA-865w-9rf3-2wh5]([link moved to references]) (Logs from childrens may be altered). (**CVE-2024-9026**) (Jakub Zelenka)

**MySQLnd:**

* Fixed bug [GH-15432]([link moved to references]) (Heap corruption when querying a vector). (cmb, Kamil Tekiela)

**Opcache:**

* Fixed bug [GH-15661]([link moved to references]) (Access null pointer in Zend/Optimizer/zend_inference.c). (nielsdos)
* Fixed bug [GH-15658]([link moved to references]) (Segmentation fault in Zend/zend_vm_execute.h). (nielsdos)

**SAPI:**

* Fixed bug [GHSA-9pqp-7h25-4f32]([link moved to references]) (Erroneous parsing of multipart form data). (**CVE-2024-8925**) (Arnaud)

**SOAP:**

* Fixed bug php#73182 (PHP SOAPClient does not support stream context HTTP headers in array form). (nielsdos)

**Standard:**

* Fixed bug [GH-15552]([link moved to references]) (Signed integer overflow in ext/standard/scanf.c). (cmb)

**Streams:**

* Fixed bug [GH-15628]([link moved to references]) (php_stream_memory_get_buffer() not zero-terminated). (cmb)");

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

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath-debuginfo", rpm:"php-bcmath-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli-debuginfo", rpm:"php-cli-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common", rpm:"php-common~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common-debuginfo", rpm:"php-common-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba-debuginfo", rpm:"php-dba-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg", rpm:"php-dbg~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg-debuginfo", rpm:"php-dbg-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debugsource", rpm:"php-debugsource~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded-debuginfo", rpm:"php-embedded-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant-debuginfo", rpm:"php-enchant-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi", rpm:"php-ffi~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi-debuginfo", rpm:"php-ffi-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm-debuginfo", rpm:"php-fpm-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd-debuginfo", rpm:"php-gd-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp", rpm:"php-gmp~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp-debuginfo", rpm:"php-gmp-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl-debuginfo", rpm:"php-intl-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap-debuginfo", rpm:"php-ldap-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring-debuginfo", rpm:"php-mbstring-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd-debuginfo", rpm:"php-mysqlnd-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc-debuginfo", rpm:"php-odbc-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache", rpm:"php-opcache~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache-debuginfo", rpm:"php-opcache-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib", rpm:"php-pdo-dblib~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib-debuginfo", rpm:"php-pdo-dblib-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-debuginfo", rpm:"php-pdo-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird", rpm:"php-pdo-firebird~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird-debuginfo", rpm:"php-pdo-firebird-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql-debuginfo", rpm:"php-pgsql-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process", rpm:"php-process~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process-debuginfo", rpm:"php-process-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pspell-debuginfo", rpm:"php-pspell-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp-debuginfo", rpm:"php-snmp-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap-debuginfo", rpm:"php-soap-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium", rpm:"php-sodium~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium-debuginfo", rpm:"php-sodium-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy-debuginfo", rpm:"php-tidy-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~8.2.24~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml-debuginfo", rpm:"php-xml-debuginfo~8.2.24~1.fc39", rls:"FC39"))) {
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

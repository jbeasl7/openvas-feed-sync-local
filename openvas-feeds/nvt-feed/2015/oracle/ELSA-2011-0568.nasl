# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122170");
  script_cve_id("CVE-2010-4647");
  script_tag(name:"creation_date", value:"2015-10-06 11:14:12 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2011-0568)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0568");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0568.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eclipse, eclipse-birt, eclipse-callgraph, eclipse-cdt, eclipse-changelog, eclipse-dtp, eclipse-emf, eclipse-gef, eclipse-linuxprofilingframework, eclipse-mylyn, eclipse-oprofile, eclipse-rse, eclipse-valgrind, icu4j, jetty-eclipse, objectweb-asm, sat4j' package(s) announced via the ELSA-2011-0568 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"eclipse:
[1:3.6.1-6.13]
- Drop patch to remove ant-trax (needed by test runs).

[1:3.6.1-6.12]
- Add two upstream patches to allow for running SDK JUnit tests.

[1:3.6.1-6.11]
- Bring in line with Fedora.
- Remove some stuff that is now done in eclipse-build.
- Fix sources URL.
- Add PDE dependency on zip for pdebuild script.
- Use new eclipse-build targets.
- Increase minimum required memory in eclipse.ini.

[1:3.6.1-6.10]
- Put ant.launching into JDT's dropins directory.

[1:3.6.1-6.9]
- Use apache-tomcat-apis JARs.
- Version objectweb-asm BR/R.

[1:3.6.1-6.8]
- Fix JSP API symlinks.

[1:3.6.1-6.7]
- Install o.e.jdt.junit.core in jdt (rhbz#663207).

[1:3.6.1-6]
- Add Eclipse help XSS vulnerability fix (RH Bz #661901).

[1:3.6.1-5]
- Remove work around for openjdk bug#647737 as openjdk has
 posted its own work around and will shortly be fixing problem
 correctly.

[1:3.6.1-4]
- Work around for openjdk bug#647737.

[1:3.6.1-3]
- Add missing Requires on tomcat5-jsp-api (bug#650145).

[1:3.6.1-2]
- Add prepare-build-dir.sh patch.

[1:3.6.1-1]
- Update to 3.6.1.

[1:3.6.0-3]
- Increasing min versions for jetty, icu4j-eclipse and sat4j.

[1:3.6.0-2]
- o.e.core.net.linux is no longer x86 only.

[1:3.6.0-1]
- Update to 3.6.0.
- Based on eclipse-build 0.6.1 RC0.

[1:3.5.2-10]
- Rebuild for new jetty.

[1:3.5.2-9]
- Fix typo in symlinking.

[1:3.5.2-8]
- No need to link jasper.

[1:3.5.2-7]
- Fix servlet and jsp apis symlinks.

[1:3.5.2-6]
- Fix jetty symlinks.

eclipse-birt:

[2.6.0-1.1]
- RHEL 6.1 rebase to Helios.

[2.6.0-1]
- Update to 2.6.0.
- Build rhino plugin as part of BIRT chart feature.
- Remove unnecessary dependencies.

eclipse-callgraph:

[0.6.1-1]
- Update to upstream 0.6.1 release.
- Add reasonable required dependency versions.

[0.6.0-2]
- Update tag to correct version

[0.6.0-1]
- Update to version 0.6 of Linux Tools Project.

[0.5.0-1]
- Resolves: #575108
- Rebase to Linux tools 0.5 release.

[0.4.0-2]
- Resolves: #553288
- Only support i686, x86_64 for RHEL6 and above.

[0.4.0-1]
- Update to version 0.4 of Linux Tools Project and remove tests feature

[0.0.1-3]
- Added ExcludeArch for ppc64 because eclipse-cdt is not present

[0.0.1-2]
- Some more changes to spec file

[0.0.1-1]
- Make minor changes to spec file

[0.0.1-1]
- Initial creation of eclipse-callgraph

eclipse-cdt:

[1:7.0.1-4]
- Resolves: #678364
- Modify a version of copy-platform so it does not add wild-cards
 when looking in the dropins folder.

[1:7.0.1-3]
- Resolves: #679543, #678364
- Fix libhover local patch to change location specifiers in glibc and
 libstdc++ plug-ins.
- Fix build so that it still works if eclipse-cdt-parsers is currently
 installed.

[1:7.0.1-2]
- Resolves: #622713
- Resolves: #668890
- Fix problems with applying autotools and libhover local patches

[1:7.0.1-1]
- Resolves: #656333
- Rebase to 7.0.1 (Helios SR1) including gdb hardware support fix
- Rebase to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'eclipse, eclipse-birt, eclipse-callgraph, eclipse-cdt, eclipse-changelog, eclipse-dtp, eclipse-emf, eclipse-gef, eclipse-linuxprofilingframework, eclipse-mylyn, eclipse-oprofile, eclipse-rse, eclipse-valgrind, icu4j, jetty-eclipse, objectweb-asm, sat4j' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"eclipse", rpm:"eclipse~3.6.1~6.13.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-birt", rpm:"eclipse-birt~2.6.0~1.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-callgraph", rpm:"eclipse-callgraph~0.6.1~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-cdt", rpm:"eclipse-cdt~7.0.1~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-cdt-parsers", rpm:"eclipse-cdt-parsers~7.0.1~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-cdt-sdk", rpm:"eclipse-cdt-sdk~7.0.1~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-changelog", rpm:"eclipse-changelog~2.7.0~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-dtp", rpm:"eclipse-dtp~1.8.1~1.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf", rpm:"eclipse-emf~2.6.0~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-examples", rpm:"eclipse-emf-examples~2.6.0~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-sdk", rpm:"eclipse-emf-sdk~2.6.0~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-xsd", rpm:"eclipse-emf-xsd~2.6.0~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-emf-xsd-sdk", rpm:"eclipse-emf-xsd-sdk~2.6.0~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-gef", rpm:"eclipse-gef~3.6.1~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-gef-examples", rpm:"eclipse-gef-examples~3.6.1~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-gef-sdk", rpm:"eclipse-gef-sdk~3.6.1~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-jdt", rpm:"eclipse-jdt~3.6.1~6.13.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-linuxprofilingframework", rpm:"eclipse-linuxprofilingframework~0.6.1~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-mylyn", rpm:"eclipse-mylyn~3.4.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-mylyn-cdt", rpm:"eclipse-mylyn-cdt~3.4.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-mylyn-java", rpm:"eclipse-mylyn-java~3.4.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-mylyn-pde", rpm:"eclipse-mylyn-pde~3.4.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-mylyn-trac", rpm:"eclipse-mylyn-trac~3.4.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-mylyn-webtasks", rpm:"eclipse-mylyn-webtasks~3.4.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-mylyn-wikitext", rpm:"eclipse-mylyn-wikitext~3.4.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-oprofile", rpm:"eclipse-oprofile~0.6.1~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-pde", rpm:"eclipse-pde~3.6.1~6.13.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-platform", rpm:"eclipse-platform~3.6.1~6.13.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-rcp", rpm:"eclipse-rcp~3.6.1~6.13.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-rse", rpm:"eclipse-rse~3.2~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-swt", rpm:"eclipse-swt~3.6.1~6.13.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eclipse-valgrind", rpm:"eclipse-valgrind~0.6.1~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu4j", rpm:"icu4j~4.2.1~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu4j-eclipse", rpm:"icu4j-eclipse~4.2.1~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu4j-javadoc", rpm:"icu4j-javadoc~4.2.1~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jetty-eclipse", rpm:"jetty-eclipse~6.1.24~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"objectweb-asm", rpm:"objectweb-asm~3.2~2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"objectweb-asm-javadoc", rpm:"objectweb-asm-javadoc~3.2~2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sat4j", rpm:"sat4j~2.2.0~4.0.el6", rls:"OracleLinux6"))) {
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

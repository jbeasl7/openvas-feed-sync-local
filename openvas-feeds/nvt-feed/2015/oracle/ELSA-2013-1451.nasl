# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123546");
  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5838", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:20 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1451)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1451");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1451.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk' package(s) announced via the ELSA-2013-1451 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.7.0.45-2.4.3.2.0.1.el6]
- Update DISTRO_NAME in specfile

[1.7.0.40-2.4.3.1.el6]
- sync with rhel 6.5 to icedtea 2.4 because of pernament tck failures
 - nss kept disabled
- Resolves: rhbz#1017626

[1.7.0.25-2.3.13.4.el6]
- added back patch408 tck20131015_5.patch, to resolve one of tck failures
- Resolves: rhbz#1017626

[1.7.0.25-2.3.13.3.el6]
- added back patch404 tck20131015_1.patch, to resolve one of tck failures
- added back patch405 tck20131015_2.patch, to resolve one of tck failures
- added back patch406 tck20131015_3.patch, to resolve one of tck failures (modified)
- added back patch407 tck20131015_4.patch, to resolve one of tck failures
- Resolves: rhbz#1017626

[1.7.0.25-2.3.13.2.el6]
- updated to newer security tarball of 2.3.13
- removed patch405 tck20131015_2.patch, no longer necessary to fix tck failures
- removed patch406 tck20131015_3.patch, no longer necessary to fix tck failures
- removed patch407 tck20131015_4.patch, no longer necessary to fix tck failures
- Resolves: rhbz#1017626

[1.7.0.25-2.3.13.1.el6]
- removed useless patch404 tck20131015_1.patch
- added patch405 tck20131015_2.patch, to resolve one of tck failures
- added patch406 tck20131015_3.patch, to resolve one of tck failures
- added patch407 tck20131015_4.patch, to resolve one of tck failures
- Resolves: rhbz#1017626

[1.7.0.25-2.3.13.0.el6]
- security update to 2.3.13
- adapted java-1.7.0-openjdk-disable-system-lcms.patch (and redeclared to 105)
- removed bootstrap
- fixed nss
- fixed buildver and updatever (Set to 25,30)
- moved to xz compression of sources
- all patches moved correctly to prep
- added patch404 tck20131015_1.patch, to resolve one of tck failures
- Resolves: rhbz#1017626");

  script_tag(name:"affected", value:"'java-1.7.0-openjdk' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.45~2.4.3.2.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.45~2.4.3.2.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.45~2.4.3.2.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.45~2.4.3.2.0.1.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.45~2.4.3.2.0.1.el6_4", rls:"OracleLinux6"))) {
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

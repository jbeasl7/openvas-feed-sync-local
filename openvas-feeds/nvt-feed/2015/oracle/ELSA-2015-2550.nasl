# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122794");
  script_cve_id("CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");
  script_tag(name:"creation_date", value:"2015-12-08 09:03:27 +0000 (Tue, 08 Dec 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-2550)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2550");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2550.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the ELSA-2015-2550 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.9.1-6.0.1.el7_1.2]
- Update doc/redhat.gif in tarball
- Add libxml2-oracle-enterprise.patch and update logos in tarball

[2.9.1-6.2]
- Fix a series of CVEs (rhbz#1286496)
- CVE-2015-7941 Stop parsing on entities boundaries errors
- CVE-2015-7941 Cleanup conditional section error handling
- CVE-2015-8317 Fail parsing early on if encoding conversion failed
- CVE-2015-7942 Another variation of overflow in Conditional sections
- CVE-2015-7942 Fix an error in previous Conditional section patch
- Fix parsing short unclosed comment uninitialized access
- CVE-2015-7498 Avoid processing entities after encoding conversion failures
- CVE-2015-7497 Avoid an heap buffer overflow in xmlDictComputeFastQKey
- CVE-2015-5312 Another entity expansion issue
- CVE-2015-7499 Add xmlHaltParser() to stop the parser
- CVE-2015-7499 Detect incoherency on GROW
- CVE-2015-7500 Fix memory access error due to incorrect entities boundaries
- CVE-2015-8242 Buffer overead with HTML parser in push mode
- CVE-2015-1819 Enforce the reader to run in constant memory

[2.9.1-6]
- Fix missing entities after CVE-2014-3660 fix
- CVE-2014-0191 Do not fetch external parameter entities (rhbz#1195650)
- Fix regressions introduced by CVE-2014-0191 patch

[2.9.1-5.1]
- CVE-2014-3660 denial of service via recursive entity expansion (rhbz#1149087)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.9.1~6.0.1.el7_2.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.1~6.0.1.el7_2.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.9.1~6.0.1.el7_2.2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-static", rpm:"libxml2-static~2.9.1~6.0.1.el7_2.2", rls:"OracleLinux7"))) {
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

# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123820");
  script_cve_id("CVE-2011-1202", "CVE-2011-3970", "CVE-2012-2825", "CVE-2012-2870", "CVE-2012-2871");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:59 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-1265)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1265");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1265.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxslt' package(s) announced via the ELSA-2012-1265 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.1.26-2.0.2.el6_3.1]
- Increment release to avoid ULN conflict with previous release.

[1.1.26-2.0.1.el6_3.1]
- Added libxslt-oracle-enterprise.patch and replaced doc/redhat.gif in tarball

[1.1.26-2.el6_3.1]
- fixes CVE-2011-1202 CVE-2011-3970 CVE-2012-2825 CVE-2012-2871 CVE-2012-2870
- Fix direct pattern matching bug
- Fix popping of vars in xsltCompilerNodePop
- Fix bug 602515
- Fix generate-id() to not expose object addresses (CVE-2011-1202)
- Fix some case of pattern parsing errors (CVE-2011-3970)
- Fix a bug in selecting XSLT elements (CVE-2012-2825)
- Fix portability to upcoming libxml2-2.9.0
- Fix default template processing on namespace nodes (CVE-2012-2871)
- Cleanup of the pattern compilation code (CVE-2012-2870)
- Hardening of code checking node types in various entry point (CVE-2012-2870)
- Hardening of code checking node types in EXSLT (CVE-2012-2870)
- Fix system-property with unknown namespace
- Xsltproc should return an error code if xinclude fails
- Fix a dictionary string usage
- Avoid a heap use after free error");

  script_tag(name:"affected", value:"'libxslt' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.17~4.0.1.el5_8.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.17~4.0.1.el5_8.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-python", rpm:"libxslt-python~1.1.17~4.0.1.el5_8.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.26~2.0.2.el6_3.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.26~2.0.2.el6_3.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-python", rpm:"libxslt-python~1.1.26~2.0.2.el6_3.1", rls:"OracleLinux6"))) {
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

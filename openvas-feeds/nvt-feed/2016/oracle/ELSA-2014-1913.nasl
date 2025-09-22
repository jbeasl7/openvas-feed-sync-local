# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122872");
  script_cve_id("CVE-2014-4975", "CVE-2014-8080", "CVE-2014-8090");
  script_tag(name:"creation_date", value:"2016-02-05 12:01:41 +0000 (Fri, 05 Feb 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1913)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1913");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1913.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby193-ruby' package(s) announced via the ELSA-2014-1913 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.9.3.484-50.0.1]
- fix build issue: self test report 'dh key to small'

[1.9.3.484-50]
- Fix off-by-one stack-based buffer overflow in the encodes() function
 (CVE-2014-4975).
 Related: rhbz#1164004
- Fix REXML billion laughs attack via parameter entity expansion
 (CVE-2014-8080).
 Related: rhbz#1164004
- REXML incomplete fix for CVE-2014-8080 (CVE-2014-8090).
 Related: rhbz#1164004");

  script_tag(name:"affected", value:"'ruby193-ruby' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby193-ruby", rpm:"ruby193-ruby~1.9.3.484~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-ruby-devel", rpm:"ruby193-ruby-devel~1.9.3.484~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-ruby-doc", rpm:"ruby193-ruby-doc~1.9.3.484~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-ruby-irb", rpm:"ruby193-ruby-irb~1.9.3.484~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-ruby-libs", rpm:"ruby193-ruby-libs~1.9.3.484~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-ruby-tcltk", rpm:"ruby193-ruby-tcltk~1.9.3.484~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-rubygem-bigdecimal", rpm:"ruby193-rubygem-bigdecimal~1.1.0~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-rubygem-io-console", rpm:"ruby193-rubygem-io-console~0.3~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-rubygem-json", rpm:"ruby193-rubygem-json~1.5.5~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-rubygem-minitest", rpm:"ruby193-rubygem-minitest~2.5.1~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-rubygem-rake", rpm:"ruby193-rubygem-rake~0.9.2.2~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-rubygem-rdoc", rpm:"ruby193-rubygem-rdoc~3.9.5~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-rubygems", rpm:"ruby193-rubygems~1.8.23~50.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby193-rubygems-devel", rpm:"ruby193-rubygems-devel~1.8.23~50.0.1.el6", rls:"OracleLinux6"))) {
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

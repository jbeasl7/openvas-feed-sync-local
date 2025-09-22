# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123967");
  script_cve_id("CVE-2011-1526");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:57 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0306)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0306");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0306.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the ELSA-2012-0306 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.6.1-70.el5]
- add upstream patch for telnetd buffer overflow (CVE-2011-4862, #770351)

[1.6.1-69.el5]
- ftp: fix a static analysis should-never-happen NULL dereference (#750823)

[1.6.1-68.el5]
- backport fixes to teach libkrb5 to use descriptors higher than FD_SETSIZE
 to talk to a KDC by using poll() if it's detected at compile-time, revised
 (#701444, RT#6905)

[1.6.1-67.el5]
- add backported patch by way of jbarbuc to free subkeys created by the
 KDC while processing TGS requests (#708516)

[1.6.1-66.el5]
- add backported patch by way of several people to better avoid false
 detection of replay attacks when talking to systems with coarse time
 resolution (#713500)

[1.6.1-65.el5]
- ftpd: add backported patch to check for errors when calling setegid
 (MITKRB5-SA-2011-005, CVE-2011-1526, #719098)

[1.6.1-64.el5]
- klist: don't trip over referral entries when invoked with -s (#729067,
 RT#6915)");

  script_tag(name:"affected", value:"'krb5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.1~70.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.1~70.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.1~70.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.1~70.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.6.1~70.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.1~70.el5", rls:"OracleLinux5"))) {
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

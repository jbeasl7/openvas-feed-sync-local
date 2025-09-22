# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122250");
  script_cve_id("CVE-2010-1322", "CVE-2010-1323", "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4022", "CVE-2011-0281", "CVE-2011-0282");
  script_tag(name:"creation_date", value:"2015-10-06 11:15:28 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 15:46:00 +0000 (Tue, 21 Jan 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-0200)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0200");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0200.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the ELSA-2011-0200 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.8.2-3.4]
- add upstream patches to fix standalone kpropd exiting if the per-client
 child process exits with an error, and hang or crash in the KDC when using
 the LDAP kdb backend (CVE-2010-4022, CVE-2011-0281, CVE-2011-0282, #671101)

[1.8.2-3.3]
- pull up crypto changes made between 1.8.2 and 1.8.3 to fix upstream #6751,
 assumed to already be there for the next fix
- incorporate candidate patch to fix various issues from MITKRB5-SA-2010-007
 (CVE-2010-1323, CVE-2010-1324, CVE-2010-4020, #651962)

[1.8.2-3.2]
- fix reading of keyUsage extensions when attempting to select pkinit client
 certs (part of #644825, RT#6775)
- fix selection of pkinit client certs when one or more don't include a
 subjectAltName extension (part of #644825, RT#6774)

[1.8.2-3.1]
- incorporate candidate patch to fix uninitialized pointer crash in the KDC
 (CVE-2010-1322, #636336)");

  script_tag(name:"affected", value:"'krb5' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.8.2~3.el6_0.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.8.2~3.el6_0.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.8.2~3.el6_0.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.8.2~3.el6_0.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.8.2~3.el6_0.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.8.2~3.el6_0.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.8.2~3.el6_0.4", rls:"OracleLinux6"))) {
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

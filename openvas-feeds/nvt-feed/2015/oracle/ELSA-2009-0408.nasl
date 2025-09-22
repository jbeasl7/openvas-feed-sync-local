# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122498");
  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846");
  script_tag(name:"creation_date", value:"2015-10-08 11:46:44 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-0408)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-0408");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-0408.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the ELSA-2009-0408 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.6.1-31.el5_3.3]
- update to revised patch for CVE-2009-0844/CVE-2009-0845

[1.6.1-31.el5_3.2]
- add fix for potential buffer read overrun in the SPNEGO GSSAPI mechanism
 (#490635, CVE-2009-0844)
- add fix for NULL pointer dereference when handling certain error cases
 in the SPNEGO GSSAPI mechanism (#490635, CVE-2009-0845)
- add fix for attempt to free uninitialized pointer in the ASN.1 decoder
 (#490635, CVE-2009-0846)
- add fix for bug in length validation in the ASN.1 decoder (CVE-2009-0847)

[1.6.1-31.el5_3.1]
- add backport of svn patch to fix a bug in how the gssapi library
 handles certain error cases in gss_accept_sec_context (CVE-2009-0845,");

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

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.1~31.el5_3.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.1~31.el5_3.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.1~31.el5_3.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.1~31.el5_3.3", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.1~31.el5_3.3", rls:"OracleLinux5"))) {
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

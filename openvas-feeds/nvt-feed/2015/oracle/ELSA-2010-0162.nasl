# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122381");
  script_cve_id("CVE-2009-3245", "CVE-2009-3555", "CVE-2010-0433");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:52 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0162)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0162");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0162.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the ELSA-2010-0162 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.9.8e-12.6]
- fix CVE-2009-3245 - add missing bn_wexpand return checks (#570924)

[0.9.8e-12.5]
- fix CVE-2010-0433 - do not pass NULL princ to krb5_kt_get_entry which
 in the RHEL-5 and newer versions will crash in such case (#569774)

[0.9.8e-12.4]
- do not disable SSLv2 in the renegotiation patch - SSLv2 does
 not support renegotiation
- allow unsafe renegotiation on clients with SSL_OP_LEGACY_SERVER_CONNECT

[0.9.8e-12.3]
- mention the RFC5746 in the CVE-2009-3555 doc

[0.9.8e-12.2]
- fix CVE-2009-3555 - support the safe renegotiation extension and
 do not allow legacy renegotiation on the server by default (#533125)");

  script_tag(name:"affected", value:"'openssl' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~12.el5_4.6", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~12.el5_4.6", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~12.el5_4.6", rls:"OracleLinux5"))) {
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

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122888");
  script_tag(name:"creation_date", value:"2016-03-02 04:56:05 +0000 (Wed, 02 Mar 2016)");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2019-02-20 16:59:00 +0000 (Wed, 20 Feb 2019)");

  script_name("Oracle: Security Advisory (ELSA-2016-3523)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-3523");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-3523.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the ELSA-2016-3523 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.0.1e-51.4]
- fix CVE-2016-0702 - side channel attack on modular exponentiation
- fix CVE-2016-0705 - double-free in DSA private key parsing
- fix CVE-2016-0797 - heap corruption in BN_hex2bn and BN_dec2bn

[1.0.1e-51.3]
- fix CVE-2015-3197 - SSLv2 ciphersuite enforcement
- disable SSLv2 in the generic TLS method

[1.0.1e-51.2]
- fix CVE-2015-7575 - disallow use of MD5 in TLS1.2

[1.0.1e-51.1]
- fix CVE-2015-3194 - certificate verify crash with missing PSS parameter
- fix CVE-2015-3195 - X509_ATTRIBUTE memory leak
- fix CVE-2015-3196 - race condition when handling PSK identity hint");

  script_tag(name:"affected", value:"'openssl' package(s) on Oracle Linux 6, Oracle Linux 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package_unreliable");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~42.ksplice1.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~42.ksplice1.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~42.ksplice1.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~42.ksplice1.el6_7.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~51.ksplice1.el7_2.4", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~51.ksplice1.el7_2.4", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-libs", rpm:"openssl-libs~1.0.1e~51.ksplice1.el7_2.4", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~51.ksplice1.el7_2.4", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~51.ksplice1.el7_2.4", rls:"OracleLinux7"))) {
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

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122889");
  script_cve_id("CVE-2015-3197", "CVE-2016-0797", "CVE-2016-0800");
  script_tag(name:"creation_date", value:"2016-03-02 04:56:06 +0000 (Wed, 02 Mar 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:21:00 +0000 (Tue, 16 Aug 2022)");

  script_name("Oracle: Security Advisory (ELSA-2016-0302)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0302");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0302.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the ELSA-2016-0302 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.9.8e-39.0.1]
- To disable SSLv2 client connections create the file
 /etc/sysconfig/openssl-ssl-client-kill-sslv2 (John Haxby) [orabug 21673934]
- Backport openssl 08-Jan-2015 security fixes (John Haxby) [orabug 20409893]
- fix CVE-2014-3570 - Bignum squaring may produce incorrect results
- fix CVE-2014-3571 - DTLS segmentation fault in dtls1_get_record
- fix CVE-2014-3572 - ECDHE silently downgrades to ECDH [Client]

[0.9.8e-39]
- fix CVE-2016-0797 - heap corruption in BN_hex2bn and BN_dec2bn

[0.9.8e-38]
- fix CVE-2015-3197 - SSLv2 ciphersuite enforcement
- disable SSLv2 in the generic TLS method (can be re-enabled
 by setting environment variable OPENSSL_ENABLE_SSL2)");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~39.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~39.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~39.0.1.el5_11", rls:"OracleLinux5"))) {
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

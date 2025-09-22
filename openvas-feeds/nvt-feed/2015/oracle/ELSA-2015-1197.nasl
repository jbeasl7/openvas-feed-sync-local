# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123086");
  script_cve_id("CVE-2015-1789", "CVE-2015-1790", "CVE-2015-4000");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:12 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-15 02:29:00 +0000 (Wed, 15 Nov 2017)");

  script_name("Oracle: Security Advisory (ELSA-2015-1197)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1197");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1197.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the ELSA-2015-1197 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.9.8e-36.0.1]
- Backport openssl 08-Jan-2015 security fixes (John Haxby) [orabug 20409893]
- fix CVE-2014-3570 - Bignum squaring may produce incorrect results
- fix CVE-2014-3571 - DTLS segmentation fault in dtls1_get_record
- fix CVE-2014-3572 - ECDHE silently downgrades to ECDH [Client]

[0.9.8e-36]
- also change the default DH parameters in s_server to 1024 bits

[0.9.8e-35]
- fix CVE-2015-1789 - out-of-bounds read in X509_cmp_time
- fix CVE-2015-1790 - PKCS7 crash with missing EncryptedContent
- fix CVE-2015-4000 - prevent the logjam attack on client - restrict
 the DH key size to at least 768 bits (limit will be increased in future)");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~36.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~36.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~36.0.1.el5_11", rls:"OracleLinux5"))) {
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

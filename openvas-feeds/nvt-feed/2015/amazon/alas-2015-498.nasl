# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120164");
  script_cve_id("CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0293");
  script_tag(name:"creation_date", value:"2015-09-08 11:18:57 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-498)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-498");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-498.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the ALAS-2015-498 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free flaw was found in the way OpenSSL importrf certain Elliptic Curve private keys. An attacker could use this flaw to crash OpenSSL, if a specially-crafted certificate was imported. (CVE-2015-0209)

A denial of service flaw was found in the way OpenSSL handled certain SSLv2 messages. A malicious client could send a specially crafted SSLv2 CLIENT-MASTER-KEY message that would cause an OpenSSL server that both supports SSLv2 and enables EXPORT-grade cipher suites to crash. (CVE-2015-0293)

An out-of-bounds write flaw was found in the way OpenSSL reused certain ASN.1 structures. A remote attacker could use a specially crafted ASN.1 structure that, when parsed by an application, would cause that application to crash. (CVE-2015-0287)

A flaw was found in the ASN (Abstract Syntax Notation) parsing code of OpenSSL. An attacker could present a specially crafted certificate, which when verified by an OpenSSL client or server could cause it to crash. (CVE-2015-0286)

A null-pointer dereference was found in the way OpenSSL handled certain PKCS#7 blobs. An attacker could cause OpenSSL to crash, when applications verify, decrypt or parsed these ASN.1 encoded PKCS#7 blobs. OpenSSL clients and servers are not affected. (CVE-2015-0289)

A NULL pointer dereference flaw was found in OpenSSL's x509 certificate handling implementation. A remote attacker could use this flaw to crash an OpenSSL server using an invalid certificate key. (CVE-2015-0288)");

  script_tag(name:"affected", value:"'openssl' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1k~1.84.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1k~1.84.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1k~1.84.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1k~1.84.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1k~1.84.amzn1", rls:"AMAZON"))) {
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

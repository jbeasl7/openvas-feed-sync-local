# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120033");
  script_cve_id("CVE-2014-8176", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-3216", "CVE-2015-4000");
  script_tag(name:"creation_date", value:"2015-09-08 11:15:46 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:29:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-550)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-550");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-550.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the ALAS-2015-550 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LOGJAM: A flaw was found in the way the TLS protocol composes the Diffie-Hellman exchange (for both export and non-export grade cipher suites). An attacker could use this flaw to downgrade a DHE connection to use export-grade key sizes, which could then be broken by sufficient pre-computation. This can lead to a passive man-in-the-middle attack in which the attacker is able to decrypt all traffic. (CVE-2015-4000)

An out-of-bounds read flaw was found in the X509_cmp_time() function of OpenSSL, which is used to test the expiry dates of SSL/TLS certificates. An attacker could possibly use a specially-crafted SSL/TLS certificate or CRL (Certificate Revocation List), which when parsed by an application would cause that application to crash. (CVE-2015-1789)

A NULL pointer dereference was found in the way OpenSSL handled certain PKCS#7 inputs. An attacker able to make an application using OpenSSL verify, decrypt, or parse a specially crafted PKCS#7 input could cause that application to crash. TLS/SSL clients and servers using OpenSSL were not affected by this flaw. (CVE-2015-1790)

A race condition was found in the session handling code of OpenSSL. An attacker could cause a multi-threaded SSL/TLS server to crash. (CVE-2015-1791)

A denial of service flaw was found in OpenSSL in the way it verified certain signed messages using CMS (Cryptographic Message Syntax). A remote attacker could cause an application using OpenSSL to use excessive amounts of memory by sending a specially-crafted message for verification. (CVE-2015-1792)

An invalid-free flaw was found in the way OpenSSL handled certain DTLS handshake messages. A malicious DTLS client or server could send a specially-crafted message to the peer, which could cause the application to crash or potentially cause arbitrary code execution. (CVE-2014-8176)

A regression was found in the ssleay_rand_bytes() function. This could lead a multi-threaded application to crash. (CVE-2015-3216)");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1k~10.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1k~10.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1k~10.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1k~10.86.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1k~10.86.amzn1", rls:"AMAZON"))) {
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

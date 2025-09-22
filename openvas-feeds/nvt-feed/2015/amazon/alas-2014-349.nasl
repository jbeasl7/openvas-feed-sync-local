# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120468");
  script_cve_id("CVE-2010-5298", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470", "CVE-2015-0292");
  script_tag(name:"creation_date", value:"2015-09-08 11:27:05 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-28 16:40:00 +0000 (Tue, 28 Jul 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-349)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-349");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-349.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the ALAS-2014-349 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that OpenSSL clients and servers could be forced, via a specially crafted handshake packet, to use weak keying material for communication. A man-in-the-middle attacker could use this flaw to decrypt and modify traffic between a client and a server. (CVE-2014-0224)

Note: In order to exploit this flaw, both the server and the client must be using a vulnerable version of OpenSSL, the server must be using OpenSSL version 1.0.1 and above, and the client must be using any version of OpenSSL.

A buffer overflow flaw was found in the way OpenSSL handled invalid DTLS packet fragments. A remote attacker could possibly use this flaw to execute arbitrary code on a DTLS client or server. (CVE-2014-0195)

Multiple flaws were found in the way OpenSSL handled read and write buffers when the SSL_MODE_RELEASE_BUFFERS mode was enabled. A TLS/SSL client or server using OpenSSL could crash or unexpectedly drop connections when processing certain SSL traffic. (CVE-2010-5298, CVE-2014-0198)

A denial of service flaw was found in the way OpenSSL handled certain DTLS ServerHello requests. A specially crafted DTLS handshake packet could cause a DTLS client using OpenSSL to crash. (CVE-2014-0221)

A NULL pointer dereference flaw was found in the way OpenSSL performed anonymous Elliptic Curve Diffie Hellman (ECDH) key exchange. A specially crafted handshake packet could cause a TLS/SSL client that has the anonymous ECDH cipher suite enabled to crash. (CVE-2014-3470)

An integer underflow flaw, leading to a heap-based buffer overflow, was found in the way OpenSSL decoded certain base64 strings. A remote attacker could provide a specially crafted base64 string via certain PEM processing routines that, when parsed by the OpenSSL library, would cause the OpenSSL server to crash. (CVE-2015-0292)");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1h~1.72.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1h~1.72.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1h~1.72.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1h~1.72.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1h~1.72.amzn1", rls:"AMAZON"))) {
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

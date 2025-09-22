# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120672");
  script_cve_id("CVE-2015-0293", "CVE-2015-3197", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0800");
  script_tag(name:"creation_date", value:"2016-05-09 11:11:48 +0000 (Mon, 09 May 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-30 21:31:00 +0000 (Fri, 30 Nov 2018)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-682)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-682");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-682.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl098e' package(s) announced via the ALAS-2016-682 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service flaw was found in the way OpenSSL handled SSLv2 handshake messages. A remote attacker could use this flaw to cause a TLS/SSL server using OpenSSL to exit on a failed assertion if it had both the SSLv2 protocol and EXPORT-grade cipher suites enabled. (CVE-2015-0293)

It was discovered that the SSLv2 servers using OpenSSL accepted SSLv2 connection handshakes that indicated non-zero clear key length for non-export cipher suites. An attacker could use this flaw to decrypt recorded SSLv2 sessions with the server by using it as a decryption oracle. (CVE-2016-0703)

It was discovered that the SSLv2 protocol implementation in OpenSSL did not properly implement the Bleichenbacher protection for export cipher suites. An attacker could use a SSLv2 server using OpenSSL as a Bleichenbacher oracle. (CVE-2016-0704)

A padding oracle flaw was found in the Secure Sockets Layer version 2.0 (SSLv2) protocol. An attacker can potentially use this flaw to decrypt RSA-encrypted cipher text from a connection using a newer SSL/TLS protocol version, allowing them to decrypt such connections. This cross-protocol attack is publicly referred to as DROWN. (CVE-2016-0800)

A flaw was found in the way malicious SSLv2 clients could negotiate SSLv2 ciphers that have been disabled on the server. This could result in weak SSLv2 ciphers being used for SSLv2 connections, making them vulnerable to man-in-the-middle attacks. (CVE-2015-3197)");

  script_tag(name:"affected", value:"'openssl098e' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl098e", rpm:"openssl098e~0.9.8e~29.19.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl098e-debuginfo", rpm:"openssl098e-debuginfo~0.9.8e~29.19.amzn1", rls:"AMAZON"))) {
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

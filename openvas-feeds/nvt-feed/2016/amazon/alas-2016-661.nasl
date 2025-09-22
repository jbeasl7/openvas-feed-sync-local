# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120651");
  script_cve_id("CVE-2015-3197", "CVE-2015-7575", "CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0799", "CVE-2016-0800", "CVE-2016-2842");
  script_tag(name:"creation_date", value:"2016-03-11 05:09:14 +0000 (Fri, 11 Mar 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-20 16:59:00 +0000 (Wed, 20 Feb 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-661)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-661");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-661.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the ALAS-2016-661 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A padding oracle flaw was found in the Secure Sockets Layer version 2.0 (SSLv2) protocol. An attacker can potentially use this flaw to decrypt RSA-encrypted cipher text from a connection using a newer SSL/TLS protocol version, allowing them to decrypt such connections. This cross-protocol attack is publicly referred to as DROWN (CVE-2016-0800). Prior to this advisory, SSLv2 has been disabled by default in OpenSSL on the Amazon Linux AMI. However, application configurations may still re-enable SSLv2.

A flaw was found in the way TLS 1.2 could use the MD5 hash function for signing ServerKeyExchange and Client Authentication packets during a TLS handshake. A man-in-the-middle attacker able to force a TLS connection to use the MD5 hash function could use this flaw to conduct collision attacks to impersonate a TLS server or an authenticated TLS client. (CVE-2015-7575, Medium)
A flaw was found in the way malicious SSLv2 clients could negotiate SSLv2 ciphers that have been disabled on the server. This could result in weak SSLv2 ciphers being used for SSLv2 connections, making them vulnerable to man-in-the-middle attacks. (CVE-2015-3197, Low)

A side-channel attack was found that makes use of cache-bank conflicts on the Intel Sandy-Bridge microarchitecture. An attacker who has the ability to control code in a thread running on the same hyper-threaded core as the victim's thread that is performing decryption, could use this flaw to recover RSA private keys. (CVE-2016-0702, Low)

A double-free flaw was found in the way OpenSSL parsed certain malformed DSA (Digital Signature Algorithm) private keys. An attacker could create specially crafted DSA private keys that, when processed by an application compiled against OpenSSL, could cause the application to crash. (CVE-2016-0705, Low)

An integer overflow flaw, leading to a NULL pointer dereference or a heap-based memory corruption, was found in the way some BIGNUM functions of OpenSSL were implemented. Applications that use these functions with large untrusted input could crash or, potentially, execute arbitrary code. (CVE-2016-0797, Low)

The fmtstr function in crypto/bio/b_print.c in OpenSSL improperly calculated string lengths, which allows remote attackers to cause a denial of service (overflow and out-of-bounds read) or possibly have unspecified other impact via a long string, as demonstrated by a large amount of ASN.1 data. (CVE-2016-0799, Low)

The doapr_outch function in crypto/bio/b_print.c in OpenSSL did not verify that a certain memory allocation succeeds, which allows remote attackers to cause a denial of service (out-of-bounds write or memory consumption) or possibly have unspecified other impact via a long string, as demonstrated by a large amount of ASN.1 data. (CVE-2016-2842, Low)

<i>(Updated on 2016-04-28: CVE-2016-2842 was fixed as part of this update but was previously not listed in this advisory.)</i>");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1k~14.89.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~1.0.1k~14.89.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1k~14.89.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1k~14.89.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1k~14.89.amzn1", rls:"AMAZON"))) {
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

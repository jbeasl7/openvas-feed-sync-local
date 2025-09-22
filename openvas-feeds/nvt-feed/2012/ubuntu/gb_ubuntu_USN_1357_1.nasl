# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840887");
  script_cve_id("CVE-2011-1945", "CVE-2011-3210", "CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4354", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2012-0027", "CVE-2012-0050");
  script_tag(name:"creation_date", value:"2012-02-13 10:59:45 +0000 (Mon, 13 Feb 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1357-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|11\.10|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1357-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1357-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-1357-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the elliptic curve cryptography (ECC) subsystem
in OpenSSL, when using the Elliptic Curve Digital Signature Algorithm
(ECDSA) for the ECDHE_ECDSA cipher suite, did not properly implement
curves over binary fields. This could allow an attacker to determine
private keys via a timing attack. This issue only affected Ubuntu 8.04
LTS, Ubuntu 10.04 LTS, Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-1945)

Adam Langley discovered that the ephemeral Elliptic Curve
Diffie-Hellman (ECDH) functionality in OpenSSL did not ensure thread
safety while processing handshake messages from clients. This
could allow a remote attacker to cause a denial of service via
out-of-order messages that violate the TLS protocol. This issue only
affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10 and Ubuntu
11.04. (CVE-2011-3210)

Nadhem Alfardan and Kenny Paterson discovered that the Datagram
Transport Layer Security (DTLS) implementation in OpenSSL performed a
MAC check only if certain padding is valid. This could allow a remote
attacker to recover plaintext. (CVE-2011-4108)

Antonio Martin discovered that a flaw existed in the fix to address
CVE-2011-4108, the DTLS MAC check failure. This could allow a remote
attacker to cause a denial of service. (CVE-2012-0050)

Ben Laurie discovered a double free vulnerability in OpenSSL that could
be triggered when the X509_V_FLAG_POLICY_CHECK flag is enabled. This
could allow a remote attacker to cause a denial of service. This
issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10
and Ubuntu 11.04. (CVE-2011-4109)

It was discovered that OpenSSL, in certain circumstances involving
ECDH or ECDHE cipher suites, used an incorrect modular reduction
algorithm in its implementation of the P-256 and P-384 NIST elliptic
curves. This could allow a remote attacker to obtain the private
key of a TLS server via multiple handshake attempts. This issue only
affected Ubuntu 8.04 LTS. (CVE-2011-4354)

Adam Langley discovered that the SSL 3.0 implementation in OpenSSL
did not properly initialize data structures for block cipher
padding. This could allow a remote attacker to obtain sensitive
information. (CVE-2011-4576)

Andrew Chi discovered that OpenSSL, when RFC 3779 support is enabled,
could trigger an assert when handling an X.509 certificate containing
certificate-extension data associated with IP address blocks or
Autonomous System (AS) identifiers. This could allow a remote attacker
to cause a denial of service. (CVE-2011-4577)

Adam Langley discovered that the Server Gated Cryptography (SGC)
implementation in OpenSSL did not properly handle handshake
restarts. This could allow a remote attacker to cause a denial of
service. (CVE-2011-4619)

Andrey Kulikov discovered that the GOST block cipher engine in OpenSSL
did not properly handle invalid parameters. This could allow a remote
attacker to cause a denial of service via crafted data from a TLS
client. This issue only affected Ubuntu 11.10. (CVE-2012-0027)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8k-7ubuntu8.8", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"0.9.8k-7ubuntu8.8", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-1ubuntu4.6", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-1ubuntu4.6", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-5ubuntu1.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-5ubuntu1.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.0e-2ubuntu4.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.0e-2ubuntu4.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-4ubuntu3.15", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-4ubuntu3.15", rls:"UBUNTU8.04 LTS"))) {
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

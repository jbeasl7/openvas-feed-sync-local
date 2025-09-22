# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842062");
  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_tag(name:"creation_date", value:"2015-01-23 11:58:57 +0000 (Fri, 23 Jan 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2459-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2459-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2459-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-2459-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pieter Wuille discovered that OpenSSL incorrectly handled Bignum squaring.
(CVE-2014-3570)

Markus Stenberg discovered that OpenSSL incorrectly handled certain crafted
DTLS messages. A remote attacker could use this issue to cause OpenSSL to
crash, resulting in a denial of service. (CVE-2014-3571)

Karthikeyan Bhargavan discovered that OpenSSL incorrectly handled certain
handshakes. A remote attacker could possibly use this issue to downgrade to
ECDH, removing forward secrecy from the ciphersuite. (CVE-2014-3572)

Antti Karjalainen, Tuomo Untinen and Konrad Kraszewski discovered that
OpenSSL incorrectly handled certain certificate fingerprints. A remote
attacker could possibly use this issue to trick certain applications that
rely on the uniqueness of fingerprints. (CVE-2014-8275)

Karthikeyan Bhargavan discovered that OpenSSL incorrectly handled certain
key exchanges. A remote attacker could possibly use this issue to downgrade
the security of the session to EXPORT_RSA. (CVE-2015-0204)

Karthikeyan Bhargavan discovered that OpenSSL incorrectly handled client
authentication. A remote attacker could possibly use this issue to
authenticate without the use of a private key in certain limited scenarios.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2015-0205)

Chris Mueller discovered that OpenSSL incorrect handled memory when
processing DTLS records. A remote attacker could use this issue to cause
OpenSSL to consume resources, resulting in a denial of service. This issue
only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-0206)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8k-7ubuntu8.23", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.21", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu2.8", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu9.1", rls:"UBUNTU14.10"))) {
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

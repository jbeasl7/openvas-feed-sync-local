# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7980.2");
  script_cve_id("CVE-2025-68160", "CVE-2025-69418", "CVE-2025-69419", "CVE-2025-69420", "CVE-2025-69421", "CVE-2026-22795", "CVE-2026-22796");
  script_tag(name:"creation_date", value:"2026-01-30 04:33:13 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7980-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7980-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7980-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl, openssl1.0' package(s) announced via the USN-7980-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7980-2 fixed vulnerabilities in OpenSSL. This update provides the
corresponding updates for CVE-2025-68160 for openssl and openssl1.0,
CVE-2025-69418 for openssl on Ubuntu 18.04 LTS and Ubuntu 20.04 LTS,
CVE-2025-69419 for openssl on Ubuntu 18.04 LTS and Ubuntu 20.04 LTS,
CVE-2025-69420 for openssl on Ubuntu 18.04 LTS and Ubuntu 20.04 LTS,
CVE-2025-69421 for openssl and openssl1.0, CVE-2026-22795 for openssl on
Ubuntu 18.04 LTS and Ubuntu 20.04 LTS, and CVE-2026-22796 for openssl and
openssl1.0.

Original advisory details:

 Stanislav Fort, Petr Simecek, and Hamza discovered that OpenSSL
 incorrectly validated PBMAC1 parameters when doing PKCS#12 MAC
 verification. An attacker could possibly use this issue to cause OpenSSL
 to crash, resulting in a denial of service. This issue only affected
 Ubuntu 25.10. (CVE-2025-11187)

 Stanislav Fort discovered that OpenSSL incorrectly parsed CMS
 AuthEnvelopedData messages. An attacker could possibly use this issue to
 cause OpenSSL to crash, resulting in a denial of service. (CVE-2025-15467)

 Stanislav Fort discovered that OpenSSL incorrectly handled memory in the
 SSL_CIPHER_find() function. An attacker could possibly use this issue to
 cause OpenSSL to crash, resulting in a denial of service. This issue only
 affected Ubuntu 25.10. (CVE-2025-15468)

 Stanislav Fort discovered that the OpenSSL 'openssl dgst' command line
 tool incorrectly truncated data to 16MB. An attacker could posibly use
 this issue to hide unauthenticated data beyond the 16MB limit. This issue
 only affected Ubuntu 25.10. (CVE-2025-15469)

 Tomas Dulka and Stanislav Fort discovered that OpenSSL incorrectly handled
 memory with TLS 1.3 connections using certificate compression. An attacker
 could possibly use this issue to consume resources, leading to a denial of
 service. This issue only affected Ubuntu 25.10. (CVE-2025-66199)

 Petr Simecek and Stanislav Fort discovered that OpenSSL incorrectly
 handled memory when writing large data into a BIO chain. An attacker could
 possibly use this issue to consume resources, leading to a denial of
 service. (CVE-2025-68160)

 Stanislav Fort discovered that the OpenSSL OCB API could incorrectly leave
 final partial blocks unencrypted and unauthenticated. An attacker could
 possibly use this issue to read or tamper with the affected final bytes.
 (CVE-2025-69418)

 Stanislav Fort discovered that OpenSSL incorrectly handled the
 PKCS12_get_friendlyname() utf-8 conversion. An attacker could possibly use
 this issue to cause OpenSSL to crash, resulting in a denial of service.
 (CVE-2025-69419)

 Luigino Camastra discovered that OpenSSL incorrectly handled ASN1_TYPE
 validation in the TS_RESP_verify_response() function. An attacker could
 possibly use this issue to cause OpenSSL to crash, resulting in a denial
 of service. (CVE-2025-69420)

 Luigino Camastra discovered that OpenSSL incorrectly handled memory in the
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openssl, openssl1.0' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu2.27+esm12", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.1f-1ubuntu2.27+esm12", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2g-1ubuntu4.20+esm14", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.2g-1ubuntu4.20+esm14", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2n-1ubuntu5.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1-1ubuntu2.1~18.04.23+esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.1-1ubuntu2.1~18.04.23+esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl1.0", ver:"1.0.2n-1ubuntu5.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1f-1ubuntu2.24+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.1f-1ubuntu2.24+esm2", rls:"UBUNTU20.04 LTS"))) {
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

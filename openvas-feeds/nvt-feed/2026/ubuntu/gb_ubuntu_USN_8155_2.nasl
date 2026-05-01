# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8155.2");
  script_cve_id("CVE-2026-28387", "CVE-2026-28388", "CVE-2026-28389", "CVE-2026-28390");
  script_tag(name:"creation_date", value:"2026-04-13 07:50:16 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-14T06:16:47+0000");
  script_tag(name:"last_modification", value:"2026-04-14 06:16:47 +0000 (Tue, 14 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8155-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8155-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8155-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl, openssl1.0' package(s) announced via the USN-8155-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-8155-1 fixed vulnerabilities in OpenSSL. This update provides the
corresponding updates for CVE-2026-28387 for openssl in Ubuntu 20.04 LTS.
CVE-2026-28388 for openssl and openssl1.0 in Ubuntu 14.04 LTS, Ubuntu 16.04
LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04 LTS, and CVE-2026-28389 and
CVE-2026-28390 for openssl and openssl1.0 for Ubuntu 16.04 LTS, Ubuntu
18.04 LTS, and Ubuntu 20.04 LTS.

Original advisory details:

 Viktor Dukhovni discovered that OpenSSL incorrectly negotiated the
 expected preferred key exchange group when used as a TLS 1.3 server. This
 could result in a less preferred key exchange being used, contrary to
 expectations. This issue only affected Ubuntu 25.10. (CVE-2026-2673)

 Igor Morgenstern discovered that OpenSSL incorrectly handled certain
 memory operations when used as a DANE client. A remote attacker could use
 this issue to cause OpenSSL to crash, resulting in a denial of service, or
 possibly execute arbitrary code. (CVE-2026-28387)

 Igor Morgenstern discovered that OpenSSL incorrectly handled certain
 memory operations when processing a delta CRL. A remote attacker could
 possibly use this issue to cause OpenSSL to crash, resulting in a denial
 of service. (CVE-2026-28388)

 Nathan Sportsman, Daniel Rhea, and Jaeho Nam discovered that OpenSSL
 incorrectly handled certain memory operations when processing a crafted
 CMS EnvelopedData message with KeyAgreeRecipientInfo. A remote attacker
 could possibly use this issue to cause OpenSSL to crash, resulting in a
 denial of service. (CVE-2026-28389)

 Muhammad Daffa, Joshua Rogers, and Chanho Kim discovered that OpenSSL
 incorrectly handled processing of a crafted CMS EnvelopedData message with
 KeyTransportRecipientInfo. A remote attacker could possibly use this issue
 to cause OpenSSL to crash, resulting in a denial of service.
 (CVE-2026-28390)

 Quoc Tran discovered that OpenSSL incorrectly handled hexadecimal
 conversion on 32-bit platforms. A remote attacker could use this issue to
 cause OpenSSL to crash, resulting in a denial of service, or possibly
 execute arbitrary code. (CVE-2026-31789)

 Simo Sorce discovered that OpenSSL incorrectly handled failures in RSA KEM
 RSASVE Encapsulation. A remote attacker could possibly use this issue to
 obtain sensitive information. (CVE-2026-31790)");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu2.27+esm13", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.1f-1ubuntu2.27+esm13", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2g-1ubuntu4.20+esm15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.0.2g-1ubuntu4.20+esm15", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2n-1ubuntu5.13+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1-1ubuntu2.1~18.04.23+esm8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.1-1ubuntu2.1~18.04.23+esm8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl1.0", ver:"1.0.2n-1ubuntu5.13+esm4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1f-1ubuntu2.24+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"1.1.1f-1ubuntu2.24+esm3", rls:"UBUNTU20.04 LTS"))) {
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

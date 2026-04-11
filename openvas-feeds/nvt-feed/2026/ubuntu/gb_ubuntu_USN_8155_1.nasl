# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8155.1");
  script_cve_id("CVE-2026-2673", "CVE-2026-28387", "CVE-2026-28388", "CVE-2026-28389", "CVE-2026-28390", "CVE-2026-31789", "CVE-2026-31790");
  script_tag(name:"creation_date", value:"2026-04-09 04:48:13 +0000 (Thu, 09 Apr 2026)");
  script_version("2026-04-09T06:11:03+0000");
  script_tag(name:"last_modification", value:"2026-04-09 06:11:03 +0000 (Thu, 09 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8155-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8155-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8155-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-8155-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Viktor Dukhovni discovered that OpenSSL incorrectly negotiated the expected
preferred key exchange group when used as a TLS 1.3 server. This could
result in a less preferred key exchange being used, contrary to
expectations. This issue only affected Ubuntu 25.10. (CVE-2026-2673)

Igor Morgenstern discovered that OpenSSL incorrectly handled certain memory
operations when used as a DANE client. A remote attacker could use this
issue to cause OpenSSL to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2026-28387)

Igor Morgenstern discovered that OpenSSL incorrectly handled certain memory
operations when processing a delta CRL. A remote attacker could possibly
use this issue to cause OpenSSL to crash, resulting in a denial of service.
(CVE-2026-28388)

Nathan Sportsman, Daniel Rhea, and Jaeho Nam discovered that OpenSSL
incorrectly handled certain memory operations when processing a crafted CMS
EnvelopedData message with KeyAgreeRecipientInfo. A remote attacker could
possibly use this issue to cause OpenSSL to crash, resulting in a denial
of service. (CVE-2026-28389)

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

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.2-0ubuntu1.23", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"3.0.2-0ubuntu1.23", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3t64", ver:"3.0.13-0ubuntu3.9", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"3.0.13-0ubuntu3.9", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3t64", ver:"3.5.3-1ubuntu3.3", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"3.5.3-1ubuntu3.3", rls:"UBUNTU25.10"))) {
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

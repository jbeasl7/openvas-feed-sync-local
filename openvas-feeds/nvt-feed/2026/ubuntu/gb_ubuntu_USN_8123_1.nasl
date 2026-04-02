# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8123.1");
  script_cve_id("CVE-2021-44732", "CVE-2024-23775", "CVE-2025-27810", "CVE-2025-47917", "CVE-2025-48965", "CVE-2025-52496", "CVE-2025-52497");
  script_tag(name:"creation_date", value:"2026-03-27 04:47:46 +0000 (Fri, 27 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-07 01:18:26 +0000 (Thu, 07 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-8123-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8123-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8123-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mbedtls' package(s) announced via the USN-8123-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Mbed TLS incorrectly handled memory allocation
failures. A remote attacker could possibly use this issue to crash
the program. This issue only affected Ubuntu 18.04 LTS and Ubuntu
20.04 LTS. (CVE-2021-44732)

Jonathan Winzig discovered that Mbed TLS incorrectly handled crafted
inputs. A remote attacker could possibly use this issue to crash the
program, resulting in a denial of service. This issue only affected
Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, Ubuntu 22.04 LTS. (CVE-2024-23775)

It was discovered that Mbed TLS incorrectly handled the TLS
handshake. A remote attacker could possibly use this issue to
break the security guarantees of the TLS handshake.
(CVE-2025-27810)

Linh Le and Ngan Nguyen discovered that Mbed TLS incorrectly
documented the behavior of a function. Application code relying
on the documented behavior might be affected. A remote attacker
could possibly use this issue to execute arbitrary code.
(CVE-2025-47917)

Linh Le and Ngan Nguyen discovered that Mbed TLS incorrectly handled
crafted input. A remote attacker could possibly use this issue to
crash the program, resulting in a denial of service. (CVE-2025-48965)

It was discovered that Mbed TLS incorrectly handled a race condition.
An attacker could possibly use this issue to extract AES keys.
(CVE-2025-52496)

Linh Le and Ngan Nguyen discovered that Mbed TLS incorrectly handled
certain invalid input. A remote attacker could possibly use this
issue to crash the program, resulting in a denial of service.
(CVE-2025-52497)");

  script_tag(name:"affected", value:"'mbedtls' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libmbedcrypto1", ver:"2.8.0-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls-dev", ver:"2.8.0-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls10", ver:"2.8.0-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedx509-0", ver:"2.8.0-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libmbedcrypto3", ver:"2.16.4-1ubuntu2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls-dev", ver:"2.16.4-1ubuntu2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls12", ver:"2.16.4-1ubuntu2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedx509-0", ver:"2.16.4-1ubuntu2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libmbedcrypto7", ver:"2.28.0-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls-dev", ver:"2.28.0-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls14", ver:"2.28.0-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedx509-1", ver:"2.28.0-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libmbedcrypto7t64", ver:"2.28.8-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls-dev", ver:"2.28.8-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedtls14t64", ver:"2.28.8-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmbedx509-1t64", ver:"2.28.8-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

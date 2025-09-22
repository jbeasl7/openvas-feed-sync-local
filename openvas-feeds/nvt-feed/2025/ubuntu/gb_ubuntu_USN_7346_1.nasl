# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7346.1");
  script_cve_id("CVE-2021-42780", "CVE-2021-42782", "CVE-2023-2977", "CVE-2023-40660", "CVE-2023-40661", "CVE-2023-5992", "CVE-2024-45615", "CVE-2024-45616", "CVE-2024-45617", "CVE-2024-45618", "CVE-2024-45619", "CVE-2024-45620", "CVE-2024-8443");
  script_tag(name:"creation_date", value:"2025-03-13 04:04:12 +0000 (Thu, 13 Mar 2025)");
  script_version("2025-03-13T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-03-13 05:38:41 +0000 (Thu, 13 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-07 18:45:22 +0000 (Wed, 07 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-7346-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7346-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7346-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the USN-7346-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSC did not correctly handle certain memory
operations, which could lead to a use-after-free vulnerability. An
attacker could possibly use this issue to cause a denial of service or
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS,
Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2021-42780)

It was discovered that OpenSC did not correctly handle certain memory
operations, which could lead to a stack buffer overflow. An attacker
could possibly use this issue to cause a denial of service or execute
arbitrary code. This issue only affected Ubuntu 20.04 LTS. (CVE-2021-42782)

It was discovered that OpenSC did not correctly handle the length of
certain buffers, which could lead to a out-of-bounds access vulnerability.
An attacker could possibly use this issue to cause a denial of service or
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS,
Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-2977)

Deepanjan Pal discovered that OpenSC did not correctly authenticate a zero
length PIN. A physically proximate attacker could possibly use this issue
to gain unauthorized access to certain systems. This issue only affected
Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-40660)

It was discovered that OpenSC did not correctly handle certain memory
operations. A physically proximate attacker could possibly use this issue
to compromise key generation, certificate loading and other card
management operations. This issue only affected Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2023-40661)

Hubert Kario, Michal Shagam and Eyal Ronen discovered that OpenSC had a
timing side-channel and incorrectly handled RSA padding. An attacker
could possibly use this issue to recover sensitive information. This issue
only affected Ubuntu 22.04 LTS. (CVE-2023-5992)

Matteo Marini discovered that OpenSC did not properly manage memory due to
certain uninitialized variables. A physically proximate attacker could
possibly use this issue to gain unauthorized access to certain systems.
This issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS,
Ubuntu 24.04 LTS and Ubuntu 24.10. (CVE-2024-45615)

Matteo Marini discovered that OpenSC did not correctly handle certain
memory operations. A physically proximate attacker could possibly use this
issue to gain unauthorized access to certain systems. This issue only
affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS and
Ubuntu 24.10. (CVE-2024-45616, CVE-2024-45617)

Matteo Marini discovered that OpenSC did not correctly handle certain
memory operations. A physically proximate attacker could possibly use this
issue to gain unauthorized access to certain systems.
(CVE-2024-45618, CVE-2024-45620)

Matteo Marini discovered that OpenSC did not correctly handle certain
memory operations. A physically proximate attacker could possibly use this
issue to gain unauthorized access to certain ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'opensc' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.15.0-1ubuntu1+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.15.0-1ubuntu1+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.17.0-3ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.17.0-3ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.20.0-3ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.20.0-3ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.22.0-1ubuntu2+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.22.0-1ubuntu2+esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.25.0~rc1-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.25.0~rc1-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.25.1-2ubuntu1.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.25.1-2ubuntu1.1", rls:"UBUNTU24.10"))) {
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

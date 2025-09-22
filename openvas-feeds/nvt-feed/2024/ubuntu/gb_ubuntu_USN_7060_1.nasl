# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7060.1");
  script_cve_id("CVE-2019-0161", "CVE-2021-28210", "CVE-2021-28211", "CVE-2021-38575", "CVE-2021-38578", "CVE-2022-1292");
  script_tag(name:"creation_date", value:"2024-10-10 14:30:54 +0000 (Thu, 10 Oct 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-11 17:19:56 +0000 (Mon, 11 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-7060-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7060-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7060-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2' package(s) announced via the USN-7060-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that EDK II did not check the buffer length in XHCI,
which could lead to a stack overflow. A local attacker could potentially
use this issue to cause a denial of service. This issue only affected
Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-0161)

Laszlo Ersek discovered that EDK II incorrectly handled recursion. A
remote attacker could possibly use this issue to cause EDK II to consume
resources, leading to a denial of service. This issue only affected
Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2021-28210)

Satoshi Tanda discovered that EDK II incorrectly handled decompressing
certain images. A remote attacker could use this issue to cause EDK II to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2021-28211)

It was discovered that EDK II incorrectly decoded certain strings. A remote
attacker could use this issue to cause EDK II to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2021-38575)

It was discovered that EDK II had integer underflow vulnerability in
SmmEntryPoint, which could result in a buffer overflow. An attacker
could potentially use this issue to cause a denial of service.
(CVE-2021-38578)

Elison Niven discovered that OpenSSL, vendored in EDK II, incorrectly
handled the c_rehash script. A local attacker could possibly use this
issue to execute arbitrary commands when c_rehash is run. This issue
only affected Ubuntu 16.04 LTS. (CVE-2022-1292)");

  script_tag(name:"affected", value:"'edk2' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20160408.ffea0a2c-2ubuntu0.2+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi", ver:"0~20160408.ffea0a2c-2ubuntu0.2+esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20180205.c0d9813c-2ubuntu0.3+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"0~20180205.c0d9813c-2ubuntu0.3+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"0~20180205.c0d9813c-2ubuntu0.3+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20191122.bd85bf54-2ubuntu3.6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"0~20191122.bd85bf54-2ubuntu3.6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"0~20191122.bd85bf54-2ubuntu3.6", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"2022.02-3ubuntu0.22.04.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovmf-ia32", ver:"2022.02-3ubuntu0.22.04.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"2022.02-3ubuntu0.22.04.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"2022.02-3ubuntu0.22.04.3", rls:"UBUNTU22.04 LTS"))) {
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

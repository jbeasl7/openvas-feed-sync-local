# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6638.1");
  script_cve_id("CVE-2022-36763", "CVE-2022-36764", "CVE-2022-36765", "CVE-2023-45230", "CVE-2023-45231", "CVE-2023-45232", "CVE-2023-45233", "CVE-2023-45234", "CVE-2023-45235", "CVE-2023-48733");
  script_tag(name:"creation_date", value:"2024-02-15 04:08:41 +0000 (Thu, 15 Feb 2024)");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-23 15:58:27 +0000 (Tue, 23 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6638-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6638-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6638-1");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/edk2/+bug/2040137");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2' package(s) announced via the USN-6638-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marc Beatove discovered buffer overflows exit in EDK2. An attacker on the
local network could potentially use this to impact availability or possibly
cause remote code execution. (CVE-2022-36763, CVE-2022-36764,
CVE-2022-36765)

It was discovered that a buffer overflows exists in EDK2's Network Package
An attacker on the local network could potentially use these to impact
availability or possibly cause remote code execution. (CVE-2023-45230,
CVE-2023-45234, CVE-2023-45235)

It was discovered that an out-of-bounds read exists in EDK2's Network
Package An attacker on the local network could potentially use this to
impact confidentiality. (CVE-2023-45231)

It was discovered that infinite-loops exists in EDK2's Network Package
An attacker on the local network could potentially use these to impact
availability. (CVE-2023-45232, CVE-2023-45233)

Mate Kukri discovered that an insecure default to allow UEFI Shell in
EDK2 was left enabled in Ubuntu's EDK2. An attacker could use this to
bypass Secure Boot. (CVE-2023-48733)");

  script_tag(name:"affected", value:"'edk2' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20191122.bd85bf54-2ubuntu3.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi", ver:"0~20191122.bd85bf54-2ubuntu3.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"0~20191122.bd85bf54-2ubuntu3.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"0~20191122.bd85bf54-2ubuntu3.5", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"2022.02-3ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi", ver:"2022.02-3ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"2022.02-3ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"2022.02-3ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"efi-shell-aa64", ver:"2023.05-2ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-shell-arm", ver:"2023.05-2ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-shell-x64", ver:"2023.05-2ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"2023.05-2ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"2023.05-2ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"2023.05-2ubuntu0.1", rls:"UBUNTU23.10"))) {
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

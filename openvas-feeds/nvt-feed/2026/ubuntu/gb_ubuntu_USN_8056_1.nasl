# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8056.1");
  script_cve_id("CVE-2024-57254", "CVE-2024-57255", "CVE-2024-57256", "CVE-2024-57257", "CVE-2024-57258", "CVE-2024-57259");
  script_tag(name:"creation_date", value:"2026-02-24 04:37:13 +0000 (Tue, 24 Feb 2026)");
  script_version("2026-02-24T05:57:09+0000");
  script_tag(name:"last_modification", value:"2026-02-24 05:57:09 +0000 (Tue, 24 Feb 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-01 16:27:27 +0000 (Wed, 01 Oct 2025)");

  script_name("Ubuntu: Security Advisory (USN-8056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8056-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8056-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'u-boot' package(s) announced via the USN-8056-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Simon Diepold discovered that U-Boot incorrectly handled certain DHCP
responses. An attacker on the local network could possibly use this issue
to obtain sensitive memory contents. (CVE-2024-42040)

It was discovered that U-Boot incorrectly handled symlink size calculations
in squashfs file systems. An attacker could use this issue with a specially
crafted squashfs file system to cause U-Boot to crash, resulting in a denial
of service, or execute arbitrary code. (CVE-2024-57254)

It was discovered that U-Boot incorrectly handled inode size calculations
in squashfs file systems. An attacker could use this issue with a specially
crafted squashfs file system to cause U-Boot to crash, resulting in a denial
of service, or execute arbitrary code. (CVE-2024-57255)

It was discovered that U-Boot incorrectly handled inode size calculations
in EXT4 file systems. An attacker could use this issue with a specially
crafted EXT4 file system to cause U-Boot to crash, resulting in a denial of
service, or execute arbitrary code. (CVE-2024-57256)

It was discovered that U-Boot incorrectly handled deep symlink nesting in
squashfs file systems. An attacker could possibly use this issue with a
specially crafted squashfs file system to cause U-Boot to crash, resulting
in a denial of service. (CVE-2024-57257)

It was discovered that U-Boot incorrectly handled memory allocation in
squashfs file systems. An attacker could use this issue with a specially
crafted squashfs file system to cause U-Boot to crash, resulting in a denial
of service, or execute arbitrary code. (CVE-2024-57258)");

  script_tag(name:"affected", value:"'u-boot' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"u-boot", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-amlogic", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-exynos", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-imx", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-microchip", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-mvebu", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-omap", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qcom", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qemu", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rockchip", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rpi", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sifive", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sunxi", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tegra", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tools", ver:"2022.01+dfsg-2ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-amlogic", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-asahi", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-exynos", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-imx", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-microchip", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-mvebu", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-omap", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qcom", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qemu", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rockchip", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rpi", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sifive", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sitara-binaries", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-starfive", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-stm32", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sunxi", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tegra", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tools", ver:"2025.10-0ubuntu0.24.04.2", rls:"UBUNTU24.04 LTS"))) {
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

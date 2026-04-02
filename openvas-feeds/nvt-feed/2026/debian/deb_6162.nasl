# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2026.6162");
  script_cve_id("CVE-2025-71238", "CVE-2026-23100", "CVE-2026-23221", "CVE-2026-23233", "CVE-2026-23234", "CVE-2026-23235", "CVE-2026-23236", "CVE-2026-23237", "CVE-2026-23238");
  script_tag(name:"creation_date", value:"2026-03-13 04:35:16 +0000 (Fri, 13 Mar 2026)");
  script_version("2026-03-18T05:59:10+0000");
  script_tag(name:"last_modification", value:"2026-03-18 05:59:10 +0000 (Wed, 18 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-17 21:21:25 +0000 (Tue, 17 Mar 2026)");

  script_name("Debian: Security Advisory (DSA-6162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB13");

  script_xref(name:"Advisory-ID", value:"DSA-6162-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2026/DSA-6162-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-6162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 13.");

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

if(release == "DEB13") {

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bpftool", ver:"7.5.0+6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drm-core-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drm-core-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drm-core-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"intel-sdsi", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-bpf-dev", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-6.12", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-6.12", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-amd64", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-arm64", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-arm64-16k", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-armmp", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-armmp-lpae", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-cloud-amd64", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-cloud-arm64", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-common", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-common-rt", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-powerpc64le", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-powerpc64le-64k", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-riscv64", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-rpi", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-rt-amd64", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-rt-arm64", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-rt-armmp", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.74+deb13+1-s390x", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp-lpae", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-powerpc64le", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-powerpc64le-64k", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-riscv64", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rpi", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rt-armmp", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-s390x", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-amd64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-amd64-unsigned", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-arm64-16k-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-arm64-16k-unsigned", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-arm64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-arm64-unsigned", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-armmp", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-armmp-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-armmp-lpae", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-armmp-lpae-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-cloud-amd64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-cloud-amd64-unsigned", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-cloud-arm64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-cloud-arm64-unsigned", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-powerpc64le", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-powerpc64le-64k", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-powerpc64le-64k-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-powerpc64le-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-riscv64", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-riscv64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-rpi", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-rpi-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-rt-amd64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-rt-amd64-unsigned", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-rt-arm64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-rt-arm64-unsigned", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-rt-armmp", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-rt-armmp-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-s390x", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.74+deb13+1-s390x-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-16k-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-amd64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-arm64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-64k", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-64k-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-riscv64", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-riscv64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-amd64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-arm64-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x-dbg", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-6.12.74+deb13+1", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-6.12", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-6.12.74+deb13+1", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtla", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.12.74+deb13+1-armmp-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.12.74+deb13+1-powerpc64le-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.12.74+deb13+1-riscv64-di", ver:"6.12.74-2", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.12.74+deb13+1-s390x-di", ver:"6.12.74-2", rls:"DEB13"))) {
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

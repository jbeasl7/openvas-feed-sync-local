# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2025.6008");
  script_cve_id("CVE-2025-21751", "CVE-2025-22103", "CVE-2025-22113", "CVE-2025-22124", "CVE-2025-22125", "CVE-2025-23133", "CVE-2025-38272", "CVE-2025-38306", "CVE-2025-38453", "CVE-2025-38502", "CVE-2025-38556", "CVE-2025-38676", "CVE-2025-38677", "CVE-2025-38730", "CVE-2025-38732", "CVE-2025-38733", "CVE-2025-38734", "CVE-2025-38735", "CVE-2025-38736", "CVE-2025-38737", "CVE-2025-39673", "CVE-2025-39675", "CVE-2025-39676", "CVE-2025-39679", "CVE-2025-39681", "CVE-2025-39682", "CVE-2025-39683", "CVE-2025-39684", "CVE-2025-39685", "CVE-2025-39686", "CVE-2025-39687", "CVE-2025-39689", "CVE-2025-39691", "CVE-2025-39692", "CVE-2025-39693", "CVE-2025-39694", "CVE-2025-39695", "CVE-2025-39697", "CVE-2025-39698", "CVE-2025-39700", "CVE-2025-39701", "CVE-2025-39702", "CVE-2025-39703", "CVE-2025-39705", "CVE-2025-39706", "CVE-2025-39707", "CVE-2025-39709", "CVE-2025-39710", "CVE-2025-39711", "CVE-2025-39712", "CVE-2025-39713", "CVE-2025-39714", "CVE-2025-39715", "CVE-2025-39716", "CVE-2025-39718", "CVE-2025-39719", "CVE-2025-39720", "CVE-2025-39721", "CVE-2025-39722", "CVE-2025-39723", "CVE-2025-39724", "CVE-2025-39759", "CVE-2025-39765", "CVE-2025-39766", "CVE-2025-39767", "CVE-2025-39770", "CVE-2025-39772", "CVE-2025-39773", "CVE-2025-39776", "CVE-2025-39779", "CVE-2025-39780", "CVE-2025-39781", "CVE-2025-39782", "CVE-2025-39783", "CVE-2025-39787", "CVE-2025-39788", "CVE-2025-39790", "CVE-2025-39791", "CVE-2025-39800", "CVE-2025-39801", "CVE-2025-39805", "CVE-2025-39806", "CVE-2025-39807", "CVE-2025-39808", "CVE-2025-39810", "CVE-2025-39811", "CVE-2025-39812", "CVE-2025-39813", "CVE-2025-39815", "CVE-2025-39817", "CVE-2025-39819", "CVE-2025-39823", "CVE-2025-39824", "CVE-2025-39825", "CVE-2025-39826", "CVE-2025-39827", "CVE-2025-39828", "CVE-2025-39829", "CVE-2025-39831", "CVE-2025-39832", "CVE-2025-39835", "CVE-2025-39836", "CVE-2025-39838", "CVE-2025-39839", "CVE-2025-39841", "CVE-2025-39842", "CVE-2025-39843", "CVE-2025-39844", "CVE-2025-39845", "CVE-2025-39846", "CVE-2025-39847", "CVE-2025-39848", "CVE-2025-39849", "CVE-2025-39850", "CVE-2025-39851", "CVE-2025-39852", "CVE-2025-39853", "CVE-2025-39854", "CVE-2025-39857", "CVE-2025-39860", "CVE-2025-39861", "CVE-2025-39863", "CVE-2025-39864", "CVE-2025-39865", "CVE-2025-39866", "CVE-2025-40300");
  script_tag(name:"creation_date", value:"2025-09-23 04:05:52 +0000 (Tue, 23 Sep 2025)");
  script_version("2025-09-23T05:39:06+0000");
  script_tag(name:"last_modification", value:"2025-09-23 05:39:06 +0000 (Tue, 23 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-6008-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB13");

  script_xref(name:"Advisory-ID", value:"DSA-6008-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2025/DSA-6008-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-6008-1 advisory.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bpftool", ver:"7.5.0+6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drm-core-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drm-core-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"drm-core-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"intel-sdsi", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-bpf-dev", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-6.12", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-6.12", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-amd64", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-arm64", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-arm64-16k", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-armmp", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-armmp-lpae", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-cloud-amd64", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-cloud-arm64", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-common", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-common-rt", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-powerpc64le", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-powerpc64le-64k", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-riscv64", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-rpi", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-rt-amd64", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-rt-arm64", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-rt-armmp", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.12.48+deb13-s390x", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp-lpae", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-powerpc64le", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-powerpc64le-64k", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-riscv64", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rpi", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rt-armmp", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-s390x", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-amd64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-amd64-unsigned", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-arm64-16k-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-arm64-16k-unsigned", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-arm64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-arm64-unsigned", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-armmp", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-armmp-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-armmp-lpae", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-armmp-lpae-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-cloud-amd64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-cloud-amd64-unsigned", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-cloud-arm64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-cloud-arm64-unsigned", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-powerpc64le", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-powerpc64le-64k", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-powerpc64le-64k-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-powerpc64le-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-riscv64", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-riscv64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-rpi", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-rpi-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-rt-amd64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-rt-amd64-unsigned", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-rt-arm64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-rt-arm64-unsigned", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-rt-armmp", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-rt-armmp-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-s390x", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.12.48+deb13-s390x-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-16k-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-amd64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-arm64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-64k", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-64k-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-riscv64", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-riscv64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-amd64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-arm64-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x-dbg", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-6.12.48+deb13", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-6.12", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-6.12.48+deb13", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtla", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.12.48+deb13-armmp-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.12.48+deb13-powerpc64le-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.12.48+deb13-riscv64-di", ver:"6.12.48-1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.12.48+deb13-s390x-di", ver:"6.12.48-1", rls:"DEB13"))) {
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

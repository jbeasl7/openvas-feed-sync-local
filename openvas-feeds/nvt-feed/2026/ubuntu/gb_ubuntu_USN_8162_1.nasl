# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8162.1");
  script_cve_id("CVE-2023-53421", "CVE-2023-53520", "CVE-2023-53662", "CVE-2023-54207", "CVE-2025-37849", "CVE-2025-38057", "CVE-2025-38125", "CVE-2025-38232", "CVE-2025-38408", "CVE-2025-38591", "CVE-2025-40149", "CVE-2025-40164", "CVE-2025-68211", "CVE-2025-68340", "CVE-2025-68365", "CVE-2025-68725", "CVE-2025-68817", "CVE-2025-71080", "CVE-2025-71163", "CVE-2025-71185", "CVE-2025-71186", "CVE-2025-71188", "CVE-2025-71190", "CVE-2025-71191", "CVE-2025-71194", "CVE-2025-71196", "CVE-2025-71197", "CVE-2025-71199", "CVE-2026-22997", "CVE-2026-22998", "CVE-2026-22999", "CVE-2026-23001", "CVE-2026-23003", "CVE-2026-23011", "CVE-2026-23026", "CVE-2026-23033", "CVE-2026-23037", "CVE-2026-23038", "CVE-2026-23049", "CVE-2026-23056", "CVE-2026-23058", "CVE-2026-23060", "CVE-2026-23061", "CVE-2026-23063", "CVE-2026-23064", "CVE-2026-23071", "CVE-2026-23073", "CVE-2026-23074", "CVE-2026-23075", "CVE-2026-23076", "CVE-2026-23078", "CVE-2026-23080", "CVE-2026-23083", "CVE-2026-23084", "CVE-2026-23085", "CVE-2026-23087", "CVE-2026-23089", "CVE-2026-23090", "CVE-2026-23091", "CVE-2026-23093", "CVE-2026-23095", "CVE-2026-23096", "CVE-2026-23097", "CVE-2026-23098", "CVE-2026-23099", "CVE-2026-23101", "CVE-2026-23103", "CVE-2026-23105", "CVE-2026-23108", "CVE-2026-23111", "CVE-2026-23119", "CVE-2026-23120", "CVE-2026-23121", "CVE-2026-23124", "CVE-2026-23125", "CVE-2026-23128", "CVE-2026-23133", "CVE-2026-23145", "CVE-2026-23146", "CVE-2026-23150", "CVE-2026-23164", "CVE-2026-23167", "CVE-2026-23170", "CVE-2026-23209");
  script_tag(name:"creation_date", value:"2026-04-13 07:50:16 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-14T06:16:47+0000");
  script_tag(name:"last_modification", value:"2026-04-14 06:16:47 +0000 (Tue, 14 Apr 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-18 20:46:07 +0000 (Wed, 18 Mar 2026)");

  script_name("Ubuntu: Security Advisory (USN-8162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-8162-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8162-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-nvidia-tegra-5.15' package(s) announced via the USN-8162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - Block layer subsystem,
 - Cryptographic API,
 - Drivers core,
 - Bluetooth drivers,
 - DMA engine subsystem,
 - GPU drivers,
 - HID subsystem,
 - Intel Trace Hub HW tracing drivers,
 - IIO ADC drivers,
 - IRQ chip drivers,
 - Modular ISDN driver,
 - LED subsystem,
 - UACCE accelerator framework,
 - Ethernet bonding driver,
 - Network drivers,
 - STMicroelectronics network drivers,
 - Ethernet team driver,
 - NVME drivers,
 - PHY drivers,
 - SLIMbus drivers,
 - W1 Dallas's 1-wire bus driver,
 - Xen hypervisor drivers,
 - BTRFS file system,
 - Ext4 file system,
 - Network file system (NFS) client,
 - Network file system (NFS) server daemon,
 - NTFS3 file system,
 - SMB network file system,
 - NFC subsystem,
 - BPF subsystem,
 - IRQ subsystem,
 - Memory management,
 - Bluetooth subsystem,
 - CAN network layer,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - L2TP protocol,
 - Netfilter,
 - NET/ROM layer,
 - Network traffic control,
 - SCTP protocol,
 - TLS protocol,
 - XFRM subsystem,
 - Creative Sound Blaster X-Fi driver,
 - USB sound devices,
(CVE-2023-53421, CVE-2023-53520, CVE-2023-53662, CVE-2023-54207,
CVE-2025-37849, CVE-2025-38057, CVE-2025-38125, CVE-2025-38232,
CVE-2025-38408, CVE-2025-38591, CVE-2025-40149, CVE-2025-40164,
CVE-2025-68211, CVE-2025-68340, CVE-2025-68365, CVE-2025-68725,
CVE-2025-68817, CVE-2025-71080, CVE-2025-71163, CVE-2025-71185,
CVE-2025-71186, CVE-2025-71188, CVE-2025-71190, CVE-2025-71191,
CVE-2025-71194, CVE-2025-71196, CVE-2025-71197, CVE-2025-71199,
CVE-2026-22997, CVE-2026-22998, CVE-2026-22999, CVE-2026-23001,
CVE-2026-23003, CVE-2026-23011, CVE-2026-23026, CVE-2026-23033,
CVE-2026-23037, CVE-2026-23038, CVE-2026-23049, CVE-2026-23056,
CVE-2026-23058, CVE-2026-23060, CVE-2026-23061, CVE-2026-23063,
CVE-2026-23064, CVE-2026-23071, CVE-2026-23073, CVE-2026-23074,
CVE-2026-23075, CVE-2026-23076, CVE-2026-23078, CVE-2026-23080,
CVE-2026-23083, CVE-2026-23084, CVE-2026-23085, CVE-2026-23087,
CVE-2026-23089, CVE-2026-23090, CVE-2026-23091, CVE-2026-23093,
CVE-2026-23095, CVE-2026-23096, CVE-2026-23097, CVE-2026-23098,
CVE-2026-23099, CVE-2026-23101, CVE-2026-23103, CVE-2026-23105,
CVE-2026-23108, CVE-2026-23111, CVE-2026-23119, CVE-2026-23120,
CVE-2026-23121, CVE-2026-23124, CVE-2026-23125, CVE-2026-23128,
CVE-2026-23133, CVE-2026-23145, CVE-2026-23146, CVE-2026-23150,
CVE-2026-23164, CVE-2026-23167, CVE-2026-23170, CVE-2026-23209)");

  script_tag(name:"affected", value:"'linux-nvidia-tegra-5.15' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1057-nvidia-tegra", ver:"5.15.0-1057.57~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1057-nvidia-tegra-rt", ver:"5.15.0-1057.57~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra", ver:"5.15.0.1057.57~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-5.15", ver:"5.15.0.1057.57~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-rt", ver:"5.15.0.1057.57~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-rt-5.15", ver:"5.15.0.1057.57~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

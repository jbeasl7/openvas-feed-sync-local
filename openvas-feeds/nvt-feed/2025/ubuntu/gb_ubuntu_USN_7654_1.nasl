# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7654.1");
  script_cve_id("CVE-2022-21546", "CVE-2022-48893", "CVE-2022-49063", "CVE-2022-49168", "CVE-2022-49535", "CVE-2023-52572", "CVE-2023-52757", "CVE-2024-26686", "CVE-2024-26739", "CVE-2024-27402", "CVE-2024-35790", "CVE-2024-35866", "CVE-2024-35867", "CVE-2024-35943", "CVE-2024-36908", "CVE-2024-38540", "CVE-2024-38541", "CVE-2024-42322", "CVE-2024-46742", "CVE-2024-46751", "CVE-2024-46774", "CVE-2024-46816", "CVE-2024-49960", "CVE-2024-49989", "CVE-2024-50125", "CVE-2024-50258", "CVE-2024-50272", "CVE-2024-50280", "CVE-2024-53128", "CVE-2024-53203", "CVE-2024-54458", "CVE-2024-56751", "CVE-2025-21839", "CVE-2025-21853", "CVE-2025-22027", "CVE-2025-22062", "CVE-2025-23140", "CVE-2025-23142", "CVE-2025-23144", "CVE-2025-23145", "CVE-2025-23146", "CVE-2025-23147", "CVE-2025-23148", "CVE-2025-23150", "CVE-2025-23151", "CVE-2025-23156", "CVE-2025-23157", "CVE-2025-23158", "CVE-2025-23159", "CVE-2025-23161", "CVE-2025-23163", "CVE-2025-37738", "CVE-2025-37739", "CVE-2025-37740", "CVE-2025-37741", "CVE-2025-37742", "CVE-2025-37749", "CVE-2025-37756", "CVE-2025-37757", "CVE-2025-37758", "CVE-2025-37765", "CVE-2025-37766", "CVE-2025-37767", "CVE-2025-37768", "CVE-2025-37770", "CVE-2025-37771", "CVE-2025-37773", "CVE-2025-37780", "CVE-2025-37781", "CVE-2025-37787", "CVE-2025-37788", "CVE-2025-37789", "CVE-2025-37790", "CVE-2025-37792", "CVE-2025-37794", "CVE-2025-37796", "CVE-2025-37797", "CVE-2025-37803", "CVE-2025-37805", "CVE-2025-37808", "CVE-2025-37810", "CVE-2025-37811", "CVE-2025-37812", "CVE-2025-37817", "CVE-2025-37819", "CVE-2025-37823", "CVE-2025-37824", "CVE-2025-37829", "CVE-2025-37830", "CVE-2025-37836", "CVE-2025-37838", "CVE-2025-37839", "CVE-2025-37840", "CVE-2025-37841", "CVE-2025-37844", "CVE-2025-37850", "CVE-2025-37851", "CVE-2025-37857", "CVE-2025-37858", "CVE-2025-37859", "CVE-2025-37862", "CVE-2025-37867", "CVE-2025-37871", "CVE-2025-37875", "CVE-2025-37881", "CVE-2025-37883", "CVE-2025-37885", "CVE-2025-37892", "CVE-2025-37905", "CVE-2025-37909", "CVE-2025-37911", "CVE-2025-37912", "CVE-2025-37913", "CVE-2025-37914", "CVE-2025-37915", "CVE-2025-37923", "CVE-2025-37927", "CVE-2025-37930", "CVE-2025-37940", "CVE-2025-37949", "CVE-2025-37964", "CVE-2025-37967", "CVE-2025-37969", "CVE-2025-37970", "CVE-2025-37982", "CVE-2025-37983", "CVE-2025-37985", "CVE-2025-37989", "CVE-2025-37990", "CVE-2025-37991", "CVE-2025-37992", "CVE-2025-37994", "CVE-2025-37995", "CVE-2025-37998", "CVE-2025-38005", "CVE-2025-38009", "CVE-2025-38023", "CVE-2025-38024", "CVE-2025-38094");
  script_tag(name:"creation_date", value:"2025-07-21 04:19:06 +0000 (Mon, 21 Jul 2025)");
  script_version("2025-07-21T05:44:15+0000");
  script_tag(name:"last_modification", value:"2025-07-21 05:44:15 +0000 (Mon, 21 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-05 14:32:13 +0000 (Thu, 05 Jun 2025)");

  script_name("Ubuntu: Security Advisory (USN-7654-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7654-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7654-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.15, linux-gcp, linux-gcp-5.15, linux-gke, linux-gkeop, linux-hwe-5.15, linux-ibm, linux-ibm-5.15, linux-intel-iotg, linux-lowlatency, linux-lowlatency-hwe-5.15, linux-nvidia, linux-nvidia-tegra, linux-nvidia-tegra-5.15, linux-nvidia-tegra-igx, linux-oracle, linux-oracle-5.15' package(s) announced via the USN-7654-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - PA-RISC architecture,
 - PowerPC architecture,
 - x86 architecture,
 - Block layer subsystem,
 - Cryptographic API,
 - Serial ATA and Parallel ATA drivers,
 - Bluetooth drivers,
 - Bus devices,
 - CPU frequency scaling framework,
 - Buffer Sharing and Synchronization framework,
 - DMA engine subsystem,
 - ARM SCMI message protocol,
 - GPU drivers,
 - HID subsystem,
 - HSI subsystem,
 - I2C subsystem,
 - I3C subsystem,
 - IIO subsystem,
 - InfiniBand drivers,
 - IOMMU subsystem,
 - IRQ chip drivers,
 - MCB driver,
 - Multiple devices driver,
 - Media drivers,
 - Multifunction device drivers,
 - PCI Endpoint Test driver,
 - MTD block device drivers,
 - Network drivers,
 - Device tree and open firmware driver,
 - PCI subsystem,
 - TI SCI PM domains driver,
 - PWM drivers,
 - S/390 drivers,
 - SCSI subsystem,
 - Samsung SoC drivers,
 - TCM subsystem,
 - UFS subsystem,
 - Cadence USB3 driver,
 - ChipIdea USB driver,
 - USB Device Class drivers,
 - DesignWare USB3 driver,
 - USB Gadget drivers,
 - USB Type-C support driver,
 - USB Type-C Connector System Software Interface driver,
 - Backlight driver,
 - Framebuffer layer,
 - Xen hypervisor drivers,
 - BTRFS file system,
 - Ext4 file system,
 - F2FS file system,
 - File systems infrastructure,
 - JFS file system,
 - Network file system (NFS) client,
 - Network file system (NFS) server daemon,
 - Proc file system,
 - SMB network file system,
 - Kernel stack handling interfaces,
 - Bluetooth subsystem,
 - Network traffic control,
 - SCTP protocol,
 - BPF subsystem,
 - Kernel command line parsing driver,
 - Tracing infrastructure,
 - Memory management,
 - 802.1Q VLAN protocol,
 - Networking core,
 - IPv6 networking,
 - MAC80211 subsystem,
 - Management Component Transport Protocol (MCTP),
 - Multipath TCP,
 - Netfilter,
 - Open vSwitch,
 - Phonet protocol,
 - TIPC protocol,
 - TLS protocol,
 - Virtio sound driver,
 - CPU Power monitoring subsystem,
(CVE-2025-37790, CVE-2025-37871, CVE-2025-23147, CVE-2025-37803,
CVE-2025-37909, CVE-2025-37840, CVE-2025-37989, CVE-2025-37927,
CVE-2024-50280, CVE-2024-50272, CVE-2025-37850, CVE-2024-35866,
CVE-2025-22027, CVE-2025-37812, CVE-2025-21853, CVE-2025-37810,
CVE-2025-37766, CVE-2024-54458, CVE-2022-21546, CVE-2025-37757,
CVE-2025-37839, CVE-2024-38540, CVE-2025-37990, CVE-2025-37794,
CVE-2024-53203, CVE-2025-37964, CVE-2025-37819, CVE-2024-50125,
CVE-2024-53128, CVE-2022-48893, CVE-2023-52572, CVE-2024-42322,
CVE-2024-35943, CVE-2025-37740, CVE-2025-37739, CVE-2025-37838,
CVE-2025-37995, CVE-2025-37789, CVE-2024-50258, CVE-2025-37970,
CVE-2025-38024, CVE-2025-23146, CVE-2025-37780, CVE-2022-49168,
CVE-2025-23145, CVE-2024-46774, CVE-2022-49063, CVE-2025-37742,
CVE-2025-37940, CVE-2025-37781, CVE-2025-37796, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.15, linux-gcp, linux-gcp-5.15, linux-gke, linux-gkeop, linux-hwe-5.15, linux-ibm, linux-ibm-5.15, linux-intel-iotg, linux-lowlatency, linux-lowlatency-hwe-5.15, linux-nvidia, linux-nvidia-tegra, linux-nvidia-tegra-5.15, linux-nvidia-tegra-igx, linux-oracle, linux-oracle-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1041-nvidia-tegra", ver:"5.15.0-1041.41~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1041-nvidia-tegra-rt", ver:"5.15.0-1041.41~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1080-ibm", ver:"5.15.0-1080.83~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1085-oracle", ver:"5.15.0-1085.91~20.04.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1087-gcp", ver:"5.15.0-1087.96~20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1088-aws", ver:"5.15.0-1088.95~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-144-generic", ver:"5.15.0-144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-144-generic-64k", ver:"5.15.0-144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-144-generic-lpae", ver:"5.15.0-144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-144-lowlatency", ver:"5.15.0-144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-144-lowlatency-64k", ver:"5.15.0-144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.15.0.1088.95~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-5.15", ver:"5.15.0.1088.95~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.15.0.1087.96~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-5.15", ver:"5.15.0.1087.96~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-5.15", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-5.15", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-20.04", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-20.04", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-5.15", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-20.04", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.15.0.1080.83~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm-5.15", ver:"5.15.0.1080.83~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-5.15", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-5.15", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-20.04", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-20.04", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra", ver:"5.15.0.1041.41~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-5.15", ver:"5.15.0.1041.41~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-rt", ver:"5.15.0.1041.41~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-rt-5.15", ver:"5.15.0.1041.41~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04b", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04c", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04d", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.15.0.1085.91~20.04.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-5.15", ver:"5.15.0.1085.91~20.04.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-5.15", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-20.04", ver:"5.15.0.144.157~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1030-nvidia-tegra-igx", ver:"5.15.0-1030.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1030-nvidia-tegra-igx-rt", ver:"5.15.0-1030.30", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1041-nvidia-tegra", ver:"5.15.0-1041.41", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1041-nvidia-tegra-rt", ver:"5.15.0-1041.41", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1070-gkeop", ver:"5.15.0-1070.78", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1080-ibm", ver:"5.15.0-1080.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1082-nvidia", ver:"5.15.0-1082.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1082-nvidia-lowlatency", ver:"5.15.0-1082.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1083-intel-iotg", ver:"5.15.0-1083.89", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1085-gke", ver:"5.15.0-1085.91", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1085-oracle", ver:"5.15.0-1085.91", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1087-gcp", ver:"5.15.0-1087.96", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1088-aws", ver:"5.15.0-1088.95", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1088-aws-64k", ver:"5.15.0-1088.95", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-144-generic", ver:"5.15.0-144.157", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-144-generic-64k", ver:"5.15.0-144.157", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-144-generic-lpae", ver:"5.15.0-144.157", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-144-lowlatency", ver:"5.15.0-144.157", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-144-lowlatency-64k", ver:"5.15.0-144.157", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-5.15", ver:"5.15.0.1088.91", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k-5.15", ver:"5.15.0.1088.91", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k-lts-22.04", ver:"5.15.0.1088.91", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-22.04", ver:"5.15.0.1088.91", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-5.15", ver:"5.15.0.1087.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-22.04", ver:"5.15.0.1087.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.15.0.144.141", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-5.15", ver:"5.15.0.144.141", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.15.0.144.141", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-5.15", ver:"5.15.0.144.141", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.15.0.144.141", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-5.15", ver:"5.15.0.144.141", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.15.0.1085.84", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.15", ver:"5.15.0.1085.84", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.15.0.1070.69", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.15", ver:"5.15.0.1070.69", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.15.0.1080.76", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm-5.15", ver:"5.15.0.1080.76", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1083.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg-5.15", ver:"5.15.0.1083.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.15.0.144.130", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-5.15", ver:"5.15.0.144.130", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"5.15.0.144.130", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-5.15", ver:"5.15.0.144.130", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia", ver:"5.15.0.1082.82", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-5.15", ver:"5.15.0.1082.82", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-lowlatency", ver:"5.15.0.1082.82", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-lowlatency-5.15", ver:"5.15.0.1082.82", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra", ver:"5.15.0.1041.41", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-5.15", ver:"5.15.0.1041.41", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-igx", ver:"5.15.0.1030.32", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-igx-5.15", ver:"5.15.0.1030.32", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-igx-rt", ver:"5.15.0.1030.32", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-igx-rt-5.15", ver:"5.15.0.1030.32", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-rt", ver:"5.15.0.1041.41", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-rt-5.15", ver:"5.15.0.1041.41", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-5.15", ver:"5.15.0.1085.81", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-22.04", ver:"5.15.0.1085.81", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.15.0.144.141", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-5.15", ver:"5.15.0.144.141", rls:"UBUNTU22.04 LTS"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7514.1");
  script_cve_id("CVE-2024-36476", "CVE-2024-38608", "CVE-2024-39282", "CVE-2024-41013", "CVE-2024-47408", "CVE-2024-47736", "CVE-2024-49568", "CVE-2024-49571", "CVE-2024-53125", "CVE-2024-53179", "CVE-2024-53685", "CVE-2024-53687", "CVE-2024-53690", "CVE-2024-54193", "CVE-2024-54455", "CVE-2024-54460", "CVE-2024-54683", "CVE-2024-55639", "CVE-2024-55881", "CVE-2024-55916", "CVE-2024-56369", "CVE-2024-56372", "CVE-2024-56652", "CVE-2024-56654", "CVE-2024-56656", "CVE-2024-56657", "CVE-2024-56659", "CVE-2024-56660", "CVE-2024-56662", "CVE-2024-56664", "CVE-2024-56665", "CVE-2024-56667", "CVE-2024-56670", "CVE-2024-56675", "CVE-2024-56709", "CVE-2024-56710", "CVE-2024-56715", "CVE-2024-56716", "CVE-2024-56717", "CVE-2024-56718", "CVE-2024-56758", "CVE-2024-56759", "CVE-2024-56760", "CVE-2024-56761", "CVE-2024-56763", "CVE-2024-56764", "CVE-2024-56767", "CVE-2024-56769", "CVE-2024-56770", "CVE-2024-57791", "CVE-2024-57792", "CVE-2024-57793", "CVE-2024-57801", "CVE-2024-57802", "CVE-2024-57804", "CVE-2024-57805", "CVE-2024-57806", "CVE-2024-57807", "CVE-2024-57841", "CVE-2024-57879", "CVE-2024-57882", "CVE-2024-57883", "CVE-2024-57884", "CVE-2024-57885", "CVE-2024-57887", "CVE-2024-57888", "CVE-2024-57889", "CVE-2024-57890", "CVE-2024-57892", "CVE-2024-57893", "CVE-2024-57895", "CVE-2024-57896", "CVE-2024-57897", "CVE-2024-57898", "CVE-2024-57899", "CVE-2024-57900", "CVE-2024-57901", "CVE-2024-57902", "CVE-2024-57903", "CVE-2024-57904", "CVE-2024-57906", "CVE-2024-57907", "CVE-2024-57908", "CVE-2024-57910", "CVE-2024-57911", "CVE-2024-57912", "CVE-2024-57913", "CVE-2024-57916", "CVE-2024-57917", "CVE-2024-57925", "CVE-2024-57926", "CVE-2024-57929", "CVE-2024-57931", "CVE-2024-57932", "CVE-2024-57933", "CVE-2024-57938", "CVE-2024-57939", "CVE-2024-57940", "CVE-2024-57945", "CVE-2024-57946", "CVE-2024-58087", "CVE-2024-58237", "CVE-2025-21631", "CVE-2025-21632", "CVE-2025-21634", "CVE-2025-21635", "CVE-2025-21636", "CVE-2025-21637", "CVE-2025-21638", "CVE-2025-21639", "CVE-2025-21640", "CVE-2025-21642", "CVE-2025-21643", "CVE-2025-21645", "CVE-2025-21646", "CVE-2025-21647", "CVE-2025-21648", "CVE-2025-21649", "CVE-2025-21650", "CVE-2025-21651", "CVE-2025-21652", "CVE-2025-21653", "CVE-2025-21654", "CVE-2025-21655", "CVE-2025-21656", "CVE-2025-21658", "CVE-2025-21659", "CVE-2025-21660", "CVE-2025-21662", "CVE-2025-21663", "CVE-2025-21664", "CVE-2025-21888", "CVE-2025-21938", "CVE-2025-21971");
  script_tag(name:"creation_date", value:"2025-05-19 04:08:41 +0000 (Mon, 19 May 2025)");
  script_version("2025-05-19T05:40:32+0000");
  script_tag(name:"last_modification", value:"2025-05-19 05:40:32 +0000 (Mon, 19 May 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-13 16:22:01 +0000 (Thu, 13 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-7514-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7514-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7514-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-nvidia, linux-nvidia-6.8, linux-nvidia-lowlatency' package(s) announced via the USN-7514-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - RISC-V architecture,
 - x86 architecture,
 - Block layer subsystem,
 - Compute Acceleration Framework,
 - ACPI drivers,
 - Drivers core,
 - Ublk userspace block driver,
 - Virtio block driver,
 - DMA engine subsystem,
 - GPU drivers,
 - Microsoft Hyper-V drivers,
 - Hardware monitoring drivers,
 - IIO ADC drivers,
 - IIO subsystem,
 - InfiniBand drivers,
 - Multiple devices driver,
 - Media drivers,
 - Microchip PCI driver,
 - Network drivers,
 - Mellanox network drivers,
 - STMicroelectronics network drivers,
 - PCI subsystem,
 - Pin controllers subsystem,
 - x86 platform drivers,
 - Power supply drivers,
 - SCSI subsystem,
 - USB Gadget drivers,
 - TDX Guest driver,
 - AFS file system,
 - BTRFS file system,
 - Ceph distributed file system,
 - EROFS file system,
 - File systems infrastructure,
 - Network file systems library,
 - NILFS2 file system,
 - Overlay file system,
 - SMB network file system,
 - VLANs driver,
 - Memory management,
 - LAPB network protocol,
 - io_uring subsystem,
 - BPF subsystem,
 - Control group (cgroup),
 - Tracing infrastructure,
 - Workqueue subsystem,
 - Bluetooth subsystem,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - MAC80211 subsystem,
 - Multipath TCP,
 - Netfilter,
 - NET/ROM layer,
 - Packet sockets,
 - RDS protocol,
 - Network traffic control,
 - SCTP protocol,
 - SMC sockets,
 - Wireless networking,
 - SELinux security module,
 - ALSA framework,
 - SOF drivers,
(CVE-2024-57901, CVE-2024-57889, CVE-2024-53687, CVE-2024-57804,
CVE-2024-56709, CVE-2025-21631, CVE-2024-57908, CVE-2025-21645,
CVE-2024-47736, CVE-2024-57896, CVE-2024-38608, CVE-2025-21637,
CVE-2024-57898, CVE-2024-53179, CVE-2024-56710, CVE-2024-57802,
CVE-2025-21659, CVE-2024-57903, CVE-2024-56764, CVE-2024-57892,
CVE-2024-56717, CVE-2024-57938, CVE-2024-55881, CVE-2024-56718,
CVE-2025-21647, CVE-2024-39282, CVE-2024-57879, CVE-2025-21643,
CVE-2024-57792, CVE-2024-56657, CVE-2024-53685, CVE-2024-54455,
CVE-2024-56656, CVE-2025-21638, CVE-2024-57907, CVE-2024-54193,
CVE-2024-57806, CVE-2025-21655, CVE-2024-56670, CVE-2024-57904,
CVE-2024-56369, CVE-2024-57945, CVE-2024-56759, CVE-2024-56716,
CVE-2025-21651, CVE-2024-57911, CVE-2024-56372, CVE-2024-36476,
CVE-2024-57888, CVE-2024-41013, CVE-2024-57882, CVE-2025-21636,
CVE-2025-21971, CVE-2024-57841, CVE-2024-56760, CVE-2024-57805,
CVE-2024-56758, CVE-2025-21648, CVE-2024-57917, CVE-2024-57913,
CVE-2025-21658, CVE-2024-57926, CVE-2024-57939, CVE-2024-57791,
CVE-2024-57883, CVE-2024-58087, CVE-2024-56665, CVE-2024-57887,
CVE-2025-21635, CVE-2024-56662, CVE-2024-57893, CVE-2024-57916,
CVE-2024-56675, CVE-2024-56763, CVE-2024-56664, CVE-2024-53690,
CVE-2025-21663, CVE-2024-56761, CVE-2024-57910, CVE-2025-21660,
CVE-2024-57885, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-nvidia, linux-nvidia-6.8, linux-nvidia-lowlatency' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1028-nvidia", ver:"6.8.0-1028.31~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1028-nvidia-64k", ver:"6.8.0-1028.31~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-6.8", ver:"6.8.0-1028.31~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-6.8", ver:"6.8.0-1028.31~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-hwe-22.04", ver:"6.8.0-1028.31~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-hwe-22.04", ver:"6.8.0-1028.31~22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1028-nvidia", ver:"6.8.0-1028.31", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1028-nvidia-64k", ver:"6.8.0-1028.31", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1028-nvidia-lowlatency", ver:"6.8.0-1028.31.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1028-nvidia-lowlatency-64k", ver:"6.8.0-1028.31.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia", ver:"6.8.0-1028.31", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k", ver:"6.8.0-1028.31", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-lowlatency", ver:"6.8.0-1028.31.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-lowlatency-64k", ver:"6.8.0-1028.31.1", rls:"UBUNTU24.04 LTS"))) {
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

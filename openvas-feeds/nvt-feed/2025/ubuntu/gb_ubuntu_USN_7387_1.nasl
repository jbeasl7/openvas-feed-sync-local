# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7387.1");
  script_cve_id("CVE-2022-49034", "CVE-2024-36476", "CVE-2024-36899", "CVE-2024-42315", "CVE-2024-43098", "CVE-2024-43900", "CVE-2024-44938", "CVE-2024-45828", "CVE-2024-46784", "CVE-2024-46809", "CVE-2024-46841", "CVE-2024-46871", "CVE-2024-47143", "CVE-2024-47408", "CVE-2024-47707", "CVE-2024-47730", "CVE-2024-48881", "CVE-2024-49571", "CVE-2024-49925", "CVE-2024-49950", "CVE-2024-49974", "CVE-2024-49996", "CVE-2024-49998", "CVE-2024-50051", "CVE-2024-50055", "CVE-2024-50121", "CVE-2024-50242", "CVE-2024-50275", "CVE-2024-50283", "CVE-2024-50304", "CVE-2024-52332", "CVE-2024-53096", "CVE-2024-53099", "CVE-2024-53112", "CVE-2024-53113", "CVE-2024-53119", "CVE-2024-53120", "CVE-2024-53121", "CVE-2024-53122", "CVE-2024-53124", "CVE-2024-53125", "CVE-2024-53127", "CVE-2024-53129", "CVE-2024-53130", "CVE-2024-53131", "CVE-2024-53135", "CVE-2024-53136", "CVE-2024-53138", "CVE-2024-53140", "CVE-2024-53142", "CVE-2024-53145", "CVE-2024-53146", "CVE-2024-53148", "CVE-2024-53150", "CVE-2024-53151", "CVE-2024-53155", "CVE-2024-53156", "CVE-2024-53157", "CVE-2024-53158", "CVE-2024-53161", "CVE-2024-53165", "CVE-2024-53171", "CVE-2024-53172", "CVE-2024-53173", "CVE-2024-53174", "CVE-2024-53180", "CVE-2024-53181", "CVE-2024-53183", "CVE-2024-53184", "CVE-2024-53194", "CVE-2024-53197", "CVE-2024-53198", "CVE-2024-53206", "CVE-2024-53214", "CVE-2024-53215", "CVE-2024-53217", "CVE-2024-53226", "CVE-2024-53227", "CVE-2024-53237", "CVE-2024-53239", "CVE-2024-53680", "CVE-2024-53685", "CVE-2024-53690", "CVE-2024-55881", "CVE-2024-55916", "CVE-2024-56369", "CVE-2024-56531", "CVE-2024-56532", "CVE-2024-56533", "CVE-2024-56539", "CVE-2024-56548", "CVE-2024-56558", "CVE-2024-56562", "CVE-2024-56567", "CVE-2024-56568", "CVE-2024-56569", "CVE-2024-56570", "CVE-2024-56572", "CVE-2024-56574", "CVE-2024-56575", "CVE-2024-56576", "CVE-2024-56578", "CVE-2024-56581", "CVE-2024-56586", "CVE-2024-56587", "CVE-2024-56589", "CVE-2024-56590", "CVE-2024-56593", "CVE-2024-56594", "CVE-2024-56595", "CVE-2024-56596", "CVE-2024-56597", "CVE-2024-56598", "CVE-2024-56600", "CVE-2024-56601", "CVE-2024-56602", "CVE-2024-56603", "CVE-2024-56605", "CVE-2024-56606", "CVE-2024-56610", "CVE-2024-56614", "CVE-2024-56615", "CVE-2024-56616", "CVE-2024-56619", "CVE-2024-56622", "CVE-2024-56623", "CVE-2024-56625", "CVE-2024-56626", "CVE-2024-56627", "CVE-2024-56629", "CVE-2024-56630", "CVE-2024-56631", "CVE-2024-56633", "CVE-2024-56634", "CVE-2024-56636", "CVE-2024-56637", "CVE-2024-56640", "CVE-2024-56642", "CVE-2024-56643", "CVE-2024-56644", "CVE-2024-56645", "CVE-2024-56648", "CVE-2024-56650", "CVE-2024-56659", "CVE-2024-56662", "CVE-2024-56670", "CVE-2024-56678", "CVE-2024-56679", "CVE-2024-56681", "CVE-2024-56688", "CVE-2024-56690", "CVE-2024-56691", "CVE-2024-56693", "CVE-2024-56694", "CVE-2024-56698", "CVE-2024-56700", "CVE-2024-56701", "CVE-2024-56704", "CVE-2024-56705", "CVE-2024-56708", "CVE-2024-56715", "CVE-2024-56716", "CVE-2024-56720", "CVE-2024-56723", "CVE-2024-56724", "CVE-2024-56726", "CVE-2024-56728", "CVE-2024-56739", "CVE-2024-56745", "CVE-2024-56746", "CVE-2024-56747", "CVE-2024-56748", "CVE-2024-56754", "CVE-2024-56756", "CVE-2024-56759", "CVE-2024-56763", "CVE-2024-56767", "CVE-2024-56769", "CVE-2024-56770", "CVE-2024-56774", "CVE-2024-56776", "CVE-2024-56777", "CVE-2024-56778", "CVE-2024-56779", "CVE-2024-56780", "CVE-2024-56781", "CVE-2024-56785", "CVE-2024-56787", "CVE-2024-57791", "CVE-2024-57792", "CVE-2024-57802", "CVE-2024-57807", "CVE-2024-57838", "CVE-2024-57841", "CVE-2024-57849", "CVE-2024-57850", "CVE-2024-57874", "CVE-2024-57882", "CVE-2024-57884", "CVE-2024-57889", "CVE-2024-57890", "CVE-2024-57892", "CVE-2024-57896", "CVE-2024-57897", "CVE-2024-57900", "CVE-2024-57901", "CVE-2024-57902", "CVE-2024-57903", "CVE-2024-57904", "CVE-2024-57906", "CVE-2024-57907", "CVE-2024-57908", "CVE-2024-57910", "CVE-2024-57911", "CVE-2024-57912", "CVE-2024-57913", "CVE-2024-57917", "CVE-2024-57922", "CVE-2024-57925", "CVE-2024-57929", "CVE-2024-57931", "CVE-2024-57938", "CVE-2024-57939", "CVE-2024-57940", "CVE-2024-57946", "CVE-2024-57948", "CVE-2024-57951", "CVE-2024-58087", "CVE-2025-21631", "CVE-2025-21636", "CVE-2025-21637", "CVE-2025-21638", "CVE-2025-21639", "CVE-2025-21640", "CVE-2025-21646", "CVE-2025-21648", "CVE-2025-21653", "CVE-2025-21664", "CVE-2025-21665", "CVE-2025-21666", "CVE-2025-21669", "CVE-2025-21678", "CVE-2025-21680", "CVE-2025-21683", "CVE-2025-21687", "CVE-2025-21689", "CVE-2025-21690", "CVE-2025-21692", "CVE-2025-21694", "CVE-2025-21697", "CVE-2025-21699");
  script_tag(name:"creation_date", value:"2025-03-28 04:04:17 +0000 (Fri, 28 Mar 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-13 16:22:01 +0000 (Thu, 13 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-7387-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7387-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7387-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-gke, linux-gkeop, linux-ibm, linux-intel-iotg, linux-lowlatency, linux-lowlatency-hwe-5.15, linux-nvidia, linux-oracle, linux-oracle-5.15, linux-raspi' package(s) announced via the USN-7387-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - MIPS architecture,
 - PowerPC architecture,
 - RISC-V architecture,
 - S390 architecture,
 - SuperH RISC architecture,
 - User-Mode Linux (UML),
 - x86 architecture,
 - Block layer subsystem,
 - Cryptographic API,
 - ACPI drivers,
 - Drivers core,
 - RAM backed block device driver,
 - Virtio block driver,
 - Data acquisition framework and drivers,
 - Hardware crypto device drivers,
 - DMA engine subsystem,
 - EDAC drivers,
 - ARM SCPI message protocol,
 - GPIO subsystem,
 - GPU drivers,
 - HID subsystem,
 - Microsoft Hyper-V drivers,
 - I3C subsystem,
 - IIO ADC drivers,
 - IIO subsystem,
 - InfiniBand drivers,
 - IOMMU subsystem,
 - LED subsystem,
 - Multiple devices driver,
 - Media drivers,
 - Multifunction device drivers,
 - MMC subsystem,
 - MTD block device drivers,
 - Network drivers,
 - Mellanox network drivers,
 - Microsoft Azure Network Adapter (MANA) driver,
 - NVME drivers,
 - PCI subsystem,
 - Pin controllers subsystem,
 - x86 platform drivers,
 - Power supply drivers,
 - Real Time Clock drivers,
 - SCSI subsystem,
 - SuperH / SH-Mobile drivers,
 - i.MX SoC drivers,
 - QCOM SoC drivers,
 - SPI subsystem,
 - Media staging drivers,
 - UFS subsystem,
 - DesignWare USB3 driver,
 - USB Gadget drivers,
 - USB Serial drivers,
 - USB Type-C Port Controller Manager driver,
 - VFIO drivers,
 - Framebuffer layer,
 - Xen hypervisor drivers,
 - AFS file system,
 - BTRFS file system,
 - Ceph distributed file system,
 - File systems infrastructure,
 - F2FS file system,
 - GFS2 file system,
 - JFFS2 file system,
 - JFS file system,
 - Network file system (NFS) client,
 - Network file system (NFS) server daemon,
 - NILFS2 file system,
 - NTFS3 file system,
 - Overlay file system,
 - Proc file system,
 - Diskquota system,
 - SMB network file system,
 - UBI file system,
 - Timer subsystem,
 - VLANs driver,
 - LAPB network protocol,
 - Kernel init infrastructure,
 - BPF subsystem,
 - Kernel CPU control infrastructure,
 - DMA mapping infrastructure,
 - KCSAN framework,
 - Tracing infrastructure,
 - Memory management,
 - 9P file system network protocol,
 - Bluetooth subsystem,
 - CAN network layer,
 - Networking core,
 - DCCP (Datagram Congestion Control Protocol),
 - Distributed Switch Architecture,
 - HSR network protocol,
 - IEEE802154.4 network protocol,
 - IPv4 networking,
 - IPv6 networking,
 - IEEE 802.15.4 subsystem,
 - Multipath TCP,
 - Netfilter,
 - Netlink,
 - NET/ROM layer,
 - Packet sockets,
 - Network traffic control,
 - SCTP protocol,
 - SMC sockets,
 - Sun RPC protocol,
 - TIPC protocol,
 - VMware vSockets driver,
 - eXpress Data Path,
 - SELinux security module,
 - ALSA framework,
 - USB sound devices,
(CVE-2024-56558, CVE-2024-53227, CVE-2024-53130, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-gke, linux-gkeop, linux-ibm, linux-intel-iotg, linux-lowlatency, linux-lowlatency-hwe-5.15, linux-nvidia, linux-oracle, linux-oracle-5.15, linux-raspi' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1077-oracle", ver:"5.15.0-1077.83~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-135-lowlatency", ver:"5.15.0-135.146~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-135-lowlatency-64k", ver:"5.15.0-135.146~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-20.04", ver:"5.15.0.135.146~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-20.04", ver:"5.15.0.135.146~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.15.0.1077.83~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1062-gkeop", ver:"5.15.0-1062.70", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1072-ibm", ver:"5.15.0-1072.75", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1074-nvidia", ver:"5.15.0-1074.75", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1074-nvidia-lowlatency", ver:"5.15.0-1074.75", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1074-raspi", ver:"5.15.0-1074.77", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1075-intel-iotg", ver:"5.15.0-1075.81", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1077-gke", ver:"5.15.0-1077.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1077-oracle", ver:"5.15.0-1077.83", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1079-gcp", ver:"5.15.0-1079.88", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1080-aws", ver:"5.15.0-1080.87", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1084-azure", ver:"5.15.0-1084.93", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-135-generic", ver:"5.15.0-135.146", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-135-generic-64k", ver:"5.15.0-135.146", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-135-generic-lpae", ver:"5.15.0-135.146", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-135-lowlatency", ver:"5.15.0-135.146", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-135-lowlatency-64k", ver:"5.15.0-135.146", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-22.04", ver:"5.15.0.1080.82", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-22.04", ver:"5.15.0.1084.82", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-22.04", ver:"5.15.0.1079.75", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.15.0.135.133", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.15.0.135.133", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.15.0.135.133", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.15.0.1077.76", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.15", ver:"5.15.0.1077.76", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.15.0.1062.61", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.15", ver:"5.15.0.1062.61", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.15.0.1072.68", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1075.75", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.15.0.135.122", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"5.15.0.135.122", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia", ver:"5.15.0.1074.74", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-lowlatency", ver:"5.15.0.1074.74", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-22.04", ver:"5.15.0.1077.73", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.15.0.1074.72", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.15.0.1074.72", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.15.0.135.133", rls:"UBUNTU22.04 LTS"))) {
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

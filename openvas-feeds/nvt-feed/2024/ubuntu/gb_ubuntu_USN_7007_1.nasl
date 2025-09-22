# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7007.1");
  script_cve_id("CVE-2022-48772", "CVE-2023-52884", "CVE-2023-52887", "CVE-2024-23848", "CVE-2024-25741", "CVE-2024-31076", "CVE-2024-33621", "CVE-2024-33847", "CVE-2024-34027", "CVE-2024-34777", "CVE-2024-35247", "CVE-2024-35927", "CVE-2024-36014", "CVE-2024-36015", "CVE-2024-36032", "CVE-2024-36270", "CVE-2024-36286", "CVE-2024-36489", "CVE-2024-36894", "CVE-2024-36971", "CVE-2024-36972", "CVE-2024-36974", "CVE-2024-36978", "CVE-2024-37078", "CVE-2024-37356", "CVE-2024-38381", "CVE-2024-38546", "CVE-2024-38547", "CVE-2024-38548", "CVE-2024-38549", "CVE-2024-38550", "CVE-2024-38552", "CVE-2024-38555", "CVE-2024-38558", "CVE-2024-38559", "CVE-2024-38560", "CVE-2024-38565", "CVE-2024-38567", "CVE-2024-38571", "CVE-2024-38573", "CVE-2024-38578", "CVE-2024-38579", "CVE-2024-38580", "CVE-2024-38582", "CVE-2024-38583", "CVE-2024-38586", "CVE-2024-38587", "CVE-2024-38588", "CVE-2024-38589", "CVE-2024-38590", "CVE-2024-38591", "CVE-2024-38596", "CVE-2024-38597", "CVE-2024-38598", "CVE-2024-38599", "CVE-2024-38601", "CVE-2024-38605", "CVE-2024-38607", "CVE-2024-38610", "CVE-2024-38612", "CVE-2024-38613", "CVE-2024-38615", "CVE-2024-38618", "CVE-2024-38619", "CVE-2024-38621", "CVE-2024-38623", "CVE-2024-38624", "CVE-2024-38627", "CVE-2024-38633", "CVE-2024-38634", "CVE-2024-38635", "CVE-2024-38637", "CVE-2024-38659", "CVE-2024-38661", "CVE-2024-38662", "CVE-2024-38780", "CVE-2024-39276", "CVE-2024-39277", "CVE-2024-39301", "CVE-2024-39466", "CVE-2024-39467", "CVE-2024-39468", "CVE-2024-39469", "CVE-2024-39471", "CVE-2024-39475", "CVE-2024-39480", "CVE-2024-39482", "CVE-2024-39487", "CVE-2024-39488", "CVE-2024-39489", "CVE-2024-39490", "CVE-2024-39493", "CVE-2024-39495", "CVE-2024-39499", "CVE-2024-39500", "CVE-2024-39501", "CVE-2024-39502", "CVE-2024-39503", "CVE-2024-39505", "CVE-2024-39506", "CVE-2024-39507", "CVE-2024-39509", "CVE-2024-40901", "CVE-2024-40902", "CVE-2024-40904", "CVE-2024-40905", "CVE-2024-40908", "CVE-2024-40911", "CVE-2024-40912", "CVE-2024-40914", "CVE-2024-40916", "CVE-2024-40927", "CVE-2024-40929", "CVE-2024-40931", "CVE-2024-40932", "CVE-2024-40934", "CVE-2024-40937", "CVE-2024-40941", "CVE-2024-40942", "CVE-2024-40943", "CVE-2024-40945", "CVE-2024-40954", "CVE-2024-40956", "CVE-2024-40957", "CVE-2024-40958", "CVE-2024-40959", "CVE-2024-40960", "CVE-2024-40961", "CVE-2024-40963", "CVE-2024-40967", "CVE-2024-40968", "CVE-2024-40970", "CVE-2024-40971", "CVE-2024-40974", "CVE-2024-40976", "CVE-2024-40978", "CVE-2024-40980", "CVE-2024-40981", "CVE-2024-40983", "CVE-2024-40984", "CVE-2024-40987", "CVE-2024-40988", "CVE-2024-40990", "CVE-2024-40994", "CVE-2024-40995", "CVE-2024-41000", "CVE-2024-41002", "CVE-2024-41004", "CVE-2024-41005", "CVE-2024-41006", "CVE-2024-41007", "CVE-2024-41027", "CVE-2024-41034", "CVE-2024-41035", "CVE-2024-41040", "CVE-2024-41041", "CVE-2024-41044", "CVE-2024-41046", "CVE-2024-41047", "CVE-2024-41048", "CVE-2024-41049", "CVE-2024-41055", "CVE-2024-41087", "CVE-2024-41089", "CVE-2024-41092", "CVE-2024-41093", "CVE-2024-41095", "CVE-2024-41097", "CVE-2024-42068", "CVE-2024-42070", "CVE-2024-42076", "CVE-2024-42077", "CVE-2024-42080", "CVE-2024-42082", "CVE-2024-42084", "CVE-2024-42085", "CVE-2024-42086", "CVE-2024-42087", "CVE-2024-42089", "CVE-2024-42090", "CVE-2024-42092", "CVE-2024-42093", "CVE-2024-42094", "CVE-2024-42095", "CVE-2024-42096", "CVE-2024-42097", "CVE-2024-42098", "CVE-2024-42101", "CVE-2024-42102", "CVE-2024-42104", "CVE-2024-42105", "CVE-2024-42106", "CVE-2024-42109", "CVE-2024-42115", "CVE-2024-42119", "CVE-2024-42120", "CVE-2024-42121", "CVE-2024-42124", "CVE-2024-42127", "CVE-2024-42130", "CVE-2024-42131", "CVE-2024-42137", "CVE-2024-42140", "CVE-2024-42145", "CVE-2024-42148", "CVE-2024-42152", "CVE-2024-42153", "CVE-2024-42154", "CVE-2024-42157", "CVE-2024-42161", "CVE-2024-42223", "CVE-2024-42224", "CVE-2024-42225", "CVE-2024-42229", "CVE-2024-42232", "CVE-2024-42236", "CVE-2024-42240", "CVE-2024-42244", "CVE-2024-42247");
  script_tag(name:"creation_date", value:"2024-09-16 04:07:54 +0000 (Mon, 16 Sep 2024)");
  script_version("2024-10-03T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-10-03 05:05:33 +0000 (Thu, 03 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-05 17:46:27 +0000 (Thu, 05 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7007-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7007-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7007-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.15, linux-gcp, linux-gcp-5.15, linux-gke, linux-gkeop, linux-gkeop-5.15, linux-hwe-5.15, linux-ibm, linux-intel-iotg, linux-intel-iotg-5.15, linux-kvm, linux-nvidia, linux-oracle, linux-raspi' package(s) announced via the USN-7007-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chenyuan Yang discovered that the CEC driver driver in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2024-23848)

Chenyuan Yang discovered that the USB Gadget subsystem in the Linux kernel
did not properly check for the device to be enabled before writing. A local
attacker could possibly use this to cause a denial of service.
(CVE-2024-25741)

It was discovered that the JFS file system contained an out-of-bounds read
vulnerability when printing xattr debug information. A local attacker could
use this to cause a denial of service (system crash). (CVE-2024-40902)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - M68K architecture,
 - MIPS architecture,
 - PowerPC architecture,
 - RISC-V architecture,
 - x86 architecture,
 - Block layer subsystem,
 - Cryptographic API,
 - Accessibility subsystem,
 - ACPI drivers,
 - Serial ATA and Parallel ATA drivers,
 - Drivers core,
 - Bluetooth drivers,
 - Character device driver,
 - CPU frequency scaling framework,
 - Hardware crypto device drivers,
 - Buffer Sharing and Synchronization framework,
 - DMA engine subsystem,
 - FPGA Framework,
 - GPIO subsystem,
 - GPU drivers,
 - Greybus drivers,
 - HID subsystem,
 - HW tracing,
 - I2C subsystem,
 - IIO subsystem,
 - InfiniBand drivers,
 - Input Device (Mouse) drivers,
 - Macintosh device drivers,
 - Multiple devices driver,
 - Media drivers,
 - VMware VMCI Driver,
 - Network drivers,
 - Near Field Communication (NFC) drivers,
 - NVME drivers,
 - Pin controllers subsystem,
 - PTP clock framework,
 - S/390 drivers,
 - SCSI drivers,
 - SoundWire subsystem,
 - Greybus lights staging drivers,
 - Media staging drivers,
 - Thermal drivers,
 - TTY drivers,
 - USB subsystem,
 - DesignWare USB3 driver,
 - Framebuffer layer,
 - ACRN Hypervisor Service Module driver,
 - eCrypt file system,
 - File systems infrastructure,
 - Ext4 file system,
 - F2FS file system,
 - JFFS2 file system,
 - JFS file system,
 - NILFS2 file system,
 - NTFS3 file system,
 - SMB network file system,
 - IOMMU subsystem,
 - Memory management,
 - Netfilter,
 - BPF subsystem,
 - Kernel debugger infrastructure,
 - DMA mapping infrastructure,
 - IRQ subsystem,
 - Tracing infrastructure,
 - 9P file system network protocol,
 - B.A.T.M.A.N. meshing protocol,
 - CAN network layer,
 - Ceph Core library,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - IUCV driver,
 - MAC80211 subsystem,
 - Multipath TCP,
 - NET/ROM layer,
 - NFC subsystem,
 - Open vSwitch,
 - Network traffic control,
 - TIPC protocol,
 - TLS protocol,
 - Unix domain sockets,
 - Wireless networking,
 - XFRM subsystem,
 - ALSA framework,
 - SoC Audio for Freescale CPUs ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.15, linux-gcp, linux-gcp-5.15, linux-gke, linux-gkeop, linux-gkeop-5.15, linux-hwe-5.15, linux-ibm, linux-intel-iotg, linux-intel-iotg-5.15, linux-kvm, linux-nvidia, linux-oracle, linux-raspi' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1052-gkeop", ver:"5.15.0-1052.59~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1064-intel-iotg", ver:"5.15.0-1064.70~20.04.1+1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1068-gcp", ver:"5.15.0-1068.76~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1069-aws", ver:"5.15.0-1069.75~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-121-generic", ver:"5.15.0-121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-121-generic-64k", ver:"5.15.0-121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-121-generic-lpae", ver:"5.15.0-121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.15.0.1069.75~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.15.0.1068.76~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-20.04", ver:"5.15.0.121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-20.04", ver:"5.15.0.121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-20.04", ver:"5.15.0.121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.15", ver:"5.15.0.1052.59~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel", ver:"5.15.0.1064.70~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1064.70~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.15.0.121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04b", ver:"5.15.0.121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04c", ver:"5.15.0.121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04d", ver:"5.15.0.121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-20.04", ver:"5.15.0.121.131~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1052-gkeop", ver:"5.15.0-1052.59", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1062-ibm", ver:"5.15.0-1062.65", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1062-raspi", ver:"5.15.0-1062.65", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1064-intel-iotg", ver:"5.15.0-1064.70", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1064-nvidia", ver:"5.15.0-1064.65", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1064-nvidia-lowlatency", ver:"5.15.0-1064.65", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1066-gke", ver:"5.15.0-1066.72", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1066-kvm", ver:"5.15.0-1066.71", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1067-oracle", ver:"5.15.0-1067.73", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1068-gcp", ver:"5.15.0-1068.76", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1069-aws", ver:"5.15.0-1069.75", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-121-generic", ver:"5.15.0-121.131", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-121-generic-64k", ver:"5.15.0-121.131", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-121-generic-lpae", ver:"5.15.0-121.131", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-22.04", ver:"5.15.0.1069.69", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-22.04", ver:"5.15.0.1068.64", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.15.0.121.121", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.15.0.121.121", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.15.0.121.121", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"5.15.0.1066.65", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-5.15", ver:"5.15.0.1066.65", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"5.15.0.1052.51", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-5.15", ver:"5.15.0.1052.51", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.15.0.1062.58", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1064.64", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.15.0.1066.62", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia", ver:"5.15.0.1064.64", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-lowlatency", ver:"5.15.0.1064.64", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-lts-22.04", ver:"5.15.0.1067.63", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.15.0.1062.60", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.15.0.1062.60", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.15.0.121.121", rls:"UBUNTU22.04 LTS"))) {
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

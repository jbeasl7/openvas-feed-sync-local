# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6898.4");
  script_cve_id("CVE-2022-38096", "CVE-2023-52488", "CVE-2023-52699", "CVE-2023-52880", "CVE-2024-23307", "CVE-2024-24857", "CVE-2024-24858", "CVE-2024-24859", "CVE-2024-24861", "CVE-2024-25739", "CVE-2024-26629", "CVE-2024-26642", "CVE-2024-26654", "CVE-2024-26687", "CVE-2024-26810", "CVE-2024-26811", "CVE-2024-26812", "CVE-2024-26813", "CVE-2024-26814", "CVE-2024-26817", "CVE-2024-26828", "CVE-2024-26922", "CVE-2024-26923", "CVE-2024-26925", "CVE-2024-26926", "CVE-2024-26929", "CVE-2024-26931", "CVE-2024-26934", "CVE-2024-26935", "CVE-2024-26937", "CVE-2024-26950", "CVE-2024-26951", "CVE-2024-26955", "CVE-2024-26956", "CVE-2024-26957", "CVE-2024-26958", "CVE-2024-26960", "CVE-2024-26961", "CVE-2024-26964", "CVE-2024-26965", "CVE-2024-26966", "CVE-2024-26969", "CVE-2024-26970", "CVE-2024-26973", "CVE-2024-26974", "CVE-2024-26976", "CVE-2024-26977", "CVE-2024-26981", "CVE-2024-26984", "CVE-2024-26988", "CVE-2024-26989", "CVE-2024-26993", "CVE-2024-26994", "CVE-2024-26996", "CVE-2024-26999", "CVE-2024-27000", "CVE-2024-27001", "CVE-2024-27004", "CVE-2024-27008", "CVE-2024-27009", "CVE-2024-27013", "CVE-2024-27015", "CVE-2024-27016", "CVE-2024-27018", "CVE-2024-27019", "CVE-2024-27020", "CVE-2024-27059", "CVE-2024-27393", "CVE-2024-27395", "CVE-2024-27396", "CVE-2024-27437", "CVE-2024-35785", "CVE-2024-35789", "CVE-2024-35791", "CVE-2024-35796", "CVE-2024-35804", "CVE-2024-35805", "CVE-2024-35806", "CVE-2024-35807", "CVE-2024-35809", "CVE-2024-35813", "CVE-2024-35815", "CVE-2024-35817", "CVE-2024-35819", "CVE-2024-35821", "CVE-2024-35822", "CVE-2024-35823", "CVE-2024-35825", "CVE-2024-35847", "CVE-2024-35849", "CVE-2024-35851", "CVE-2024-35852", "CVE-2024-35853", "CVE-2024-35854", "CVE-2024-35855", "CVE-2024-35857", "CVE-2024-35871", "CVE-2024-35872", "CVE-2024-35877", "CVE-2024-35879", "CVE-2024-35884", "CVE-2024-35885", "CVE-2024-35886", "CVE-2024-35888", "CVE-2024-35890", "CVE-2024-35893", "CVE-2024-35895", "CVE-2024-35896", "CVE-2024-35897", "CVE-2024-35898", "CVE-2024-35899", "CVE-2024-35900", "CVE-2024-35902", "CVE-2024-35905", "CVE-2024-35907", "CVE-2024-35910", "CVE-2024-35912", "CVE-2024-35915", "CVE-2024-35918", "CVE-2024-35922", "CVE-2024-35925", "CVE-2024-35930", "CVE-2024-35933", "CVE-2024-35934", "CVE-2024-35935", "CVE-2024-35936", "CVE-2024-35938", "CVE-2024-35940", "CVE-2024-35944", "CVE-2024-35950", "CVE-2024-35955", "CVE-2024-35958", "CVE-2024-35960", "CVE-2024-35969", "CVE-2024-35970", "CVE-2024-35973", "CVE-2024-35976", "CVE-2024-35978", "CVE-2024-35982", "CVE-2024-35984", "CVE-2024-35988", "CVE-2024-35989", "CVE-2024-35990", "CVE-2024-35997", "CVE-2024-36004", "CVE-2024-36005", "CVE-2024-36006", "CVE-2024-36007", "CVE-2024-36008", "CVE-2024-36020", "CVE-2024-36025", "CVE-2024-36029");
  script_tag(name:"creation_date", value:"2024-07-24 04:08:24 +0000 (Wed, 24 Jul 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-30 19:47:30 +0000 (Mon, 30 Dec 2024)");

  script_name("Ubuntu: Security Advisory (USN-6898-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6898-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6898-4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-5.15' package(s) announced via the USN-6898-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ziming Zhang discovered that the DRM driver for VMware Virtual GPU did not
properly handle certain error conditions, leading to a NULL pointer
dereference. A local attacker could possibly trigger this vulnerability to
cause a denial of service. (CVE-2022-38096)

Gui-Dong Han discovered that the software RAID driver in the Linux kernel
contained a race condition, leading to an integer overflow vulnerability. A
privileged attacker could possibly use this to cause a denial of service
(system crash). (CVE-2024-23307)

It was discovered that a race condition existed in the Bluetooth subsystem
in the Linux kernel when modifying certain settings values through debugfs.
A privileged local attacker could use this to cause a denial of service.
(CVE-2024-24857, CVE-2024-24858, CVE-2024-24859)

Bai Jiaju discovered that the Xceive XC4000 silicon tuner device driver in
the Linux kernel contained a race condition, leading to an integer overflow
vulnerability. An attacker could possibly use this to cause a denial of
service (system crash). (CVE-2024-24861)

Chenyuan Yang discovered that the Unsorted Block Images (UBI) flash device
volume management subsystem did not properly validate logical eraseblock
sizes in certain situations. An attacker could possibly use this to cause a
denial of service (system crash). (CVE-2024-25739)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - RISC-V architecture,
 - x86 architecture,
 - Block layer subsystem,
 - Accessibility subsystem,
 - Android drivers,
 - Bluetooth drivers,
 - Clock framework and drivers,
 - Data acquisition framework and drivers,
 - Cryptographic API,
 - DMA engine subsystem,
 - GPU drivers,
 - HID subsystem,
 - I2C subsystem,
 - IRQ chip drivers,
 - Multiple devices driver,
 - VMware VMCI Driver,
 - MMC subsystem,
 - Network drivers,
 - Device tree and open firmware driver,
 - PCI subsystem,
 - S/390 drivers,
 - SCSI drivers,
 - Freescale SoC drivers,
 - Trusted Execution Environment drivers,
 - TTY drivers,
 - USB subsystem,
 - VFIO drivers,
 - Framebuffer layer,
 - Xen hypervisor drivers,
 - File systems infrastructure,
 - BTRFS file system,
 - Ext4 file system,
 - FAT file system,
 - Network file system client,
 - Network file system server daemon,
 - NILFS2 file system,
 - Pstore file system,
 - SMB network file system,
 - UBI file system,
 - Netfilter,
 - BPF subsystem,
 - Core kernel,
 - PCI iomap interfaces,
 - Memory management,
 - B.A.T.M.A.N. meshing protocol,
 - Bluetooth subsystem,
 - Ethernet bridge,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - MAC80211 subsystem,
 - IEEE 802.15.4 subsystem,
 - NFC subsystem,
 - Open vSwitch,
 - RDS protocol,
 - Network traffic control,
 - SMC sockets,
 - Unix domain sockets,
 - eXpress Data Path,
 - ALSA SH ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-aws-5.15' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1065-aws", ver:"5.15.0-1065.71~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.15.0.1065.71~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7655.1");
  script_cve_id("CVE-2022-21546", "CVE-2022-48893", "CVE-2022-49063", "CVE-2022-49168", "CVE-2022-49535", "CVE-2022-49636", "CVE-2022-49728", "CVE-2023-52572", "CVE-2023-52757", "CVE-2023-53034", "CVE-2024-26686", "CVE-2024-26739", "CVE-2024-27402", "CVE-2024-35790", "CVE-2024-35866", "CVE-2024-35867", "CVE-2024-35943", "CVE-2024-36908", "CVE-2024-36945", "CVE-2024-38540", "CVE-2024-38541", "CVE-2024-42230", "CVE-2024-42322", "CVE-2024-46742", "CVE-2024-46751", "CVE-2024-46753", "CVE-2024-46774", "CVE-2024-46787", "CVE-2024-46812", "CVE-2024-46816", "CVE-2024-46821", "CVE-2024-49960", "CVE-2024-49989", "CVE-2024-50047", "CVE-2024-50125", "CVE-2024-50258", "CVE-2024-50272", "CVE-2024-50280", "CVE-2024-53051", "CVE-2024-53128", "CVE-2024-53144", "CVE-2024-53168", "CVE-2024-53203", "CVE-2024-54458", "CVE-2024-56551", "CVE-2024-56608", "CVE-2024-56664", "CVE-2024-56751", "CVE-2024-58093", "CVE-2024-8805", "CVE-2025-21839", "CVE-2025-21853", "CVE-2025-21941", "CVE-2025-21956", "CVE-2025-21957", "CVE-2025-21959", "CVE-2025-21962", "CVE-2025-21963", "CVE-2025-21964", "CVE-2025-21968", "CVE-2025-21970", "CVE-2025-21975", "CVE-2025-21981", "CVE-2025-21991", "CVE-2025-21992", "CVE-2025-21994", "CVE-2025-21996", "CVE-2025-21999", "CVE-2025-22004", "CVE-2025-22005", "CVE-2025-22007", "CVE-2025-22008", "CVE-2025-22010", "CVE-2025-22014", "CVE-2025-22018", "CVE-2025-22020", "CVE-2025-22021", "CVE-2025-22025", "CVE-2025-22027", "CVE-2025-22035", "CVE-2025-22044", "CVE-2025-22045", "CVE-2025-22050", "CVE-2025-22054", "CVE-2025-22055", "CVE-2025-22056", "CVE-2025-22060", "CVE-2025-22062", "CVE-2025-22063", "CVE-2025-22066", "CVE-2025-22071", "CVE-2025-22073", "CVE-2025-22075", "CVE-2025-22079", "CVE-2025-22081", "CVE-2025-22086", "CVE-2025-22089", "CVE-2025-22097", "CVE-2025-2312", "CVE-2025-23136", "CVE-2025-23138", "CVE-2025-23140", "CVE-2025-23142", "CVE-2025-23144", "CVE-2025-23145", "CVE-2025-23146", "CVE-2025-23147", "CVE-2025-23148", "CVE-2025-23150", "CVE-2025-23151", "CVE-2025-23156", "CVE-2025-23157", "CVE-2025-23158", "CVE-2025-23159", "CVE-2025-23161", "CVE-2025-23163", "CVE-2025-37738", "CVE-2025-37739", "CVE-2025-37740", "CVE-2025-37741", "CVE-2025-37742", "CVE-2025-37749", "CVE-2025-37756", "CVE-2025-37757", "CVE-2025-37758", "CVE-2025-37765", "CVE-2025-37766", "CVE-2025-37767", "CVE-2025-37768", "CVE-2025-37770", "CVE-2025-37771", "CVE-2025-37773", "CVE-2025-37780", "CVE-2025-37781", "CVE-2025-37785", "CVE-2025-37787", "CVE-2025-37788", "CVE-2025-37789", "CVE-2025-37790", "CVE-2025-37792", "CVE-2025-37794", "CVE-2025-37796", "CVE-2025-37797", "CVE-2025-37798", "CVE-2025-37803", "CVE-2025-37805", "CVE-2025-37808", "CVE-2025-37810", "CVE-2025-37811", "CVE-2025-37812", "CVE-2025-37817", "CVE-2025-37819", "CVE-2025-37823", "CVE-2025-37824", "CVE-2025-37829", "CVE-2025-37830", "CVE-2025-37836", "CVE-2025-37838", "CVE-2025-37839", "CVE-2025-37840", "CVE-2025-37841", "CVE-2025-37844", "CVE-2025-37850", "CVE-2025-37851", "CVE-2025-37857", "CVE-2025-37858", "CVE-2025-37859", "CVE-2025-37862", "CVE-2025-37867", "CVE-2025-37875", "CVE-2025-37881", "CVE-2025-37883", "CVE-2025-37885", "CVE-2025-37889", "CVE-2025-37890", "CVE-2025-37892", "CVE-2025-37905", "CVE-2025-37909", "CVE-2025-37911", "CVE-2025-37912", "CVE-2025-37913", "CVE-2025-37914", "CVE-2025-37915", "CVE-2025-37923", "CVE-2025-37927", "CVE-2025-37930", "CVE-2025-37932", "CVE-2025-37937", "CVE-2025-37940", "CVE-2025-37949", "CVE-2025-37964", "CVE-2025-37967", "CVE-2025-37969", "CVE-2025-37970", "CVE-2025-37982", "CVE-2025-37983", "CVE-2025-37985", "CVE-2025-37989", "CVE-2025-37990", "CVE-2025-37991", "CVE-2025-37992", "CVE-2025-37994", "CVE-2025-37995", "CVE-2025-37997", "CVE-2025-37998", "CVE-2025-38000", "CVE-2025-38001", "CVE-2025-38005", "CVE-2025-38009", "CVE-2025-38023", "CVE-2025-38024", "CVE-2025-38094", "CVE-2025-38152", "CVE-2025-38177", "CVE-2025-38575", "CVE-2025-38637", "CVE-2025-39728", "CVE-2025-39735");
  script_tag(name:"creation_date", value:"2025-07-21 04:19:06 +0000 (Mon, 21 Jul 2025)");
  script_version("2025-07-21T05:44:15+0000");
  script_tag(name:"last_modification", value:"2025-07-21 05:44:15 +0000 (Mon, 21 Jul 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");

  script_name("Ubuntu: Security Advisory (USN-7655-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7655-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7655-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-intel-iotg-5.15' package(s) announced via the USN-7655-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michael Randrianantenaina discovered that the Bluetooth driver in the Linux
Kernel contained an improper access control vulnerability. A nearby
attacker could use this to connect a rougue device and possibly execute
arbitrary code. (CVE-2024-8805)

It was discovered that the CIFS network file system implementation in the
Linux kernel did not properly verify the target namespace when handling
upcalls. An attacker could use this to expose sensitive information.
(CVE-2025-2312)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - PA-RISC architecture,
 - PowerPC architecture,
 - x86 architecture,
 - Block layer subsystem,
 - Cryptographic API,
 - ACPI drivers,
 - Serial ATA and Parallel ATA drivers,
 - Bluetooth drivers,
 - Bus devices,
 - Clock framework and drivers,
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
 - MemoryStick subsystem,
 - Multifunction device drivers,
 - PCI Endpoint Test driver,
 - MTD block device drivers,
 - Network drivers,
 - Mellanox network drivers,
 - NTB driver,
 - Device tree and open firmware driver,
 - PCI subsystem,
 - TI SCI PM domains driver,
 - PWM drivers,
 - Voltage and Current Regulator drivers,
 - Remote Processor subsystem,
 - S/390 drivers,
 - SCSI subsystem,
 - QCOM SoC drivers,
 - Samsung SoC drivers,
 - TCM subsystem,
 - Thermal drivers,
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
 - NTFS3 file system,
 - Proc file system,
 - SMB network file system,
 - Kernel stack handling interfaces,
 - Bluetooth subsystem,
 - IPv6 networking,
 - Network traffic control,
 - SCTP protocol,
 - RDMA verbs API,
 - SoC audio core drivers,
 - BPF subsystem,
 - Kernel command line parsing driver,
 - Tracing infrastructure,
 - Watch queue notification mechanism,
 - Memory management,
 - 802.1Q VLAN protocol,
 - Asynchronous Transfer Mode (ATM) subsystem,
 - Networking core,
 - IPv4 networking,
 - MAC80211 subsystem,
 - Management Component Transport Protocol (MCTP),
 - Multipath TCP,
 - Netfilter,
 - Open vSwitch,
 - Phonet protocol,
 - SMC sockets,
 - Sun ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-intel-iotg-5.15' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1083-intel-iotg", ver:"5.15.0-1083.89~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel", ver:"5.15.0.1083.89~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1083.89~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg-5.15", ver:"5.15.0.1083.89~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

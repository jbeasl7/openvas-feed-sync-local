# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7775.1");
  script_cve_id("CVE-2022-48703", "CVE-2024-26726", "CVE-2024-26775", "CVE-2024-44939", "CVE-2024-57883", "CVE-2025-21888", "CVE-2025-37948", "CVE-2025-37954", "CVE-2025-37958", "CVE-2025-37963", "CVE-2025-38067", "CVE-2025-38074", "CVE-2025-38084", "CVE-2025-38085", "CVE-2025-38086", "CVE-2025-38088", "CVE-2025-38090", "CVE-2025-38100", "CVE-2025-38102", "CVE-2025-38103", "CVE-2025-38107", "CVE-2025-38108", "CVE-2025-38111", "CVE-2025-38112", "CVE-2025-38115", "CVE-2025-38119", "CVE-2025-38120", "CVE-2025-38122", "CVE-2025-38135", "CVE-2025-38136", "CVE-2025-38138", "CVE-2025-38143", "CVE-2025-38145", "CVE-2025-38146", "CVE-2025-38147", "CVE-2025-38153", "CVE-2025-38154", "CVE-2025-38157", "CVE-2025-38159", "CVE-2025-38160", "CVE-2025-38161", "CVE-2025-38163", "CVE-2025-38167", "CVE-2025-38173", "CVE-2025-38174", "CVE-2025-38181", "CVE-2025-38184", "CVE-2025-38194", "CVE-2025-38197", "CVE-2025-38200", "CVE-2025-38203", "CVE-2025-38204", "CVE-2025-38206", "CVE-2025-38211", "CVE-2025-38212", "CVE-2025-38218", "CVE-2025-38219", "CVE-2025-38222", "CVE-2025-38226", "CVE-2025-38227", "CVE-2025-38229", "CVE-2025-38231", "CVE-2025-38237", "CVE-2025-38245", "CVE-2025-38249", "CVE-2025-38251", "CVE-2025-38257", "CVE-2025-38262", "CVE-2025-38263", "CVE-2025-38273", "CVE-2025-38280", "CVE-2025-38285", "CVE-2025-38286", "CVE-2025-38293", "CVE-2025-38298", "CVE-2025-38305", "CVE-2025-38310", "CVE-2025-38312", "CVE-2025-38313", "CVE-2025-38319", "CVE-2025-38320", "CVE-2025-38324", "CVE-2025-38326", "CVE-2025-38328", "CVE-2025-38332", "CVE-2025-38336", "CVE-2025-38337", "CVE-2025-38342", "CVE-2025-38344", "CVE-2025-38345", "CVE-2025-38346", "CVE-2025-38348", "CVE-2025-38352", "CVE-2025-38362", "CVE-2025-38363", "CVE-2025-38371", "CVE-2025-38375", "CVE-2025-38377", "CVE-2025-38384", "CVE-2025-38386", "CVE-2025-38387", "CVE-2025-38389", "CVE-2025-38391", "CVE-2025-38393", "CVE-2025-38395", "CVE-2025-38399", "CVE-2025-38400", "CVE-2025-38401", "CVE-2025-38403", "CVE-2025-38406", "CVE-2025-38410", "CVE-2025-38412", "CVE-2025-38415", "CVE-2025-38416", "CVE-2025-38418", "CVE-2025-38419", "CVE-2025-38420", "CVE-2025-38424", "CVE-2025-38428", "CVE-2025-38430", "CVE-2025-38439", "CVE-2025-38441", "CVE-2025-38443", "CVE-2025-38444", "CVE-2025-38445", "CVE-2025-38448", "CVE-2025-38457", "CVE-2025-38458", "CVE-2025-38459", "CVE-2025-38460", "CVE-2025-38461", "CVE-2025-38462", "CVE-2025-38464", "CVE-2025-38465", "CVE-2025-38466", "CVE-2025-38467", "CVE-2025-38498", "CVE-2025-38513", "CVE-2025-38514", "CVE-2025-38515", "CVE-2025-38516", "CVE-2025-38540", "CVE-2025-38542");
  script_tag(name:"creation_date", value:"2025-09-26 04:04:47 +0000 (Fri, 26 Sep 2025)");
  script_version("2025-09-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-09-26 05:38:41 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-12 20:58:03 +0000 (Thu, 12 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7775-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7775-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7775-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure-fips' package(s) announced via the USN-7775-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - PowerPC architecture,
 - x86 architecture,
 - ACPI drivers,
 - Serial ATA and Parallel ATA drivers,
 - Drivers core,
 - ATA over ethernet (AOE) driver,
 - Network block device driver,
 - Bus devices,
 - Clock framework and drivers,
 - Hardware crypto device drivers,
 - DMA engine subsystem,
 - EDAC drivers,
 - GPU drivers,
 - HID subsystem,
 - InfiniBand drivers,
 - Input Device (Miscellaneous) drivers,
 - Multiple devices driver,
 - Media drivers,
 - VMware VMCI Driver,
 - MMC subsystem,
 - MTD block device drivers,
 - Network drivers,
 - Pin controllers subsystem,
 - x86 platform drivers,
 - PTP clock framework,
 - RapidIO drivers,
 - Voltage and Current Regulator drivers,
 - Remote Processor subsystem,
 - S/390 drivers,
 - SCSI subsystem,
 - ASPEED SoC drivers,
 - TCM subsystem,
 - Thermal drivers,
 - Thunderbolt and USB4 drivers,
 - TTY drivers,
 - UFS subsystem,
 - USB Gadget drivers,
 - Renesas USBHS Controller drivers,
 - USB Type-C support driver,
 - Virtio Host (VHOST) subsystem,
 - Backlight driver,
 - Framebuffer layer,
 - BTRFS file system,
 - File systems infrastructure,
 - Ext4 file system,
 - F2FS file system,
 - JFFS2 file system,
 - JFS file system,
 - Network file system (NFS) client,
 - Network file system (NFS) server daemon,
 - NTFS3 file system,
 - SMB network file system,
 - DRM display driver,
 - Memory Management,
 - Mellanox drivers,
 - Memory management,
 - Netfilter,
 - Network sockets,
 - IPC subsystem,
 - BPF subsystem,
 - Perf events,
 - Kernel exit() syscall,
 - Restartable seuqences system call mechanism,
 - Timer subsystem,
 - Tracing infrastructure,
 - Appletalk network protocol,
 - Asynchronous Transfer Mode (ATM) subsystem,
 - Networking core,
 - IPv6 networking,
 - MultiProtocol Label Switching driver,
 - NetLabel subsystem,
 - Netlink,
 - NFC subsystem,
 - Open vSwitch,
 - Rose network layer,
 - RxRPC session sockets,
 - Network traffic control,
 - TIPC protocol,
 - VMware vSockets driver,
 - USB sound devices,
(CVE-2025-38181, CVE-2025-38200, CVE-2025-38115, CVE-2025-38375,
CVE-2025-38457, CVE-2025-38371, CVE-2025-38145, CVE-2025-38540,
CVE-2025-38305, CVE-2025-38443, CVE-2025-38222, CVE-2025-38143,
CVE-2025-38173, CVE-2025-38466, CVE-2025-38458, CVE-2025-38293,
CVE-2025-38412, CVE-2025-38418, CVE-2025-38513, CVE-2025-38459,
CVE-2025-38084, CVE-2022-48703, CVE-2025-38419, CVE-2025-38336,
CVE-2025-37963, CVE-2025-38204, CVE-2025-38227, CVE-2025-38088,
CVE-2025-38401, CVE-2025-38107, CVE-2025-38285, CVE-2025-37958,
CVE-2025-38389, CVE-2025-38444, CVE-2025-38465, CVE-2025-38206,
CVE-2025-38326, CVE-2025-38103, CVE-2024-44939, CVE-2025-38154,
CVE-2025-38348, CVE-2025-38229, CVE-2025-38514, CVE-2025-38231,
CVE-2025-38136, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure-fips' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1096-azure-fips", ver:"5.15.0-1096.105+fips1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fips", ver:"5.15.0.1096.81", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fips-5.15", ver:"5.15.0.1096.81", rls:"UBUNTU22.04 LTS"))) {
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

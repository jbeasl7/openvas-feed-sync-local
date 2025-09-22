# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6895.4");
  script_cve_id("CVE-2023-52631", "CVE-2023-52637", "CVE-2023-52638", "CVE-2023-52642", "CVE-2023-52643", "CVE-2023-52645", "CVE-2023-52880", "CVE-2023-6270", "CVE-2024-0841", "CVE-2024-1151", "CVE-2024-23307", "CVE-2024-24861", "CVE-2024-26593", "CVE-2024-26600", "CVE-2024-26601", "CVE-2024-26602", "CVE-2024-26603", "CVE-2024-26606", "CVE-2024-26642", "CVE-2024-26659", "CVE-2024-26660", "CVE-2024-26661", "CVE-2024-26662", "CVE-2024-26663", "CVE-2024-26664", "CVE-2024-26665", "CVE-2024-26666", "CVE-2024-26667", "CVE-2024-26674", "CVE-2024-26675", "CVE-2024-26676", "CVE-2024-26677", "CVE-2024-26679", "CVE-2024-26680", "CVE-2024-26681", "CVE-2024-26684", "CVE-2024-26685", "CVE-2024-26688", "CVE-2024-26689", "CVE-2024-26691", "CVE-2024-26693", "CVE-2024-26694", "CVE-2024-26695", "CVE-2024-26696", "CVE-2024-26697", "CVE-2024-26698", "CVE-2024-26700", "CVE-2024-26702", "CVE-2024-26703", "CVE-2024-26707", "CVE-2024-26708", "CVE-2024-26710", "CVE-2024-26711", "CVE-2024-26712", "CVE-2024-26714", "CVE-2024-26715", "CVE-2024-26716", "CVE-2024-26717", "CVE-2024-26718", "CVE-2024-26719", "CVE-2024-26720", "CVE-2024-26722", "CVE-2024-26723", "CVE-2024-26726", "CVE-2024-26733", "CVE-2024-26734", "CVE-2024-26735", "CVE-2024-26736", "CVE-2024-26748", "CVE-2024-26782", "CVE-2024-26789", "CVE-2024-26790", "CVE-2024-26792", "CVE-2024-26798", "CVE-2024-26802", "CVE-2024-26803", "CVE-2024-26818", "CVE-2024-26820", "CVE-2024-26822", "CVE-2024-26824", "CVE-2024-26825", "CVE-2024-26826", "CVE-2024-26828", "CVE-2024-26829", "CVE-2024-26830", "CVE-2024-26831", "CVE-2024-26838", "CVE-2024-26889", "CVE-2024-26890", "CVE-2024-26898", "CVE-2024-26910", "CVE-2024-26916", "CVE-2024-26917", "CVE-2024-26919", "CVE-2024-26920", "CVE-2024-26922", "CVE-2024-26923", "CVE-2024-26926", "CVE-2024-27416", "CVE-2024-35833");
  script_tag(name:"creation_date", value:"2024-08-05 04:08:49 +0000 (Mon, 05 Aug 2024)");
  script_version("2024-08-05T05:05:50+0000");
  script_tag(name:"last_modification", value:"2024-08-05 05:05:50 +0000 (Mon, 05 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-29 19:31:26 +0000 (Mon, 29 Apr 2024)");

  script_name("Ubuntu: Security Advisory (USN-6895-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6895-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6895-4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-6.5' package(s) announced via the USN-6895-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ATA over Ethernet (AoE) driver in the Linux
kernel contained a race condition, leading to a use-after-free
vulnerability. An attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2023-6270)

It was discovered that the HugeTLB file system component of the Linux
Kernel contained a NULL pointer dereference vulnerability. A privileged
attacker could possibly use this to to cause a denial of service.
(CVE-2024-0841)

It was discovered that the Open vSwitch implementation in the Linux kernel
could overflow its stack during recursive action operations under certain
conditions. A local attacker could use this to cause a denial of service
(system crash). (CVE-2024-1151)

Gui-Dong Han discovered that the software RAID driver in the Linux kernel
contained a race condition, leading to an integer overflow vulnerability. A
privileged attacker could possibly use this to cause a denial of service
(system crash). (CVE-2024-23307)

Bai Jiaju discovered that the Xceive XC4000 silicon tuner device driver in
the Linux kernel contained a race condition, leading to an integer overflow
vulnerability. An attacker could possibly use this to cause a denial of
service (system crash). (CVE-2024-24861)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - PowerPC architecture,
 - x86 architecture,
 - Cryptographic API,
 - Android drivers,
 - Block layer subsystem,
 - Bluetooth drivers,
 - DMA engine subsystem,
 - GPU drivers,
 - HID subsystem,
 - Hardware monitoring drivers,
 - I2C subsystem,
 - IIO ADC drivers,
 - IIO subsystem,
 - IIO Magnetometer sensors drivers,
 - InfiniBand drivers,
 - On-Chip Interconnect management framework,
 - Multiple devices driver,
 - Media drivers,
 - Network drivers,
 - PHY drivers,
 - MediaTek PM domains,
 - SCSI drivers,
 - TTY drivers,
 - USB subsystem,
 - DesignWare USB3 driver,
 - Framebuffer layer,
 - AFS file system,
 - BTRFS file system,
 - Ceph distributed file system,
 - Ext4 file system,
 - File systems infrastructure,
 - NILFS2 file system,
 - NTFS3 file system,
 - SMB network file system,
 - Core kernel,
 - Memory management,
 - Bluetooth subsystem,
 - CAN network layer,
 - Devlink API,
 - Handshake API,
 - HSR network protocol,
 - IPv4 networking,
 - IPv6 networking,
 - MAC80211 subsystem,
 - Multipath TCP,
 - Netfilter,
 - NFC subsystem,
 - RxRPC session sockets,
 - TIPC protocol,
 - Unix domain sockets,
 - Realtek audio codecs,
(CVE-2023-52638, CVE-2024-26684, CVE-2024-26659, CVE-2024-26708,
CVE-2024-26663, CVE-2024-26662, CVE-2024-26789, CVE-2024-26831,
CVE-2024-26703, CVE-2023-52643, CVE-2024-26688, CVE-2024-26733,
CVE-2024-26818, CVE-2024-26707, CVE-2024-26820, CVE-2024-26719,
CVE-2024-26726, CVE-2024-26830, CVE-2024-26694, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-oem-6.5' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1027-oem", ver:"6.5.0-1027.28", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04", ver:"6.5.0.1027.29", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04a", ver:"6.5.0.1027.29", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04b", ver:"6.5.0.1027.29", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04c", ver:"6.5.0.1027.29", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04d", ver:"6.5.0.1027.29", rls:"UBUNTU22.04 LTS"))) {
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

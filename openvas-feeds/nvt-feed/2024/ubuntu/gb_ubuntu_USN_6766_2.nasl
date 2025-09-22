# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6766.2");
  script_cve_id("CVE-2023-52435", "CVE-2023-52486", "CVE-2023-52489", "CVE-2023-52491", "CVE-2023-52492", "CVE-2023-52493", "CVE-2023-52494", "CVE-2023-52498", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52588", "CVE-2023-52594", "CVE-2023-52595", "CVE-2023-52597", "CVE-2023-52598", "CVE-2023-52599", "CVE-2023-52601", "CVE-2023-52602", "CVE-2023-52604", "CVE-2023-52606", "CVE-2023-52607", "CVE-2023-52608", "CVE-2023-52614", "CVE-2023-52615", "CVE-2023-52616", "CVE-2023-52617", "CVE-2023-52618", "CVE-2023-52619", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-52627", "CVE-2023-52631", "CVE-2023-52633", "CVE-2023-52635", "CVE-2023-52637", "CVE-2023-52638", "CVE-2023-52642", "CVE-2023-52643", "CVE-2024-1151", "CVE-2024-2201", "CVE-2024-23849", "CVE-2024-26592", "CVE-2024-26593", "CVE-2024-26594", "CVE-2024-26600", "CVE-2024-26602", "CVE-2024-26606", "CVE-2024-26608", "CVE-2024-26610", "CVE-2024-26614", "CVE-2024-26615", "CVE-2024-26625", "CVE-2024-26627", "CVE-2024-26635", "CVE-2024-26636", "CVE-2024-26640", "CVE-2024-26641", "CVE-2024-26644", "CVE-2024-26645", "CVE-2024-26660", "CVE-2024-26663", "CVE-2024-26664", "CVE-2024-26665", "CVE-2024-26668", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26675", "CVE-2024-26676", "CVE-2024-26679", "CVE-2024-26684", "CVE-2024-26685", "CVE-2024-26689", "CVE-2024-26695", "CVE-2024-26696", "CVE-2024-26697", "CVE-2024-26698", "CVE-2024-26702", "CVE-2024-26704", "CVE-2024-26707", "CVE-2024-26712", "CVE-2024-26715", "CVE-2024-26717", "CVE-2024-26720", "CVE-2024-26722", "CVE-2024-26808", "CVE-2024-26825", "CVE-2024-26826", "CVE-2024-26829", "CVE-2024-26910", "CVE-2024-26916", "CVE-2024-26920");
  script_tag(name:"creation_date", value:"2024-05-16 04:07:58 +0000 (Thu, 16 May 2024)");
  script_version("2025-01-15T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-14 15:37:59 +0000 (Tue, 14 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-6766-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6766-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6766-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe-5.15, linux-raspi' package(s) announced via the USN-6766-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Open vSwitch implementation in the Linux kernel
could overflow its stack during recursive action operations under certain
conditions. A local attacker could use this to cause a denial of service
(system crash). (CVE-2024-1151)

Sander Wiebing, Alvise de Faveri Tron, Herbert Bos, and Cristiano Giuffrida
discovered that the Linux kernel mitigations for the initial Branch History
Injection vulnerability (CVE-2022-0001) were insufficient for Intel
processors. A local attacker could potentially use this to expose sensitive
information. (CVE-2024-2201)

Chenyuan Yang discovered that the RDS Protocol implementation in the Linux
kernel contained an out-of-bounds read vulnerability. An attacker could use
this to possibly cause a denial of service (system crash). (CVE-2024-23849)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - PowerPC architecture,
 - S390 architecture,
 - Core kernel,
 - Block layer subsystem,
 - Android drivers,
 - Power management core,
 - Bus devices,
 - Hardware random number generator core,
 - Cryptographic API,
 - Device frequency,
 - DMA engine subsystem,
 - ARM SCMI message protocol,
 - GPU drivers,
 - HID subsystem,
 - Hardware monitoring drivers,
 - I2C subsystem,
 - IIO ADC drivers,
 - IIO subsystem,
 - IIO Magnetometer sensors drivers,
 - InfiniBand drivers,
 - Media drivers,
 - Network drivers,
 - PCI driver for MicroSemi Switchtec,
 - PHY drivers,
 - SCSI drivers,
 - DesignWare USB3 driver,
 - BTRFS file system,
 - Ceph distributed file system,
 - Ext4 file system,
 - F2FS file system,
 - JFS file system,
 - NILFS2 file system,
 - NTFS3 file system,
 - Pstore file system,
 - SMB network file system,
 - Memory management,
 - CAN network layer,
 - Networking core,
 - HSR network protocol,
 - IPv4 networking,
 - IPv6 networking,
 - Logical Link layer,
 - Multipath TCP,
 - Netfilter,
 - NFC subsystem,
 - SMC sockets,
 - Sun RPC protocol,
 - TIPC protocol,
 - Unix domain sockets,
 - Realtek audio codecs,
(CVE-2023-52594, CVE-2023-52601, CVE-2024-26826, CVE-2023-52622,
CVE-2024-26665, CVE-2023-52493, CVE-2023-52633, CVE-2024-26684,
CVE-2024-26663, CVE-2023-52618, CVE-2023-52588, CVE-2023-52637,
CVE-2024-26825, CVE-2023-52606, CVE-2024-26594, CVE-2024-26625,
CVE-2024-26720, CVE-2024-26614, CVE-2023-52627, CVE-2023-52602,
CVE-2024-26673, CVE-2024-26685, CVE-2023-52638, CVE-2023-52498,
CVE-2023-52619, CVE-2024-26910, CVE-2024-26689, CVE-2023-52583,
CVE-2024-26676, CVE-2024-26671, CVE-2024-26704, CVE-2024-26608,
CVE-2024-26610, CVE-2024-26592, CVE-2023-52599, CVE-2023-52595,
CVE-2024-26660, CVE-2023-52617, CVE-2024-26645, CVE-2023-52486,
CVE-2023-52631, CVE-2023-52607, CVE-2023-52608, CVE-2024-26722,
CVE-2024-26615, CVE-2023-52615, CVE-2024-26636, CVE-2023-52642,
CVE-2023-52587, CVE-2024-26712, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-hwe-5.15, linux-raspi' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-106-generic", ver:"5.15.0-106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-106-generic-64k", ver:"5.15.0-106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-106-generic-lpae", ver:"5.15.0-106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-20.04", ver:"5.15.0.106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-20.04", ver:"5.15.0.106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-20.04", ver:"5.15.0.106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.15.0.106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04b", ver:"5.15.0.106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04c", ver:"5.15.0.106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04d", ver:"5.15.0.106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-20.04", ver:"5.15.0.106.116~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1054-raspi", ver:"5.15.0-1054.57", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.15.0.1054.52", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.15.0.1054.52", rls:"UBUNTU22.04 LTS"))) {
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

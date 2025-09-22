# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7293.1");
  script_cve_id("CVE-2021-47469", "CVE-2023-52458", "CVE-2023-52917", "CVE-2024-35887", "CVE-2024-35896", "CVE-2024-38544", "CVE-2024-40911", "CVE-2024-40953", "CVE-2024-40965", "CVE-2024-41016", "CVE-2024-41066", "CVE-2024-42252", "CVE-2024-43863", "CVE-2024-44931", "CVE-2024-46731", "CVE-2024-46849", "CVE-2024-46853", "CVE-2024-46854", "CVE-2024-47670", "CVE-2024-47671", "CVE-2024-47672", "CVE-2024-47674", "CVE-2024-47679", "CVE-2024-47684", "CVE-2024-47685", "CVE-2024-47692", "CVE-2024-47696", "CVE-2024-47697", "CVE-2024-47698", "CVE-2024-47699", "CVE-2024-47701", "CVE-2024-47706", "CVE-2024-47709", "CVE-2024-47710", "CVE-2024-47712", "CVE-2024-47713", "CVE-2024-47723", "CVE-2024-47737", "CVE-2024-47740", "CVE-2024-47742", "CVE-2024-47747", "CVE-2024-47749", "CVE-2024-47756", "CVE-2024-47757", "CVE-2024-49851", "CVE-2024-49860", "CVE-2024-49867", "CVE-2024-49868", "CVE-2024-49877", "CVE-2024-49878", "CVE-2024-49879", "CVE-2024-49882", "CVE-2024-49883", "CVE-2024-49892", "CVE-2024-49894", "CVE-2024-49896", "CVE-2024-49900", "CVE-2024-49902", "CVE-2024-49903", "CVE-2024-49924", "CVE-2024-49938", "CVE-2024-49944", "CVE-2024-49948", "CVE-2024-49949", "CVE-2024-49952", "CVE-2024-49955", "CVE-2024-49957", "CVE-2024-49958", "CVE-2024-49959", "CVE-2024-49962", "CVE-2024-49963", "CVE-2024-49965", "CVE-2024-49966", "CVE-2024-49973", "CVE-2024-49975", "CVE-2024-49981", "CVE-2024-49982", "CVE-2024-49985", "CVE-2024-49995", "CVE-2024-49997", "CVE-2024-50006", "CVE-2024-50007", "CVE-2024-50008", "CVE-2024-50024", "CVE-2024-50033", "CVE-2024-50035", "CVE-2024-50039", "CVE-2024-50040", "CVE-2024-50044", "CVE-2024-50045", "CVE-2024-50059", "CVE-2024-50074", "CVE-2024-50082", "CVE-2024-50096", "CVE-2024-50099", "CVE-2024-50116", "CVE-2024-50117", "CVE-2024-50127", "CVE-2024-50131", "CVE-2024-50134", "CVE-2024-50142", "CVE-2024-50143", "CVE-2024-50148", "CVE-2024-50150", "CVE-2024-50151", "CVE-2024-50167", "CVE-2024-50168", "CVE-2024-50171", "CVE-2024-50179", "CVE-2024-50180", "CVE-2024-50184", "CVE-2024-50194", "CVE-2024-50195", "CVE-2024-50199", "CVE-2024-50202", "CVE-2024-50205", "CVE-2024-50218", "CVE-2024-50229", "CVE-2024-50230", "CVE-2024-50233", "CVE-2024-50234", "CVE-2024-50236", "CVE-2024-50237", "CVE-2024-50251", "CVE-2024-50262", "CVE-2024-50265", "CVE-2024-50267", "CVE-2024-50269", "CVE-2024-50273", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50282", "CVE-2024-50287", "CVE-2024-50290", "CVE-2024-50296", "CVE-2024-50299", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-53059", "CVE-2024-53061", "CVE-2024-53063", "CVE-2024-53066", "CVE-2024-53101", "CVE-2024-53104", "CVE-2025-0927");
  script_tag(name:"creation_date", value:"2025-02-25 15:04:34 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("Ubuntu: Security Advisory (USN-7293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7293-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7293-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-hwe-5.4' package(s) announced via the USN-7293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Attila Szasz discovered that the HFS+ file system implementation in the
Linux Kernel contained a heap overflow vulnerability. An attacker could use
a specially crafted file system image that, when mounted, could cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2025-0927)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - Block layer subsystem,
 - ACPI drivers,
 - Drivers core,
 - ATA over ethernet (AOE) driver,
 - TPM device driver,
 - GPIO subsystem,
 - GPU drivers,
 - HID subsystem,
 - I2C subsystem,
 - InfiniBand drivers,
 - Mailbox framework,
 - Multiple devices driver,
 - Media drivers,
 - Network drivers,
 - NTB driver,
 - Virtio pmem driver,
 - Parport drivers,
 - PCI subsystem,
 - SPI subsystem,
 - Direct Digital Synthesis drivers,
 - USB Device Class drivers,
 - USB Dual Role (OTG-ready) Controller drivers,
 - USB Serial drivers,
 - USB Type-C support driver,
 - Framebuffer layer,
 - BTRFS file system,
 - Ceph distributed file system,
 - Ext4 file system,
 - F2FS file system,
 - File systems infrastructure,
 - JFS file system,
 - Network file system (NFS) client,
 - Network file system (NFS) server daemon,
 - NILFS2 file system,
 - SMB network file system,
 - Network traffic control,
 - Network sockets,
 - TCP network protocol,
 - BPF subsystem,
 - Perf events,
 - Arbitrary resource management,
 - Timer substystem drivers,
 - Tracing infrastructure,
 - Closures library,
 - Memory management,
 - Amateur Radio drivers,
 - Bluetooth subsystem,
 - Ethernet bridge,
 - CAN network layer,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - MAC80211 subsystem,
 - Netfilter,
 - Netlink,
 - SCTP protocol,
 - TIPC protocol,
 - Wireless networking,
 - XFRM subsystem,
 - Key management,
 - FireWire sound drivers,
 - AudioScience HPI driver,
 - Amlogic Meson SoC drivers,
 - KVM core,
(CVE-2024-50184, CVE-2024-47706, CVE-2024-49962, CVE-2024-35887,
CVE-2024-53101, CVE-2024-50199, CVE-2024-47709, CVE-2024-50074,
CVE-2024-41066, CVE-2024-42252, CVE-2024-43863, CVE-2024-47685,
CVE-2024-47756, CVE-2024-50282, CVE-2024-50143, CVE-2024-50116,
CVE-2024-47699, CVE-2024-47698, CVE-2024-50301, CVE-2024-47723,
CVE-2024-50296, CVE-2024-50007, CVE-2024-49952, CVE-2024-50233,
CVE-2023-52458, CVE-2024-53063, CVE-2024-49975, CVE-2024-50099,
CVE-2024-47742, CVE-2024-50033, CVE-2024-50218, CVE-2024-50096,
CVE-2024-49981, CVE-2024-40911, CVE-2024-47697, CVE-2024-49894,
CVE-2024-49955, CVE-2024-53104, CVE-2024-49963, CVE-2024-49883,
CVE-2024-47710, CVE-2024-49959, CVE-2024-49948, CVE-2024-50302,
CVE-2024-49867, CVE-2024-50234, CVE-2024-49902, CVE-2024-50006,
CVE-2024-47672, CVE-2024-50202, CVE-2024-49851, CVE-2024-35896,
CVE-2024-50150, CVE-2024-53061, CVE-2024-46854, CVE-2024-50279,
CVE-2024-50278, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-hwe-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-208-generic", ver:"5.4.0-208.228~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-208-lowlatency", ver:"5.4.0-208.228~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"5.4.0.208.228~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"5.4.0.208.228~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.208.228~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.208.228~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"5.4.0.208.228~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"5.4.0.208.228~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-208-generic", ver:"5.4.0-208.228", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-208-generic-lpae", ver:"5.4.0-208.228", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-208-lowlatency", ver:"5.4.0-208.228", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.4.0.208.204", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.4.0.208.204", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.4.0.208.204", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"5.4.0.208.204", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-osp1", ver:"5.4.0.208.204", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.4.0.208.204", rls:"UBUNTU20.04 LTS"))) {
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

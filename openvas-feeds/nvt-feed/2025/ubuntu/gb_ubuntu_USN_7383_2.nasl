# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7383.2");
  script_cve_id("CVE-2024-47711", "CVE-2024-47726", "CVE-2024-49865", "CVE-2024-49893", "CVE-2024-49914", "CVE-2024-49920", "CVE-2024-49921", "CVE-2024-49968", "CVE-2024-49972", "CVE-2024-50009", "CVE-2024-50019", "CVE-2024-50020", "CVE-2024-50021", "CVE-2024-50022", "CVE-2024-50023", "CVE-2024-50024", "CVE-2024-50025", "CVE-2024-50026", "CVE-2024-50027", "CVE-2024-50028", "CVE-2024-50029", "CVE-2024-50030", "CVE-2024-50031", "CVE-2024-50032", "CVE-2024-50033", "CVE-2024-50035", "CVE-2024-50036", "CVE-2024-50038", "CVE-2024-50039", "CVE-2024-50040", "CVE-2024-50041", "CVE-2024-50042", "CVE-2024-50044", "CVE-2024-50045", "CVE-2024-50046", "CVE-2024-50047", "CVE-2024-50048", "CVE-2024-50049", "CVE-2024-50055", "CVE-2024-50056", "CVE-2024-50057", "CVE-2024-50058", "CVE-2024-50059", "CVE-2024-50060", "CVE-2024-50061", "CVE-2024-50062", "CVE-2024-50063", "CVE-2024-50064", "CVE-2024-50065", "CVE-2024-50066", "CVE-2024-50068", "CVE-2024-50069", "CVE-2024-50070", "CVE-2024-50072", "CVE-2024-50073", "CVE-2024-50074", "CVE-2024-50075", "CVE-2024-50076", "CVE-2024-50077", "CVE-2024-50078", "CVE-2024-50080", "CVE-2024-50082", "CVE-2024-50083", "CVE-2024-50084", "CVE-2024-50085", "CVE-2024-50086", "CVE-2024-50087", "CVE-2024-50088", "CVE-2024-50090", "CVE-2024-50093", "CVE-2024-50095", "CVE-2024-50096", "CVE-2024-50098", "CVE-2024-50099", "CVE-2024-50101", "CVE-2024-50117", "CVE-2024-50134", "CVE-2024-50148", "CVE-2024-50171", "CVE-2024-50180", "CVE-2024-50182", "CVE-2024-50183", "CVE-2024-50184", "CVE-2024-50185", "CVE-2024-50186", "CVE-2024-50187", "CVE-2024-50188", "CVE-2024-50189", "CVE-2024-50191", "CVE-2024-50192", "CVE-2024-50193", "CVE-2024-50194", "CVE-2024-50195", "CVE-2024-50196", "CVE-2024-50197", "CVE-2024-50198", "CVE-2024-50199", "CVE-2024-50200", "CVE-2024-50201", "CVE-2024-50202", "CVE-2024-50229", "CVE-2024-50233", "CVE-2024-53156", "CVE-2024-53165", "CVE-2024-53170", "CVE-2024-56582", "CVE-2024-56614", "CVE-2024-56663");
  script_tag(name:"creation_date", value:"2025-03-28 04:04:17 +0000 (Fri, 28 Mar 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-08 17:10:39 +0000 (Wed, 08 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-7383-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7383-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7383-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-realtime' package(s) announced via the USN-7383-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - x86 architecture,
 - Block layer subsystem,
 - Drivers core,
 - Ublk userspace block driver,
 - Compressed RAM block device driver,
 - CPU frequency scaling framework,
 - DAX dirext access to differentiated memory framework,
 - GPU drivers,
 - HID subsystem,
 - I3C subsystem,
 - IIO subsystem,
 - InfiniBand drivers,
 - IOMMU subsystem,
 - IRQ chip drivers,
 - Network drivers,
 - NTB driver,
 - Virtio pmem driver,
 - Parport drivers,
 - Pin controllers subsystem,
 - SCSI subsystem,
 - SuperH / SH-Mobile drivers,
 - Direct Digital Synthesis drivers,
 - Thermal drivers,
 - TTY drivers,
 - UFS subsystem,
 - USB Gadget drivers,
 - USB Host Controller drivers,
 - TI TPS6598x USB Power Delivery controller driver,
 - Framebuffer layer,
 - BTRFS file system,
 - Ext4 file system,
 - F2FS file system,
 - Network file system (NFS) client,
 - NILFS2 file system,
 - NTFS3 file system,
 - SMB network file system,
 - BPF subsystem,
 - Network file system (NFS) superblock,
 - Network traffic control,
 - Network sockets,
 - User-space API (UAPI),
 - io_uring subsystem,
 - Kernel thread helper (kthread),
 - RCU subsystem,
 - Timer subsystem,
 - Maple Tree data structure library,
 - Memory management,
 - Bluetooth subsystem,
 - Ethernet bridge,
 - Networking core,
 - IPv4 networking,
 - Multipath TCP,
 - Netfilter,
 - Netlink,
 - Unix domain sockets,
 - Wireless networking,
 - eXpress Data Path,
(CVE-2024-50182, CVE-2024-50020, CVE-2024-50060, CVE-2024-50074,
CVE-2024-50193, CVE-2024-50117, CVE-2024-50201, CVE-2024-50033,
CVE-2024-50056, CVE-2024-50026, CVE-2024-50059, CVE-2024-50041,
CVE-2024-50083, CVE-2024-50038, CVE-2024-50229, CVE-2024-50028,
CVE-2024-50183, CVE-2024-50196, CVE-2024-50029, CVE-2024-50093,
CVE-2024-50188, CVE-2024-50025, CVE-2024-50200, CVE-2024-50068,
CVE-2024-49920, CVE-2024-50198, CVE-2024-50035, CVE-2024-50042,
CVE-2024-50023, CVE-2024-50047, CVE-2024-56582, CVE-2024-50090,
CVE-2024-50062, CVE-2024-50073, CVE-2024-50063, CVE-2024-50098,
CVE-2024-50197, CVE-2024-50040, CVE-2024-50180, CVE-2024-53170,
CVE-2024-50087, CVE-2024-50031, CVE-2024-50202, CVE-2024-50058,
CVE-2024-50186, CVE-2024-50134, CVE-2024-50194, CVE-2024-50075,
CVE-2024-50046, CVE-2024-50078, CVE-2024-50066, CVE-2024-53156,
CVE-2024-49893, CVE-2024-50021, CVE-2024-47711, CVE-2024-47726,
CVE-2024-50024, CVE-2024-49865, CVE-2024-50064, CVE-2024-50049,
CVE-2024-50171, CVE-2024-50019, CVE-2024-50077, CVE-2024-50199,
CVE-2024-50072, CVE-2024-50069, CVE-2024-50048, CVE-2024-49972,
CVE-2024-53165, CVE-2024-50022, CVE-2024-50084, CVE-2024-50185,
CVE-2024-50055, CVE-2024-50187, CVE-2024-50009, CVE-2024-50082,
CVE-2024-50085, CVE-2024-50095, CVE-2024-50195, CVE-2024-50080,
CVE-2024-50076, CVE-2024-50088, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-realtime' package(s) on Ubuntu 24.04.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.1-1018-realtime", ver:"6.8.1-1018.19", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-realtime", ver:"6.8.1-1018.19", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-realtime-hwe-24.04", ver:"6.8.1-1018.19", rls:"UBUNTU24.04 LTS"))) {
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

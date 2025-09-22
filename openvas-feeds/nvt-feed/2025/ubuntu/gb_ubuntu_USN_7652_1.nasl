# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7652.1");
  script_cve_id("CVE-2024-49887", "CVE-2024-57953", "CVE-2024-57973", "CVE-2024-57974", "CVE-2024-57975", "CVE-2024-57979", "CVE-2024-57980", "CVE-2024-57981", "CVE-2024-57982", "CVE-2024-57984", "CVE-2024-57986", "CVE-2024-57990", "CVE-2024-57993", "CVE-2024-57994", "CVE-2024-57996", "CVE-2024-57997", "CVE-2024-57998", "CVE-2024-57999", "CVE-2024-58001", "CVE-2024-58002", "CVE-2024-58003", "CVE-2024-58005", "CVE-2024-58006", "CVE-2024-58007", "CVE-2024-58010", "CVE-2024-58011", "CVE-2024-58013", "CVE-2024-58014", "CVE-2024-58016", "CVE-2024-58017", "CVE-2024-58018", "CVE-2024-58019", "CVE-2024-58034", "CVE-2024-58051", "CVE-2024-58052", "CVE-2024-58053", "CVE-2024-58054", "CVE-2024-58055", "CVE-2024-58056", "CVE-2024-58057", "CVE-2024-58058", "CVE-2024-58061", "CVE-2024-58063", "CVE-2024-58068", "CVE-2024-58069", "CVE-2024-58070", "CVE-2024-58071", "CVE-2024-58072", "CVE-2024-58076", "CVE-2024-58077", "CVE-2024-58078", "CVE-2024-58079", "CVE-2024-58080", "CVE-2024-58081", "CVE-2024-58082", "CVE-2024-58083", "CVE-2024-58085", "CVE-2025-21705", "CVE-2025-21707", "CVE-2025-21708", "CVE-2025-21710", "CVE-2025-21711", "CVE-2025-21714", "CVE-2025-21715", "CVE-2025-21716", "CVE-2025-21718", "CVE-2025-21719", "CVE-2025-21720", "CVE-2025-21721", "CVE-2025-21722", "CVE-2025-21723", "CVE-2025-21724", "CVE-2025-21725", "CVE-2025-21726", "CVE-2025-21727", "CVE-2025-21728", "CVE-2025-21731", "CVE-2025-21732", "CVE-2025-21733", "CVE-2025-21734", "CVE-2025-21735", "CVE-2025-21736", "CVE-2025-21738", "CVE-2025-21739", "CVE-2025-21741", "CVE-2025-21742", "CVE-2025-21743", "CVE-2025-21744", "CVE-2025-21745", "CVE-2025-21748", "CVE-2025-21749", "CVE-2025-21750", "CVE-2025-21753", "CVE-2025-21754", "CVE-2025-21798", "CVE-2025-21799", "CVE-2025-21801", "CVE-2025-21802", "CVE-2025-21804", "CVE-2025-21806", "CVE-2025-21808", "CVE-2025-21809", "CVE-2025-21810", "CVE-2025-21811", "CVE-2025-21812", "CVE-2025-21814", "CVE-2025-21815", "CVE-2025-21816", "CVE-2025-21820", "CVE-2025-21825", "CVE-2025-21826", "CVE-2025-21828", "CVE-2025-21829", "CVE-2025-21830", "CVE-2025-21832", "CVE-2025-37750", "CVE-2025-37974");
  script_tag(name:"creation_date", value:"2025-07-18 04:17:04 +0000 (Fri, 18 Jul 2025)");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-06 12:23:16 +0000 (Thu, 06 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-7652-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7652-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7652-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-realtime' package(s) announced via the USN-7652-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - PowerPC architecture,
 - S390 architecture,
 - Block layer subsystem,
 - Serial ATA and Parallel ATA drivers,
 - Drivers core,
 - Network block device driver,
 - Character device driver,
 - TPM device driver,
 - Clock framework and drivers,
 - FireWire subsystem,
 - GPU drivers,
 - HID subsystem,
 - I3C subsystem,
 - InfiniBand drivers,
 - IOMMU subsystem,
 - Media drivers,
 - NVIDIA Tegra memory controller driver,
 - Fastrpc Driver,
 - Network drivers,
 - Operating Performance Points (OPP) driver,
 - PCI subsystem,
 - x86 platform drivers,
 - PPS (Pulse Per Second) driver,
 - PTP clock framework,
 - Remote Processor subsystem,
 - Real Time Clock drivers,
 - SCSI subsystem,
 - QCOM SoC drivers,
 - Media staging drivers,
 - TTY drivers,
 - UFS subsystem,
 - USB Gadget drivers,
 - USB Host Controller drivers,
 - File systems infrastructure,
 - BTRFS file system,
 - F2FS file system,
 - NILFS2 file system,
 - SMB network file system,
 - UBI file system,
 - Timer subsystem,
 - KVM subsystem,
 - Networking core,
 - ptr_ring data structure definitions,
 - Networking subsytem,
 - Amateur Radio drivers,
 - XFRM subsystem,
 - Tracing infrastructure,
 - BPF subsystem,
 - Padata parallel execution mechanism,
 - printk logging mechanism,
 - Memory management,
 - Bluetooth subsystem,
 - IPv4 networking,
 - IPv6 networking,
 - MAC80211 subsystem,
 - Multipath TCP,
 - Netfilter,
 - NFC subsystem,
 - Rose network layer,
 - RxRPC session sockets,
 - Network traffic control,
 - Landlock security,
 - Linux Security Modules (LSM) Framework,
 - Tomoyo security module,
 - SoC audio core drivers,
(CVE-2024-58055, CVE-2024-58077, CVE-2024-58080, CVE-2024-58082,
CVE-2025-21743, CVE-2024-57953, CVE-2024-57994, CVE-2025-21806,
CVE-2024-58007, CVE-2024-58002, CVE-2024-57974, CVE-2024-57980,
CVE-2025-21720, CVE-2024-57990, CVE-2025-21725, CVE-2024-58057,
CVE-2024-58018, CVE-2024-58011, CVE-2025-21814, CVE-2025-21799,
CVE-2024-58017, CVE-2024-58014, CVE-2025-21731, CVE-2024-58072,
CVE-2024-58069, CVE-2024-58006, CVE-2024-57984, CVE-2025-21710,
CVE-2024-58061, CVE-2024-57997, CVE-2024-57975, CVE-2025-21724,
CVE-2025-37974, CVE-2025-21808, CVE-2024-58056, CVE-2025-21753,
CVE-2024-58068, CVE-2025-21728, CVE-2025-21714, CVE-2024-58054,
CVE-2025-21741, CVE-2025-21736, CVE-2025-21715, CVE-2025-21802,
CVE-2025-21739, CVE-2025-21727, CVE-2025-21749, CVE-2024-58053,
CVE-2024-58081, CVE-2025-21828, CVE-2025-21705, CVE-2024-58051,
CVE-2024-57979, CVE-2025-21754, CVE-2025-21734, CVE-2025-21829,
CVE-2025-21735, CVE-2025-21826, CVE-2025-21738, CVE-2024-58079,
CVE-2025-21815, CVE-2025-21708, CVE-2024-57986, CVE-2024-58085,
CVE-2025-21801, CVE-2024-58071, CVE-2025-21810, CVE-2025-21726,
CVE-2025-21744, CVE-2025-21830, CVE-2025-21748, ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.1-1025-realtime", ver:"6.8.1-1025.26", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-realtime", ver:"6.8.1-1025.26", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-realtime-6.8.1", ver:"6.8.1-1025.26", rls:"UBUNTU24.04 LTS"))) {
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

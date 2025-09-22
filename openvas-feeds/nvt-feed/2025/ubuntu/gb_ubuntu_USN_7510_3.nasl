# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7510.3");
  script_cve_id("CVE-2024-26982", "CVE-2024-47726", "CVE-2024-56599", "CVE-2024-56721", "CVE-2024-57834", "CVE-2024-57973", "CVE-2024-57977", "CVE-2024-57978", "CVE-2024-57979", "CVE-2024-57980", "CVE-2024-57981", "CVE-2024-57986", "CVE-2024-58001", "CVE-2024-58002", "CVE-2024-58005", "CVE-2024-58007", "CVE-2024-58010", "CVE-2024-58014", "CVE-2024-58016", "CVE-2024-58017", "CVE-2024-58020", "CVE-2024-58034", "CVE-2024-58051", "CVE-2024-58052", "CVE-2024-58055", "CVE-2024-58058", "CVE-2024-58063", "CVE-2024-58069", "CVE-2024-58071", "CVE-2024-58072", "CVE-2024-58076", "CVE-2024-58079", "CVE-2024-58083", "CVE-2024-58085", "CVE-2024-58086", "CVE-2024-58090", "CVE-2025-21647", "CVE-2025-21684", "CVE-2025-21704", "CVE-2025-21707", "CVE-2025-21708", "CVE-2025-21711", "CVE-2025-21715", "CVE-2025-21718", "CVE-2025-21719", "CVE-2025-21721", "CVE-2025-21722", "CVE-2025-21726", "CVE-2025-21727", "CVE-2025-21728", "CVE-2025-21731", "CVE-2025-21735", "CVE-2025-21736", "CVE-2025-21744", "CVE-2025-21745", "CVE-2025-21748", "CVE-2025-21749", "CVE-2025-21753", "CVE-2025-21758", "CVE-2025-21760", "CVE-2025-21761", "CVE-2025-21762", "CVE-2025-21763", "CVE-2025-21764", "CVE-2025-21765", "CVE-2025-21766", "CVE-2025-21767", "CVE-2025-21772", "CVE-2025-21776", "CVE-2025-21779", "CVE-2025-21781", "CVE-2025-21782", "CVE-2025-21785", "CVE-2025-21787", "CVE-2025-21791", "CVE-2025-21795", "CVE-2025-21796", "CVE-2025-21799", "CVE-2025-21802", "CVE-2025-21804", "CVE-2025-21806", "CVE-2025-21811", "CVE-2025-21814", "CVE-2025-21820", "CVE-2025-21823", "CVE-2025-21826", "CVE-2025-21830", "CVE-2025-21835", "CVE-2025-21844", "CVE-2025-21846", "CVE-2025-21848", "CVE-2025-21858", "CVE-2025-21859", "CVE-2025-21862", "CVE-2025-21865", "CVE-2025-21866", "CVE-2025-21871", "CVE-2025-21875", "CVE-2025-21877", "CVE-2025-21878", "CVE-2025-21887", "CVE-2025-21898", "CVE-2025-21904", "CVE-2025-21905", "CVE-2025-21909", "CVE-2025-21910", "CVE-2025-21912", "CVE-2025-21914", "CVE-2025-21916", "CVE-2025-21917", "CVE-2025-21919", "CVE-2025-21920", "CVE-2025-21922", "CVE-2025-21924", "CVE-2025-21925", "CVE-2025-21926", "CVE-2025-21928", "CVE-2025-21934", "CVE-2025-21935", "CVE-2025-21943", "CVE-2025-21948", "CVE-2025-21950", "CVE-2025-21951", "CVE-2025-21971");
  script_tag(name:"creation_date", value:"2025-05-21 04:05:31 +0000 (Wed, 21 May 2025)");
  script_version("2025-05-21T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-21 05:40:19 +0000 (Wed, 21 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-10 18:06:44 +0000 (Thu, 10 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7510-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7510-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7510-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-5.15, linux-nvidia-tegra' package(s) announced via the USN-7510-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - PowerPC architecture,
 - x86 architecture,
 - Block layer subsystem,
 - Network block device driver,
 - Bus devices,
 - Character device driver,
 - TPM device driver,
 - Clock framework and drivers,
 - GPIO subsystem,
 - GPU drivers,
 - HID subsystem,
 - I2C subsystem,
 - InfiniBand drivers,
 - Media drivers,
 - NVIDIA Tegra memory controller driver,
 - Network drivers,
 - PCI subsystem,
 - PPS (Pulse Per Second) driver,
 - PTP clock framework,
 - RapidIO drivers,
 - Real Time Clock drivers,
 - SLIMbus drivers,
 - QCOM SoC drivers,
 - Trusted Execution Environment drivers,
 - TTY drivers,
 - USB DSL drivers,
 - USB Device Class drivers,
 - USB core drivers,
 - USB Gadget drivers,
 - USB Host Controller drivers,
 - Renesas USBHS Controller drivers,
 - ACRN Hypervisor Service Module driver,
 - File systems infrastructure,
 - BTRFS file system,
 - F2FS file system,
 - Network file system (NFS) server daemon,
 - NILFS2 file system,
 - Overlay file system,
 - SMB network file system,
 - UBI file system,
 - KVM subsystem,
 - L3 Master device support module,
 - Process Accounting mechanism,
 - Padata parallel execution mechanism,
 - printk logging mechanism,
 - Scheduler infrastructure,
 - Timer subsystem,
 - Tracing infrastructure,
 - Memory management,
 - 802.1Q VLAN protocol,
 - B.A.T.M.A.N. meshing protocol,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - Logical Link layer,
 - Multipath TCP,
 - Netfilter,
 - NFC subsystem,
 - Open vSwitch,
 - Rose network layer,
 - Network traffic control,
 - Wireless networking,
 - Landlock security,
 - Linux Security Modules (LSM) Framework,
 - Tomoyo security module,
(CVE-2024-58069, CVE-2025-21912, CVE-2025-21922, CVE-2025-21765,
CVE-2025-21823, CVE-2025-21971, CVE-2024-58010, CVE-2025-21767,
CVE-2025-21727, CVE-2025-21916, CVE-2025-21859, CVE-2025-21844,
CVE-2024-58063, CVE-2025-21704, CVE-2024-57986, CVE-2025-21846,
CVE-2024-58007, CVE-2025-21708, CVE-2025-21731, CVE-2024-58058,
CVE-2024-58090, CVE-2025-21791, CVE-2025-21917, CVE-2024-26982,
CVE-2024-47726, CVE-2025-21848, CVE-2025-21948, CVE-2025-21796,
CVE-2025-21919, CVE-2025-21950, CVE-2024-58085, CVE-2025-21766,
CVE-2025-21764, CVE-2025-21781, CVE-2024-58071, CVE-2024-58072,
CVE-2025-21726, CVE-2025-21858, CVE-2024-58005, CVE-2025-21866,
CVE-2025-21935, CVE-2025-21753, CVE-2025-21904, CVE-2025-21877,
CVE-2024-58002, CVE-2025-21776, CVE-2025-21926, CVE-2025-21865,
CVE-2025-21898, CVE-2024-58076, CVE-2025-21707, CVE-2025-21735,
CVE-2025-21905, CVE-2025-21928, CVE-2025-21647, CVE-2025-21718,
CVE-2025-21814, CVE-2025-21925, CVE-2024-58001, CVE-2025-21811,
CVE-2024-58055, CVE-2024-58086, CVE-2025-21736, CVE-2025-21871,
CVE-2025-21878, CVE-2025-21684, CVE-2025-21763, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-5.15, linux-nvidia-tegra' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1089-azure", ver:"5.15.0-1089.98~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.15.0.1089.98~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-cvm", ver:"5.15.0.1089.98~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1037-nvidia-tegra", ver:"5.15.0-1037.37", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1037-nvidia-tegra-rt", ver:"5.15.0-1037.37", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1089-azure", ver:"5.15.0-1089.98", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-22.04", ver:"5.15.0.1089.87", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra", ver:"5.15.0.1037.37", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-tegra-rt", ver:"5.15.0.1037.37", rls:"UBUNTU22.04 LTS"))) {
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

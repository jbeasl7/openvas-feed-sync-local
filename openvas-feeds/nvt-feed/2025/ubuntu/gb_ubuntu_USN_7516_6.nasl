# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7516.6");
  script_cve_id("CVE-2021-47191", "CVE-2023-52741", "CVE-2024-26982", "CVE-2024-26996", "CVE-2024-50055", "CVE-2024-56599", "CVE-2024-57973", "CVE-2024-57977", "CVE-2024-57979", "CVE-2024-57980", "CVE-2024-57981", "CVE-2024-57986", "CVE-2024-58001", "CVE-2024-58002", "CVE-2024-58007", "CVE-2024-58009", "CVE-2024-58010", "CVE-2024-58014", "CVE-2024-58017", "CVE-2024-58020", "CVE-2024-58051", "CVE-2024-58052", "CVE-2024-58055", "CVE-2024-58058", "CVE-2024-58063", "CVE-2024-58069", "CVE-2024-58071", "CVE-2024-58072", "CVE-2024-58083", "CVE-2024-58085", "CVE-2024-58090", "CVE-2025-21647", "CVE-2025-21704", "CVE-2025-21708", "CVE-2025-21715", "CVE-2025-21718", "CVE-2025-21719", "CVE-2025-21721", "CVE-2025-21722", "CVE-2025-21728", "CVE-2025-21731", "CVE-2025-21735", "CVE-2025-21736", "CVE-2025-21744", "CVE-2025-21749", "CVE-2025-21753", "CVE-2025-21760", "CVE-2025-21761", "CVE-2025-21762", "CVE-2025-21763", "CVE-2025-21764", "CVE-2025-21765", "CVE-2025-21772", "CVE-2025-21776", "CVE-2025-21781", "CVE-2025-21782", "CVE-2025-21785", "CVE-2025-21787", "CVE-2025-21791", "CVE-2025-21806", "CVE-2025-21811", "CVE-2025-21814", "CVE-2025-21823", "CVE-2025-21835", "CVE-2025-21846", "CVE-2025-21848", "CVE-2025-21858", "CVE-2025-21859", "CVE-2025-21862", "CVE-2025-21865", "CVE-2025-21866", "CVE-2025-21871", "CVE-2025-21877", "CVE-2025-21898", "CVE-2025-21904", "CVE-2025-21905", "CVE-2025-21909", "CVE-2025-21910", "CVE-2025-21914", "CVE-2025-21916", "CVE-2025-21917", "CVE-2025-21920", "CVE-2025-21922", "CVE-2025-21925", "CVE-2025-21926", "CVE-2025-21928", "CVE-2025-21934", "CVE-2025-21935", "CVE-2025-21948", "CVE-2025-21971");
  script_tag(name:"creation_date", value:"2025-05-27 04:07:40 +0000 (Tue, 27 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-10 18:06:44 +0000 (Thu, 10 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7516-6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7516-6");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7516-6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ibm' package(s) announced via the USN-7516-6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - PowerPC architecture,
 - Block layer subsystem,
 - Drivers core,
 - Network block device driver,
 - Character device driver,
 - GPU drivers,
 - HID subsystem,
 - InfiniBand drivers,
 - Media drivers,
 - Network drivers,
 - PPS (Pulse Per Second) driver,
 - PTP clock framework,
 - RapidIO drivers,
 - Real Time Clock drivers,
 - SCSI subsystem,
 - SLIMbus drivers,
 - QCOM SoC drivers,
 - Trusted Execution Environment drivers,
 - USB DSL drivers,
 - USB Device Class drivers,
 - USB core drivers,
 - USB Gadget drivers,
 - USB Host Controller drivers,
 - Renesas USBHS Controller drivers,
 - File systems infrastructure,
 - BTRFS file system,
 - NILFS2 file system,
 - UBI file system,
 - KVM subsystem,
 - L3 Master device support module,
 - Process Accounting mechanism,
 - printk logging mechanism,
 - Scheduler infrastructure,
 - Tracing infrastructure,
 - Memory management,
 - 802.1Q VLAN protocol,
 - B.A.T.M.A.N. meshing protocol,
 - Bluetooth subsystem,
 - Networking core,
 - IPv4 networking,
 - IPv6 networking,
 - Logical Link layer,
 - NFC subsystem,
 - Open vSwitch,
 - Rose network layer,
 - Network traffic control,
 - Wireless networking,
 - Tomoyo security module,
(CVE-2025-21814, CVE-2025-21917, CVE-2025-21871, CVE-2024-57973,
CVE-2025-21862, CVE-2025-21877, CVE-2024-26982, CVE-2024-58090,
CVE-2025-21925, CVE-2025-21787, CVE-2025-21763, CVE-2024-58083,
CVE-2025-21719, CVE-2025-21715, CVE-2025-21704, CVE-2025-21865,
CVE-2025-21781, CVE-2025-21762, CVE-2023-52741, CVE-2025-21761,
CVE-2025-21764, CVE-2025-21811, CVE-2025-21846, CVE-2024-57981,
CVE-2024-58051, CVE-2025-21772, CVE-2024-56599, CVE-2024-58014,
CVE-2024-58007, CVE-2025-21760, CVE-2021-47191, CVE-2025-21909,
CVE-2025-21791, CVE-2025-21916, CVE-2024-57979, CVE-2024-26996,
CVE-2024-58085, CVE-2024-58072, CVE-2025-21914, CVE-2025-21848,
CVE-2025-21736, CVE-2025-21785, CVE-2024-58002, CVE-2024-58058,
CVE-2025-21776, CVE-2025-21935, CVE-2025-21722, CVE-2024-58071,
CVE-2025-21721, CVE-2025-21708, CVE-2024-58055, CVE-2025-21782,
CVE-2025-21806, CVE-2025-21922, CVE-2025-21835, CVE-2025-21749,
CVE-2025-21858, CVE-2024-58020, CVE-2024-58069, CVE-2024-57980,
CVE-2025-21735, CVE-2025-21905, CVE-2025-21823, CVE-2024-58052,
CVE-2025-21971, CVE-2024-58063, CVE-2025-21728, CVE-2025-21910,
CVE-2024-58017, CVE-2025-21647, CVE-2025-21934, CVE-2025-21926,
CVE-2024-57986, CVE-2025-21948, CVE-2024-58009, CVE-2025-21765,
CVE-2025-21904, CVE-2025-21866, CVE-2025-21928, CVE-2025-21859,
CVE-2024-58010, CVE-2025-21753, CVE-2025-21718, CVE-2024-58001,
CVE-2025-21731, CVE-2024-50055, CVE-2025-21744, CVE-2025-21920,
CVE-2024-57977, CVE-2025-21898)");

  script_tag(name:"affected", value:"'linux-ibm' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1092-ibm", ver:"5.4.0-1092.97", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm-lts-20.04", ver:"5.4.0.1092.121", rls:"UBUNTU20.04 LTS"))) {
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
